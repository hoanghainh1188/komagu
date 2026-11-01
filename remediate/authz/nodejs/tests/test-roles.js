'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  NotFoundException,
  UnauthorizedException,
  ForbiddenException,
  InMemorySecurityAuditSink,
  KomaguSecurityService,
  RequireRole,
  KomaguRoleGuard,
  requireRole,
  allowFields,
} = require('../src/index');

function mockRes() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.body = data;
      return this;
    },
  };
}

async function runMiddleware(mw, req) {
  const res = mockRes();
  let nextCalled = false;
  await mw(req, res, () => { nextCalled = true; });
  return { res, nextCalled };
}

const admin = { userId: 'user-admin', tenantId: 'tenant-komagu', roles: ['admin'] };
const plainUser = { userId: 'user-b', tenantId: 'tenant-komagu', roles: ['user'] };

// ---------------------------------------------------------------------------
// Express requireRole
// ---------------------------------------------------------------------------

test('Express requireRole: allows caller holding a required role (roles array or role string)', async () => {
  const mw = requireRole(['admin', 'ops']);

  const fromArray = await runMiddleware(mw, { user: admin });
  assert.strictEqual(fromArray.nextCalled, true);
  assert.strictEqual(fromArray.res.statusCode, null);

  const fromString = await runMiddleware(mw, { user: { userId: 'user-o', tenantId: 't', role: 'ops' } });
  assert.strictEqual(fromString.nextCalled, true);
});

test('Express requireRole: denies with 403 Forbidden by default (case-sensitive match)', async () => {
  const mw = requireRole('admin', { securityService: new KomaguSecurityService(new InMemorySecurityAuditSink()) });

  const denied = await runMiddleware(mw, { user: plainUser });
  assert.strictEqual(denied.nextCalled, false);
  assert.strictEqual(denied.res.statusCode, 403);
  assert.deepStrictEqual(denied.res.body, { message: 'Forbidden' });

  const wrongCase = await runMiddleware(mw, { user: { userId: 'u', tenantId: 't', roles: ['Admin'] } });
  assert.strictEqual(wrongCase.res.statusCode, 403);
});

test('Express requireRole: denyStatus 404 hides the endpoint', async () => {
  const mw = requireRole('admin', {
    denyStatus: 404,
    securityService: new KomaguSecurityService(new InMemorySecurityAuditSink()),
  });
  const denied = await runMiddleware(mw, { user: plainUser });
  assert.strictEqual(denied.nextCalled, false);
  assert.strictEqual(denied.res.statusCode, 404);
  assert.deepStrictEqual(denied.res.body, { message: 'Resource not found' });
});

test('Express requireRole: returns 401 without a principal', async () => {
  const mw = requireRole('admin');
  const result = await runMiddleware(mw, { headers: {} });
  assert.strictEqual(result.nextCalled, false);
  assert.strictEqual(result.res.statusCode, 401);
  assert.deepStrictEqual(result.res.body, { message: 'Unauthorized' });
});

test('Express requireRole: role claimed in body, query, params or headers is ignored', async () => {
  const sink = new InMemorySecurityAuditSink();
  const mw = requireRole('admin', { securityService: new KomaguSecurityService(sink) });

  const req = {
    user: { userId: 'user-b', tenantId: 'tenant-komagu' }, // authenticated, no roles
    body: { role: 'admin', roles: ['admin'], isAdmin: true },
    query: { role: 'admin', roles: ['admin'] },
    params: { role: 'admin' },
    headers: { 'x-role': 'admin', 'x-roles': 'admin' },
  };
  const result = await runMiddleware(mw, req);
  assert.strictEqual(result.nextCalled, false);
  assert.strictEqual(result.res.statusCode, 403);
  assert.strictEqual(sink.events.length, 1);
});

test('Express requireRole: emits RoleDenied audit event on denial only', async () => {
  const sink = new InMemorySecurityAuditSink();
  const mw = requireRole(['admin', 'ops'], { securityService: new KomaguSecurityService(sink) });

  await runMiddleware(mw, { user: admin, method: 'DELETE', baseUrl: '/api', route: { path: '/users/:id' } });
  assert.strictEqual(sink.events.length, 0);

  await runMiddleware(mw, {
    user: plainUser,
    method: 'DELETE',
    baseUrl: '/api',
    route: { path: '/users/:id' },
    originalUrl: '/api/users/7?token=secret',
  });
  assert.strictEqual(sink.events.length, 1);
  const event = sink.events[0];
  assert.strictEqual(event.eventName, 'Komagu.Authorization.RoleDenied');
  assert.strictEqual(event.actorUserId, 'user-b');
  assert.strictEqual(event.actorTenantId, 'tenant-komagu');
  assert.deepStrictEqual(event.requiredRoles, ['admin', 'ops']);
  assert.strictEqual(event.route, 'DELETE /api/users/:id');
  assert.ok(event.timestamp);
});

test('Express requireRole: audit sink failure does not change the denial', async () => {
  const brokenSink = { emit() { throw new Error('sink down'); } };
  const mw = requireRole('admin', { securityService: new KomaguSecurityService(brokenSink) });
  const result = await runMiddleware(mw, { user: plainUser });
  assert.strictEqual(result.res.statusCode, 403);
});

test('requireRole / RequireRole: invalid arguments throw at construction time', () => {
  for (const bad of [undefined, null, '', '   ', [], [''], ['admin', 42], 42, {}]) {
    assert.throws(() => requireRole(bad), TypeError, `requireRole(${JSON.stringify(bad)})`);
    assert.throws(() => RequireRole(bad), TypeError, `RequireRole(${JSON.stringify(bad)})`);
  }
  for (const badStatus of [401, 500, '404', 0]) {
    assert.throws(() => requireRole('admin', { denyStatus: badStatus }), /denyStatus must be 403 or 404/);
    assert.throws(() => RequireRole('admin', { denyStatus: badStatus }), /denyStatus must be 403 or 404/);
  }
  assert.doesNotThrow(() => requireRole('admin', { denyStatus: 403 }));
  assert.doesNotThrow(() => requireRole('admin', { denyStatus: 404 }));
});

// ---------------------------------------------------------------------------
// NestJS RequireRole + KomaguRoleGuard
// ---------------------------------------------------------------------------

function nestContext(controller, handlerName, req) {
  return {
    getHandler: () => controller.prototype[handlerName],
    getClass: () => controller,
    switchToHttp: () => ({ getRequest: () => req }),
  };
}

function decorate(decorator, controller, handlerName) {
  decorator(controller.prototype, handlerName, Object.getOwnPropertyDescriptor(controller.prototype, handlerName));
}

test('NestJS KomaguRoleGuard: allows role holder, denies others with 403 and audits', async () => {
  const sink = new InMemorySecurityAuditSink();
  const guard = new KomaguRoleGuard(null, new KomaguSecurityService(sink));

  class AdminController {
    deleteUser() {}
    publicInfo() {}
  }
  decorate(RequireRole('admin'), AdminController, 'deleteUser');

  assert.strictEqual(await guard.canActivate(nestContext(AdminController, 'deleteUser', { user: admin })), true);

  await assert.rejects(
    guard.canActivate(nestContext(AdminController, 'deleteUser', {
      user: plainUser,
      body: { role: 'admin' },
      query: { roles: ['admin'] },
      headers: { 'x-role': 'admin' },
    })),
    (err) => {
      assert(err instanceof ForbiddenException);
      assert.strictEqual(err.getStatus(), 403);
      return true;
    }
  );
  assert.strictEqual(sink.events.length, 1);
  assert.strictEqual(sink.events[0].eventName, 'Komagu.Authorization.RoleDenied');
  assert.strictEqual(sink.events[0].route, 'AdminController.deleteUser');
  assert.deepStrictEqual(sink.events[0].requiredRoles, ['admin']);

  // Undecorated handler passes through
  assert.strictEqual(await guard.canActivate(nestContext(AdminController, 'publicInfo', { user: plainUser })), true);
});

test('NestJS KomaguRoleGuard: class-level decorator, denyStatus 404 and 401', async () => {
  const guard = new KomaguRoleGuard(null, new KomaguSecurityService(new InMemorySecurityAuditSink()));

  class OpsController {
    rotateKeys() {}
  }
  RequireRole(['ops'], { denyStatus: 404 })(OpsController);

  await assert.rejects(
    guard.canActivate(nestContext(OpsController, 'rotateKeys', { user: plainUser })),
    (err) => err instanceof NotFoundException && err.getStatus() === 404
  );
  await assert.rejects(
    guard.canActivate(nestContext(OpsController, 'rotateKeys', {})),
    (err) => err instanceof UnauthorizedException && err.getStatus() === 401
  );
  assert.strictEqual(
    await guard.canActivate(nestContext(OpsController, 'rotateKeys', { user: { userId: 'o', tenantId: 't', role: 'ops' } })),
    true
  );
});

// ---------------------------------------------------------------------------
// allowFields (mass assignment)
// ---------------------------------------------------------------------------

test('allowFields: picks allow-listed keys, skips missing, never mutates source', () => {
  const source = { name: 'Bob', email: 'b@example.com', role: 'admin', isAdmin: true };
  const snapshot = JSON.parse(JSON.stringify(source));

  const picked = allowFields(source, ['name', 'email', 'phone']);
  assert.deepStrictEqual(picked, { name: 'Bob', email: 'b@example.com' });
  assert.strictEqual(Object.prototype.hasOwnProperty.call(picked, 'phone'), false);
  assert.notStrictEqual(picked, source);
  assert.deepStrictEqual(source, snapshot);
});

test('allowFields: ignores __proto__/constructor/prototype and inherited or non-enumerable keys', () => {
  const malicious = JSON.parse('{"__proto__": {"isAdmin": true}, "constructor": {"x": 1}, "prototype": 1, "name": "x"}');
  const picked = allowFields(malicious, ['__proto__', 'constructor', 'prototype', 'name']);
  assert.deepStrictEqual(Object.keys(picked), ['name']);
  assert.strictEqual(Object.getPrototypeOf(picked), Object.prototype);
  assert.strictEqual(picked.isAdmin, undefined);
  assert.strictEqual({}.isAdmin, undefined);

  const inherited = Object.create({ role: 'admin' });
  Object.defineProperty(inherited, 'hidden', { value: 'h', enumerable: false });
  assert.deepStrictEqual(allowFields(inherited, ['role', 'hidden']), {});
});

test('allowFields: non-object source yields {}; invalid allow-list throws', () => {
  for (const bad of [undefined, null, 'str', 42, true, ['a']]) {
    assert.deepStrictEqual(allowFields(bad, ['a', '0']), {});
  }
  assert.throws(() => allowFields({ a: 1 }, 'a'), TypeError);
});

test('DTO allow-list example: profile update cannot change role or isAdmin', async () => {
  const usersDb = { 'user-b': { id: 'user-b', name: 'Bob', email: 'bob@old.example', role: 'user', isAdmin: false } };

  // Example Express handler: PATCH /me
  function updateProfile(req, res) {
    const changes = allowFields(req.body, ['name', 'email']);
    const current = usersDb[req.user.userId];
    usersDb[req.user.userId] = { ...current, ...changes };
    return res.status(200).json(usersDb[req.user.userId]);
  }

  const res = mockRes();
  updateProfile({
    user: { userId: 'user-b', tenantId: 'tenant-komagu' },
    body: { name: 'Bobby', email: 'bob@new.example', role: 'admin', isAdmin: true, id: 'user-a' },
  }, res);

  assert.strictEqual(res.statusCode, 200);
  assert.deepStrictEqual(usersDb['user-b'], {
    id: 'user-b', name: 'Bobby', email: 'bob@new.example', role: 'user', isAdmin: false,
  });
});
