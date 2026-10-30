'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  ResourceOperation,
  NotFoundException,
  UnauthorizedException,
  InMemorySecurityAuditSink,
  KomaguSecurityService,
  KOMAGU_REQUIRE_OWNERSHIP_KEY,
  RequireOwnership,
  OwnershipGuard,
  OwnershipInterceptor,
  komaguOwnershipMiddleware,
} = require('../src/index');

test('KomaguSecurityService: allows owner access', async () => {
  const auditSink = new InMemorySecurityAuditSink();
  const service = new KomaguSecurityService(auditSink);

  const alice = { userId: 'user-a', tenantId: 'tenant-komagu' };
  const order = { id: 'ord-01', ownerUserId: 'user-a', tenantId: 'tenant-komagu' };

  const decision = await service.authorize(alice, order, ResourceOperation.READ);
  assert.strictEqual(decision.succeeded, true);
  assert.strictEqual(auditSink.events.length, 0);

  // requireOwnership should resolve without throwing
  await assert.doesNotReject(async () => {
    await service.requireOwnership(alice, order, ResourceOperation.READ);
  });
});

test('KomaguSecurityService: denies attacker with 404 and emits audit', async () => {
  const auditSink = new InMemorySecurityAuditSink();
  const service = new KomaguSecurityService(auditSink);

  const bob = { userId: 'user-b', tenantId: 'tenant-komagu' };
  const order = { id: 'ord-01', ownerUserId: 'user-a', tenantId: 'tenant-komagu' };

  const decision = await service.authorize(bob, order, ResourceOperation.READ);
  assert.strictEqual(decision.succeeded, false);
  assert.match(decision.failureReason, /User ownership violation/);

  // Invariant: requireOwnership throws NotFoundException (HTTP 404)
  await assert.rejects(
    async () => {
      await service.requireOwnership(bob, order, ResourceOperation.READ);
    },
    (err) => {
      assert(err instanceof NotFoundException);
      assert.strictEqual(err.getStatus(), 404);
      return true;
    }
  );

  // Verify audit event
  assert.strictEqual(auditSink.events.length, 2); // 1 from authorize + 1 from requireOwnership
  const event = auditSink.events[0];
  assert.strictEqual(event.eventName, 'Komainu.Authorization.Denied');
  assert.strictEqual(event.actorUserId, 'user-b');
  assert.strictEqual(event.actorTenantId, 'tenant-komagu');
  assert.strictEqual(event.resourceId, 'ord-01');
});

test('KomaguSecurityService: denies cross-tenant access', async () => {
  const auditSink = new InMemorySecurityAuditSink();
  const service = new KomaguSecurityService(auditSink);

  const charlie = { userId: 'user-c', tenantId: 'tenant-other' };
  const order = { id: 'ord-01', ownerUserId: 'user-a', tenantId: 'tenant-komagu' };

  const decision = await service.authorize(charlie, order, ResourceOperation.READ);
  assert.strictEqual(decision.succeeded, false);
  assert.match(decision.failureReason, /Tenant boundary violation/);
});

test('NestJS OwnershipGuard: allows owner and throws 404 on attacker', async () => {
  const auditSink = new InMemorySecurityAuditSink();
  const service = new KomaguSecurityService(auditSink);

  const ordersDb = {
    'ord-100': { id: 'ord-100', ownerUserId: 'user-a', tenantId: 'tenant-komagu', title: 'Private Doc' },
  };

  class TestController {
    getOrder() {}
  }
  // Apply decorator
  RequireOwnership(ResourceOperation.READ, {
    idParamName: 'id',
    resourceLoader: async (id) => ordersDb[id] || null,
  })(TestController.prototype, 'getOrder', Object.getOwnPropertyDescriptor(TestController.prototype, 'getOrder'));

  const guard = new OwnershipGuard(null, service);

  // 1. Owner Alice execution context
  const aliceContext = {
    getHandler: () => TestController.prototype.getOrder,
    getClass: () => TestController,
    switchToHttp: () => ({
      getRequest: () => ({
        user: { userId: 'user-a', tenantId: 'tenant-komagu' },
        params: { id: 'ord-100' },
      }),
    }),
  };

  const allowed = await guard.canActivate(aliceContext);
  assert.strictEqual(allowed, true);

  // 2. Attacker Bob execution context
  const bobContext = {
    getHandler: () => TestController.prototype.getOrder,
    getClass: () => TestController,
    switchToHttp: () => ({
      getRequest: () => ({
        user: { userId: 'user-b', tenantId: 'tenant-komagu' },
        params: { id: 'ord-100' },
      }),
    }),
  };

  await assert.rejects(
    async () => {
      await guard.canActivate(bobContext);
    },
    (err) => {
      assert(err instanceof NotFoundException);
      assert.strictEqual(err.getStatus(), 404);
      return true;
    }
  );
});

test('NestJS OwnershipInterceptor: verifies returned entity', async () => {
  const auditSink = new InMemorySecurityAuditSink();
  const service = new KomaguSecurityService(auditSink);
  const interceptor = new OwnershipInterceptor(null, service);

  // 1. Owner returns order
  const aliceContext = {
    switchToHttp: () => ({
      getRequest: () => ({
        user: { userId: 'user-a', tenantId: 'tenant-komagu' },
      }),
    }),
  };
  const aliceNext = {
    handle: async () => ({ id: 'ord-200', ownerUserId: 'user-a', tenantId: 'tenant-komagu' }),
  };
  const result = await interceptor.intercept(aliceContext, aliceNext);
  assert.strictEqual(result.id, 'ord-200');

  // 2. Attacker Bob gets returned entity belonging to Alice -> Interceptor blocks with 404
  const bobContext = {
    switchToHttp: () => ({
      getRequest: () => ({
        user: { userId: 'user-b', tenantId: 'tenant-komagu' },
      }),
    }),
  };
  const bobNext = {
    handle: async () => ({ id: 'ord-200', ownerUserId: 'user-a', tenantId: 'tenant-komagu' }),
  };

  await assert.rejects(
    async () => {
      await interceptor.intercept(bobContext, bobNext);
    },
    (err) => {
      assert(err instanceof NotFoundException);
      assert.strictEqual(err.getStatus(), 404);
      return true;
    }
  );
});

test('Express komaguOwnershipMiddleware: enforces BOLA check', async () => {
  const auditSink = new InMemorySecurityAuditSink();
  const service = new KomaguSecurityService(auditSink);

  const middleware = komaguOwnershipMiddleware({
    operation: ResourceOperation.READ,
    idParamName: 'id',
    resourceLoader: async (id) => (id === 'ord-300' ? { id: 'ord-300', ownerUserId: 'user-a', tenantId: 'tenant-komagu' } : null),
    securityService: service,
  });

  // Owner Alice succeeds -> next() called
  let nextCalled = false;
  const aliceReq = {
    user: { userId: 'user-a', tenantId: 'tenant-komagu' },
    params: { id: 'ord-300' },
  };
  const dummyRes = {};
  await middleware(aliceReq, dummyRes, () => { nextCalled = true; });
  assert.strictEqual(nextCalled, true);
  assert.strictEqual(aliceReq.komaguResource.id, 'ord-300');

  // Attacker Bob denied -> res.status(404).json(...)
  let responseStatus = null;
  let responseData = null;
  const bobReq = {
    user: { userId: 'user-b', tenantId: 'tenant-komagu' },
    params: { id: 'ord-300' },
  };
  const mockRes = {
    status(code) {
      responseStatus = code;
      return this;
    },
    json(data) {
      responseData = data;
      return this;
    },
  };
  await middleware(bobReq, mockRes, () => {
    assert.fail('next() should not be called on BOLA denial');
  });

  assert.strictEqual(responseStatus, 404);
  assert.strictEqual(responseData.message, 'Resource not found');
});

test('KomaguSecurityService: claim semantics and edge cases', async () => {
  const service = new KomaguSecurityService();

  // 1. Accepts generic "id" claim and trims whitespace
  const userWithId = {
    claims: {
      id: '  user-trimmed  ',
      tenant_id: '  tenant-trimmed  ',
    },
  };
  assert.strictEqual(service.getCurrentUserId(userWithId), 'user-trimmed');
  assert.strictEqual(service.getCurrentTenantId(userWithId), 'tenant-trimmed');

  // 2. Rejects non-scalar claims (objects, arrays, booleans)
  const nonScalarUser = {
    claims: {
      sub: { nested: 'obj' },
      tenant_id: ['array-val'],
    },
  };
  assert.throws(() => service.getCurrentUserId(nonScalarUser), UnauthorizedException);
  assert.throws(() => service.getCurrentTenantId(nonScalarUser), UnauthorizedException);

  // 3. Rejects resource with empty or whitespace owner
  const emptyOwnerRes = { id: 'ord-01', ownerUserId: '   ', tenantId: 'tenant-trimmed' };
  const decision = await service.authorize(userWithId, emptyOwnerRes, ResourceOperation.READ);
  assert.strictEqual(decision.succeeded, false);
});
