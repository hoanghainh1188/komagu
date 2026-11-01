'use strict';

const { NotFoundException, UnauthorizedException, ForbiddenException } = require('../interfaces');
const { KOMAGU_REQUIRE_OWNERSHIP_KEY, KOMAGU_REQUIRE_ROLE_KEY, getMetadata } = require('./decorators');
const { KomaguSecurityService } = require('../service');
const { hasAnyRole } = require('../roles');

/**
 * NestJS Guard evaluating object-level authorization before route handler execution.
 */
class OwnershipGuard {
  constructor(reflector, securityService) {
    this.reflector = reflector;
    this.securityService = securityService;
  }

  async canActivate(context) {
    const handler = context.getHandler ? context.getHandler() : null;
    const targetClass = context.getClass ? context.getClass() : null;

    let meta = null;
    if (this.reflector && typeof this.reflector.get === 'function') {
      meta = this.reflector.get(KOMAGU_REQUIRE_OWNERSHIP_KEY, handler) ||
             this.reflector.get(KOMAGU_REQUIRE_OWNERSHIP_KEY, targetClass);
    }
    if (!meta) {
      meta = (handler && getMetadata(KOMAGU_REQUIRE_OWNERSHIP_KEY, handler)) ||
             (targetClass && getMetadata(KOMAGU_REQUIRE_OWNERSHIP_KEY, targetClass));
    }

    if (!meta) {
      return true; // No ownership requirements on this route
    }

    const httpContext = context.switchToHttp ? context.switchToHttp() : null;
    const req = httpContext ? httpContext.getRequest() : context.request;

    if (!req) {
      throw new UnauthorizedException('Request object missing from execution context');
    }

    const user = req.user;
    if (!user) {
      throw new UnauthorizedException('Unauthenticated caller');
    }

    const idParam = meta.idParamName || 'id';
    const params = req.params || {};
    const query = req.query || {};
    const body = req.body || {};

    const resourceId = params[idParam] !== undefined
      ? params[idParam]
      : (query[idParam] !== undefined ? query[idParam] : body[idParam]);

    let resource = null;
    if (meta.resourceLoader) {
      resource = await meta.resourceLoader(resourceId, req);
    } else if (body && (body.ownerUserId || body.owner_user_id)) {
      resource = body;
    }

    if (!resource) {
      // Invariant: Target resource does not exist -> 404
      throw new NotFoundException('Resource not found');
    }

    // Enforce ownership: throws NotFoundException on BOLA violation
    await this.securityService.requireOwnership(user, resource, meta.operation, meta.options);

    req.komaguResource = resource;
    return true;
  }
}

function readMeta(reflector, key, handler, targetClass) {
  let meta = null;
  if (reflector && typeof reflector.get === 'function') {
    meta = reflector.get(key, handler) || reflector.get(key, targetClass);
  }
  if (!meta) {
    meta = (handler && getMetadata(key, handler)) ||
           (targetClass && getMetadata(key, targetClass));
  }
  return meta || null;
}

function describeOperation(req, handler, targetClass) {
  if (req && req.method && req.route && req.route.path) {
    return `${req.method} ${req.baseUrl || ''}${req.route.path}`;
  }
  const className = targetClass && targetClass.name;
  const handlerName = handler && handler.name;
  if (className && handlerName) {
    return `${className}.${handlerName}`;
  }
  return handlerName || className || undefined;
}

/**
 * NestJS Guard enforcing @RequireRole (function-level / BFLA authorization).
 * Roles are read only from the authenticated principal (req.user.roles / req.user.role).
 * Method-level @RequireRole overrides class-level.
 */
class KomaguRoleGuard {
  constructor(reflector, securityService) {
    this.reflector = reflector;
    this.securityService = securityService || new KomaguSecurityService();
  }

  async canActivate(context) {
    const handler = context.getHandler ? context.getHandler() : null;
    const targetClass = context.getClass ? context.getClass() : null;

    const meta = readMeta(this.reflector, KOMAGU_REQUIRE_ROLE_KEY, handler, targetClass);
    if (!meta) {
      return true; // No role requirements on this route
    }

    const httpContext = context.switchToHttp ? context.switchToHttp() : null;
    const req = httpContext ? httpContext.getRequest() : context.request;

    if (!req || !req.user) {
      throw new UnauthorizedException('Unauthorized');
    }

    if (hasAnyRole(req.user, meta.roles)) {
      return true;
    }

    await this.securityService.emitRoleDenial(req.user, meta.roles, describeOperation(req, handler, targetClass));

    if (meta.denyStatus === 404) {
      throw new NotFoundException('Resource not found');
    }
    throw new ForbiddenException('Forbidden');
  }
}

module.exports = {
  OwnershipGuard,
  KomaguRoleGuard,
};
