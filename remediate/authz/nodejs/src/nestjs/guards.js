'use strict';

const { NotFoundException, UnauthorizedException } = require('../interfaces');
const { KOMAINU_REQUIRE_OWNERSHIP_KEY, getMetadata } = require('./decorators');

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
      meta = this.reflector.get(KOMAINU_REQUIRE_OWNERSHIP_KEY, handler) ||
             this.reflector.get(KOMAINU_REQUIRE_OWNERSHIP_KEY, targetClass);
    }
    if (!meta) {
      meta = (handler && getMetadata(KOMAINU_REQUIRE_OWNERSHIP_KEY, handler)) ||
             (targetClass && getMetadata(KOMAINU_REQUIRE_OWNERSHIP_KEY, targetClass));
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

    req.komainuResource = resource;
    return true;
  }
}

module.exports = {
  OwnershipGuard,
};
