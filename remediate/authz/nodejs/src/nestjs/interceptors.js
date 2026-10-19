'use strict';

const { ResourceOperation, NotFoundException, UnauthorizedException } = require('../interfaces');
const { KOMAINU_REQUIRE_OWNERSHIP_KEY, getMetadata } = require('./decorators');

/**
 * NestJS Interceptor verifying ownership of controller returned domain entities.
 */
class OwnershipInterceptor {
  constructor(reflector, securityService) {
    this.reflector = reflector;
    this.securityService = securityService;
  }

  async intercept(context, next) {
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

    const httpContext = context.switchToHttp ? context.switchToHttp() : null;
    const req = httpContext ? httpContext.getRequest() : context.request;

    // Call the handler to get the response value
    let result = null;
    if (next && typeof next.handle === 'function') {
      const observableOrPromise = next.handle();
      if (observableOrPromise && typeof observableOrPromise.toPromise === 'function') {
        result = await observableOrPromise.toPromise();
      } else {
        result = await observableOrPromise;
      }
    } else if (typeof next === 'function') {
      result = await next();
    }

    if (!result || !req) {
      return result;
    }

    const user = req.user;
    if (!user) {
      throw new UnauthorizedException('Unauthenticated caller');
    }

    const op = (meta && meta.operation) || ResourceOperation.READ;

    // Check individual resource
    if (result.ownerUserId || result.owner_user_id) {
      await this.securityService.requireOwnership(user, result, op);
    } else if (Array.isArray(result)) {
      for (const item of result) {
        if (item && (item.ownerUserId || item.owner_user_id)) {
          await this.securityService.requireOwnership(user, item, op);
        }
      }
    }

    return result;
  }
}

module.exports = {
  OwnershipInterceptor,
};
