'use strict';

const { KomaguSecurityService } = require('../service');
const { normalizeRequiredRoles, resolveDenyStatus, hasAnyRole, denyBody } = require('../roles');

const defaultService = new KomaguSecurityService();

function describeRoute(req) {
  const method = req.method ? `${req.method} ` : '';
  if (req.route && req.route.path) {
    return `${method}${req.baseUrl || ''}${req.route.path}`;
  }
  const raw = req.path || req.originalUrl || req.url;
  if (!raw) {
    return undefined;
  }
  // Never put the query string into the audit trail
  return `${method}${String(raw).split('?')[0]}`;
}

/**
 * Express middleware enforcing function-level authorization (BFLA).
 * Roles come only from req.user.roles / req.user.role.
 *
 * @param {string|string[]} roles - caller needs at least one of these
 * @param {Object} [options]
 * @param {403|404} [options.denyStatus=403] - 404 hides the endpoint
 * @param {KomaguSecurityService} [options.securityService]
 */
function requireRole(roles, options = {}) {
  const requiredRoles = normalizeRequiredRoles(roles);
  const denyStatus = resolveDenyStatus(options);
  const service = options.securityService || defaultService;

  return async function (req, res, next) {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    if (hasAnyRole(user, requiredRoles)) {
      return next();
    }

    await service.emitRoleDenial(user, requiredRoles, describeRoute(req));
    return res.status(denyStatus).json(denyBody(denyStatus));
  };
}

module.exports = {
  requireRole,
};
