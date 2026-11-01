'use strict';

/**
 * Shared function-level authorization (BFLA) helpers used by the Express
 * middleware and the NestJS guard.
 *
 * Security invariant: roles are read ONLY from the trusted authenticated
 * principal (`req.user.roles` / `req.user.role`). Request body, query,
 * params and headers are never consulted.
 */

const ALLOWED_DENY_STATUSES = Object.freeze([403, 404]);

/**
 * Validate and normalize the required roles argument. Throws at construction time.
 * @param {string|string[]} roles
 * @returns {string[]} frozen copy of the required roles
 */
function normalizeRequiredRoles(roles) {
  const list = typeof roles === 'string' ? [roles] : roles;
  if (!Array.isArray(list) || list.length === 0) {
    throw new TypeError('requireRole: roles must be a non-empty string or a non-empty array of strings');
  }
  for (const role of list) {
    if (typeof role !== 'string' || role.trim() === '') {
      throw new TypeError('requireRole: every role must be a non-empty string');
    }
  }
  return Object.freeze(list.slice());
}

/**
 * Validate options.denyStatus (403 default, or 404 to hide the endpoint).
 * @param {Object} [options]
 * @returns {number}
 */
function resolveDenyStatus(options) {
  const opts = options || {};
  if (opts.denyStatus === undefined || opts.denyStatus === null) {
    return 403;
  }
  if (!ALLOWED_DENY_STATUSES.includes(opts.denyStatus)) {
    throw new TypeError(`requireRole: options.denyStatus must be 403 or 404 (got ${String(opts.denyStatus)})`);
  }
  return opts.denyStatus;
}

/**
 * Collect the caller's roles from the trusted principal only.
 * @param {Object} user - req.user
 * @returns {string[]}
 */
function getPrincipalRoles(user) {
  if (!user || typeof user !== 'object') {
    return [];
  }
  const roles = [];
  if (Array.isArray(user.roles)) {
    for (const role of user.roles) {
      if (typeof role === 'string') {
        roles.push(role);
      }
    }
  }
  if (typeof user.role === 'string') {
    roles.push(user.role);
  }
  return roles;
}

/**
 * True when the principal holds at least one required role (case-sensitive exact match).
 */
function hasAnyRole(user, requiredRoles) {
  const held = getPrincipalRoles(user);
  return requiredRoles.some((role) => held.includes(role));
}

function denyBody(status) {
  return status === 404 ? { message: 'Resource not found' } : { message: 'Forbidden' };
}

module.exports = {
  ALLOWED_DENY_STATUSES,
  normalizeRequiredRoles,
  resolveDenyStatus,
  getPrincipalRoles,
  hasAnyRole,
  denyBody,
};
