'use strict';

const {
  ResourceOperation,
  NotFoundException,
  UnauthorizedException,
  LoggingSecurityAuditSink,
} = require('./interfaces');

const USER_ID_CLAIMS = ['sub', 'uid', 'userId', 'user_id', 'id'];
const TENANT_ID_CLAIMS = ['tenant_id', 'tid', 'tenant', 'org_id', 'organization_id'];

class KomainuSecurityService {
  constructor(auditSink = new LoggingSecurityAuditSink()) {
    this.auditSink = auditSink;
  }

  getCurrentUserId(user) {
    if (!user) {
      throw new UnauthorizedException('No user principal present in request context');
    }

    const claims = user.claims || user;
    for (const claim of USER_ID_CLAIMS) {
      const val = claims[claim];
      if (val !== undefined && val !== null && typeof val !== 'object' && typeof val !== 'boolean') {
        const s = String(val).trim();
        if (s !== '') {
          return s;
        }
      }
    }

    if (user.userId && String(user.userId).trim() !== '') {
      return String(user.userId).trim();
    }

    throw new UnauthorizedException('Verified user subject identifier claim is missing');
  }

  getCurrentTenantId(user) {
    if (!user) {
      throw new UnauthorizedException('No user principal present in request context');
    }

    const claims = user.claims || user;
    for (const claim of TENANT_ID_CLAIMS) {
      const val = claims[claim];
      if (val !== undefined && val !== null && typeof val !== 'object' && typeof val !== 'boolean') {
        const s = String(val).trim();
        if (s !== '') {
          return s;
        }
      }
    }

    if (user.tenantId && String(user.tenantId).trim() !== '') {
      return String(user.tenantId).trim();
    }

    throw new UnauthorizedException('Verified tenant identifier claim is missing');
  }

  async authorize(user, resource, operation = ResourceOperation.READ, options = {}) {
    if (!user) {
      const reason = 'Caller is unauthenticated';
      await this._emitDenial(null, resource, operation, reason);
      return { succeeded: false, failureReason: reason };
    }

    let currentUserId;
    let currentTenantId;

    try {
      currentUserId = this.getCurrentUserId(user);
      currentTenantId = this.getCurrentTenantId(user);
    } catch (err) {
      const reason = err.message || 'Invalid user or tenant identity in claims';
      await this._emitDenial(user, resource, operation, reason);
      return { succeeded: false, failureReason: reason };
    }

    if (!resource) {
      return { succeeded: false, failureReason: 'Resource is null or undefined' };
    }

    let ownerUserId = options.ownerUserIdExtractor
      ? options.ownerUserIdExtractor(resource)
      : (resource.ownerUserId !== undefined && resource.ownerUserId !== null ? resource.ownerUserId : resource.owner_user_id);

    let tenantId = options.tenantIdExtractor
      ? options.tenantIdExtractor(resource)
      : (resource.tenantId !== undefined && resource.tenantId !== null ? resource.tenantId : resource.tenant_id);

    const resourceId = resource.id !== undefined && resource.id !== null ? String(resource.id) : undefined;

    const trimmedOwner = ownerUserId !== undefined && ownerUserId !== null ? String(ownerUserId).trim() : '';
    const trimmedTenant = tenantId !== undefined && tenantId !== null ? String(tenantId).trim() : '';

    if (!trimmedOwner || !trimmedTenant) {
      const reason = `Target resource does not expose ownerUserId and tenantId`;
      await this._emitDenial(user, resource, operation, reason, resourceId);
      return { succeeded: false, failureReason: reason };
    }

    // 1. Tenant boundary check
    if (String(trimmedTenant) !== String(currentTenantId)) {
      const reason = `Tenant boundary violation: current tenant '${currentTenantId}' != resource tenant '${trimmedTenant}'`;
      await this._emitDenial(user, resource, operation, reason, resourceId);
      return { succeeded: false, failureReason: reason };
    }

    // 2. User ownership check
    if (String(trimmedOwner) !== String(currentUserId)) {
      const reason = `User ownership violation: current user '${currentUserId}' != resource owner '${trimmedOwner}'`;
      await this._emitDenial(user, resource, operation, reason, resourceId);
      return { succeeded: false, failureReason: reason };
    }

    return { succeeded: true };
  }

  async requireOwnership(user, resource, operation = ResourceOperation.READ, options = {}) {
    const decision = await this.authorize(user, resource, operation, options);
    if (!decision.succeeded) {
      // Invariant: Always return HTTP 404 Not Found to prevent ID enumeration
      throw new NotFoundException('Resource not found');
    }
  }

  async _emitDenial(user, resource, operation, reason, resourceId) {
    try {
      let actorUserId = null;
      let actorTenantId = null;

      if (user) {
        try { actorUserId = this.getCurrentUserId(user); } catch (_) {}
        try { actorTenantId = this.getCurrentTenantId(user); } catch (_) {}
      }

      const event = {
        timestamp: new Date().toISOString(),
        eventName: 'Komainu.Authorization.Denied',
        actorUserId: actorUserId || undefined,
        actorTenantId: actorTenantId || undefined,
        resourceType: resource && resource.constructor ? resource.constructor.name : 'Object',
        resourceId: resourceId || (resource && resource.id ? String(resource.id) : undefined),
        operation,
        reason,
      };

      await this.auditSink.emit(event);
    } catch (_) {
      // Auditing failures must never affect the denial outcome
    }
  }
}

module.exports = {
  KomainuSecurityService,
};
