'use strict';

const {
  ResourceOperation,
  HttpException,
  NotFoundException,
  UnauthorizedException,
  ForbiddenException,
  LoggingSecurityAuditSink,
  InMemorySecurityAuditSink,
} = require('./interfaces');

const { KomaguSecurityService } = require('./service');
const {
  KOMAGU_REQUIRE_OWNERSHIP_KEY,
  KOMAGU_REQUIRE_ROLE_KEY,
  RequireOwnership,
  RequireRole,
  CurrentUser,
} = require('./nestjs/decorators');
const { OwnershipGuard, KomaguRoleGuard } = require('./nestjs/guards');
const { OwnershipInterceptor } = require('./nestjs/interceptors');
const { komaguOwnershipMiddleware } = require('./express/middleware');
const { requireRole } = require('./express/role-middleware');
const { allowFields } = require('./mass-assignment');

module.exports = {
  ResourceOperation,
  HttpException,
  NotFoundException,
  UnauthorizedException,
  ForbiddenException,
  LoggingSecurityAuditSink,
  InMemorySecurityAuditSink,
  KomaguSecurityService,
  KOMAGU_REQUIRE_OWNERSHIP_KEY,
  KOMAGU_REQUIRE_ROLE_KEY,
  RequireOwnership,
  RequireRole,
  CurrentUser,
  OwnershipGuard,
  KomaguRoleGuard,
  OwnershipInterceptor,
  komaguOwnershipMiddleware,
  requireRole,
  allowFields,
};
