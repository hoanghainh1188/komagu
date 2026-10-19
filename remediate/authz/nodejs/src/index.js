'use strict';

const {
  ResourceOperation,
  HttpException,
  NotFoundException,
  UnauthorizedException,
  LoggingSecurityAuditSink,
  InMemorySecurityAuditSink,
} = require('./interfaces');

const { KomainuSecurityService } = require('./service');
const { KOMAINU_REQUIRE_OWNERSHIP_KEY, RequireOwnership, CurrentUser } = require('./nestjs/decorators');
const { OwnershipGuard } = require('./nestjs/guards');
const { OwnershipInterceptor } = require('./nestjs/interceptors');
const { komainuOwnershipMiddleware } = require('./express/middleware');

module.exports = {
  ResourceOperation,
  HttpException,
  NotFoundException,
  UnauthorizedException,
  LoggingSecurityAuditSink,
  InMemorySecurityAuditSink,
  KomainuSecurityService,
  KOMAINU_REQUIRE_OWNERSHIP_KEY,
  RequireOwnership,
  CurrentUser,
  OwnershipGuard,
  OwnershipInterceptor,
  komainuOwnershipMiddleware,
};
