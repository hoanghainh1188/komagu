'use strict';

const {
  ResourceOperation,
  HttpException,
  NotFoundException,
  UnauthorizedException,
  LoggingSecurityAuditSink,
  InMemorySecurityAuditSink,
} = require('./interfaces');

const { KomaguSecurityService } = require('./service');
const { KOMAGU_REQUIRE_OWNERSHIP_KEY, RequireOwnership, CurrentUser } = require('./nestjs/decorators');
const { OwnershipGuard } = require('./nestjs/guards');
const { OwnershipInterceptor } = require('./nestjs/interceptors');
const { komaguOwnershipMiddleware } = require('./express/middleware');

module.exports = {
  ResourceOperation,
  HttpException,
  NotFoundException,
  UnauthorizedException,
  LoggingSecurityAuditSink,
  InMemorySecurityAuditSink,
  KomaguSecurityService,
  KOMAGU_REQUIRE_OWNERSHIP_KEY,
  RequireOwnership,
  CurrentUser,
  OwnershipGuard,
  OwnershipInterceptor,
  komaguOwnershipMiddleware,
};
