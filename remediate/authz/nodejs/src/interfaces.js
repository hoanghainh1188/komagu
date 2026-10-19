'use strict';

/**
 * Komainu Object-Level Authorization Interfaces & Exceptions (Node.js).
 */

const ResourceOperation = Object.freeze({
  READ: 'Read',
  CREATE: 'Create',
  UPDATE: 'Update',
  DELETE: 'Delete',
});

/**
 * Base HTTP Exception for NestJS compatibility.
 */
class HttpException extends Error {
  constructor(response, status) {
    super(typeof response === 'string' ? response : (response.message || 'HTTP Exception'));
    this.name = this.constructor.name;
    this.status = status;
    this.response = typeof response === 'string' ? { statusCode: status, message: response } : response;
  }

  getStatus() {
    return this.status;
  }

  getResponse() {
    return this.response;
  }
}

/**
 * Thrown on BOLA / IDOR denial.
 * Invariant: Always returns HTTP 404 to avoid ID enumeration.
 */
class NotFoundException extends HttpException {
  constructor(message = 'Resource not found') {
    super(message, 404);
  }
}

class UnauthorizedException extends HttpException {
  constructor(message = 'Unauthorized') {
    super(message, 401);
  }
}

class LoggingSecurityAuditSink {
  constructor(logger = console) {
    this.logger = logger;
  }

  emit(event) {
    this.logger.warn(`SECURITY_AUDIT: ${JSON.stringify(event)}`);
  }
}

class InMemorySecurityAuditSink {
  constructor() {
    this.events = [];
  }

  emit(event) {
    this.events.push(event);
  }

  clear() {
    this.events = [];
  }
}

module.exports = {
  ResourceOperation,
  HttpException,
  NotFoundException,
  UnauthorizedException,
  LoggingSecurityAuditSink,
  InMemorySecurityAuditSink,
};
