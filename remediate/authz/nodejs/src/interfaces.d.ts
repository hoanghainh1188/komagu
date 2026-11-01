export type ResourceOperationType = 'Read' | 'Create' | 'Update' | 'Delete';

export declare const ResourceOperation: {
  readonly READ: 'Read';
  readonly CREATE: 'Create';
  readonly UPDATE: 'Update';
  readonly DELETE: 'Delete';
};

export interface IOwnedResource {
  id?: string | number;
  ownerUserId: string;
  tenantId: string;
  [key: string]: any;
}

export interface SecurityAuditEvent {
  timestamp: string;
  eventName: string;
  actorUserId?: string;
  actorTenantId?: string;
  resourceType: string;
  resourceId?: string;
  operation: ResourceOperationType;
  reason: string;
}

export interface RoleDeniedAuditEvent {
  timestamp: string;
  eventName: 'Komagu.Authorization.RoleDenied';
  actorUserId?: string;
  actorTenantId?: string;
  requiredRoles: string[];
  route?: string;
  reason: string;
}

export interface ISecurityAuditSink {
  emit(event: SecurityAuditEvent | RoleDeniedAuditEvent): void | Promise<void>;
}

export declare class HttpException extends Error {
  readonly status: number;
  readonly response: any;
  constructor(response: any, status: number);
  getStatus(): number;
  getResponse(): any;
}

export declare class NotFoundException extends HttpException {
  constructor(message?: string);
}

export declare class UnauthorizedException extends HttpException {
  constructor(message?: string);
}

export declare class ForbiddenException extends HttpException {
  constructor(message?: string);
}

export declare class LoggingSecurityAuditSink implements ISecurityAuditSink {
  constructor(logger?: any);
  emit(event: SecurityAuditEvent | RoleDeniedAuditEvent): void;
}

export declare class InMemorySecurityAuditSink implements ISecurityAuditSink {
  readonly events: Array<SecurityAuditEvent | RoleDeniedAuditEvent>;
  emit(event: SecurityAuditEvent | RoleDeniedAuditEvent): void;
  clear(): void;
}

export interface UserPrincipal {
  userId: string;
  tenantId: string;
  claims?: Record<string, any>;
  roles?: string[];
  role?: string;
  isAuthenticated?: boolean;
}
