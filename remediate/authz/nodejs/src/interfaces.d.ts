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

export interface ISecurityAuditSink {
  emit(event: SecurityAuditEvent): void | Promise<void>;
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

export declare class LoggingSecurityAuditSink implements ISecurityAuditSink {
  constructor(logger?: any);
  emit(event: SecurityAuditEvent): void;
}

export declare class InMemorySecurityAuditSink implements ISecurityAuditSink {
  readonly events: SecurityAuditEvent[];
  emit(event: SecurityAuditEvent): void;
  clear(): void;
}

export interface UserPrincipal {
  userId: string;
  tenantId: string;
  claims?: Record<string, any>;
  roles?: string[];
  isAuthenticated?: boolean;
}
