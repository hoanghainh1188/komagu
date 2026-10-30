import {
  IOwnedResource,
  ISecurityAuditSink,
  ResourceOperationType,
  UserPrincipal,
} from './interfaces';

export interface AuthorizeOptions {
  ownerUserIdExtractor?: (resource: any) => string;
  tenantIdExtractor?: (resource: any) => string;
}

export interface AuthorizationDecision {
  succeeded: boolean;
  failureReason?: string;
}

export declare class KomaguSecurityService {
  readonly auditSink: ISecurityAuditSink;
  constructor(auditSink?: ISecurityAuditSink);
  getCurrentUserId(user: any): string;
  getCurrentTenantId(user: any): string;
  authorize(
    user: any,
    resource: any,
    operation?: ResourceOperationType,
    options?: AuthorizeOptions
  ): Promise<AuthorizationDecision>;
  requireOwnership(
    user: any,
    resource: any,
    operation?: ResourceOperationType,
    options?: AuthorizeOptions
  ): Promise<void>;
}
