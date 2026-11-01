import { ResourceOperationType } from '../interfaces';

export declare const KOMAGU_REQUIRE_OWNERSHIP_KEY = 'komagu:require_ownership';
export declare const KOMAGU_REQUIRE_ROLE_KEY = 'komagu:require_role';

export interface RequireOwnershipOptions {
  idParamName?: string;
  resourceLoader?: (id: string, req: any) => Promise<any> | any;
  [key: string]: any;
}

export declare function RequireOwnership(
  operation?: ResourceOperationType,
  options?: RequireOwnershipOptions
): MethodDecorator & ClassDecorator;

export interface RequireRoleDecoratorOptions {
  /** 403 Forbidden (default) or 404 Resource not found to hide the endpoint. */
  denyStatus?: 403 | 404;
}

export interface RequireRoleMetadata {
  readonly roles: readonly string[];
  readonly denyStatus: 403 | 404;
}

export declare function RequireRole(
  roles: string | readonly string[],
  options?: RequireRoleDecoratorOptions
): MethodDecorator & ClassDecorator;

export declare function CurrentUser(): ParameterDecorator;
