import { ResourceOperationType } from '../interfaces';

export declare const KOMAGU_REQUIRE_OWNERSHIP_KEY = 'komagu:require_ownership';

export interface RequireOwnershipOptions {
  idParamName?: string;
  resourceLoader?: (id: string, req: any) => Promise<any> | any;
  [key: string]: any;
}

export declare function RequireOwnership(
  operation?: ResourceOperationType,
  options?: RequireOwnershipOptions
): MethodDecorator & ClassDecorator;

export declare function CurrentUser(): ParameterDecorator;
