import { ResourceOperationType } from '../interfaces';
import { KomainuSecurityService } from '../service';

export interface ExpressMiddlewareConfig {
  operation?: ResourceOperationType;
  idParamName?: string;
  resourceLoader: (id: string, req: any) => Promise<any> | any;
  securityService?: KomainuSecurityService;
}

export declare function komainuOwnershipMiddleware(
  config: ExpressMiddlewareConfig
): (req: any, res: any, next: (err?: any) => void) => Promise<void>;
