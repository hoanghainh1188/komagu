import { ResourceOperationType } from '../interfaces';
import { KomaguSecurityService } from '../service';

export interface ExpressMiddlewareConfig {
  operation?: ResourceOperationType;
  idParamName?: string;
  resourceLoader: (id: string, req: any) => Promise<any> | any;
  securityService?: KomaguSecurityService;
}

export declare function komaguOwnershipMiddleware(
  config: ExpressMiddlewareConfig
): (req: any, res: any, next: (err?: any) => void) => Promise<void>;
