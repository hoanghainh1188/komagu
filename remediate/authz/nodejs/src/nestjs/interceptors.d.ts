import { KomainuSecurityService } from '../service';

export declare class OwnershipInterceptor {
  constructor(reflector: any, securityService: KomainuSecurityService);
  intercept(context: any, next: any): Promise<any>;
}
