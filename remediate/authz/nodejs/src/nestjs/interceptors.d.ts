import { KomaguSecurityService } from '../service';

export declare class OwnershipInterceptor {
  constructor(reflector: any, securityService: KomaguSecurityService);
  intercept(context: any, next: any): Promise<any>;
}
