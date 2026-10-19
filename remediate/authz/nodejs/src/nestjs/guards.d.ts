import { KomainuSecurityService } from '../service';

export declare class OwnershipGuard {
  constructor(reflector: any, securityService: KomainuSecurityService);
  canActivate(context: any): Promise<boolean>;
}
