import { KomaguSecurityService } from '../service';

export declare class OwnershipGuard {
  constructor(reflector: any, securityService: KomaguSecurityService);
  canActivate(context: any): Promise<boolean>;
}

export declare class KomaguRoleGuard {
  constructor(reflector: any, securityService?: KomaguSecurityService);
  canActivate(context: any): Promise<boolean>;
}
