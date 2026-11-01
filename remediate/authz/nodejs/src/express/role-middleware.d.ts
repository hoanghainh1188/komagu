import { KomaguSecurityService } from '../service';

export type RoleDenyStatus = 403 | 404;

export interface RequireRoleOptions {
  /** 403 Forbidden (default) or 404 Resource not found to hide the endpoint. */
  denyStatus?: RoleDenyStatus;
  securityService?: KomaguSecurityService;
}

export declare function requireRole(
  roles: string | readonly string[],
  options?: RequireRoleOptions
): (req: any, res: any, next: (err?: any) => void) => Promise<void>;
