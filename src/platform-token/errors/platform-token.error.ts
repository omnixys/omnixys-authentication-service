import { AuthenticationDomainException } from '../../authentication/errors/authentication.error.js';

/**
 * Keine aktive Tenant-Membership für den angefragten Tenant.
 *  - kein aktives Membership → Zugriff strikt verweigert (fail-closed).
 */
export class TenantAccessDeniedException extends AuthenticationDomainException {
  constructor(tenantId?: string) {
    super(
      'PLATFORM_TENANT_ACCESS_DENIED',
      'No active membership for the requested tenant',
      tenantId ? { tenantId } : {},
    );
  }
}

/**
 * Mehrere aktive Tenants – eine explizite Tenant-Auswahl ist erforderlich.
 */
export class TenantSelectionRequiredException extends AuthenticationDomainException {
  constructor(tenantIds: string[]) {
    super(
      'PLATFORM_TENANT_SELECTION_REQUIRED',
      'Multiple tenants require an explicit tenant selection',
      {},
      undefined,
      { tenantIds },
    );
  }
}

/**
 * Allgemeiner Plattform-Token-Fehler (Signing-/Konfiguration-/Verifikationsfehler).
 */
export class PlatformTokenException extends AuthenticationDomainException {
  constructor(operation: string, cause?: unknown) {
    super(
      'PLATFORM_TOKEN_ERROR',
      'Platform token operation failed',
      { operation },
      cause,
    );
  }
}

/**
 * Revoked- oder Ablauf-Check schlägt bei der Plattform-Token-Verifikation fehl.
 */
export class PlatformTokenInvalidException extends AuthenticationDomainException {
  constructor(reason: string, cause?: unknown) {
    super('PLATFORM_TOKEN_INVALID', 'Platform token is invalid', {}, cause, {
      reason,
    });
  }
}
