import { env } from '../../config/env.js';
import { AuthenticationStateException } from '../errors/authentication.error.js';
import { ContextAccessor } from '@omnixys/context-ts';
import { guestAuthKeySchema } from '@omnixys/contracts-ts';

const tenantIdSchema = guestAuthKeySchema.shape.tenantId;

export function resolveTenantId(explicitTenantId?: string): string {
  const context = ContextAccessor.get();
  const candidate =
    explicitTenantId ??
    context?.tenant?.tenantId ??
    context?.principal?.tenantId ??
    env.DEFAULT_TENANT_ID;
  const parsed = tenantIdSchema.safeParse(candidate);

  if (!parsed.success) {
    throw new AuthenticationStateException(
      'verified-tenant-required',
      parsed.error,
    );
  }

  return parsed.data;
}

export function keycloakTenantAttributes(explicitTenantId?: string): {
  tenants: string[];
} {
  return { tenants: [resolveTenantId(explicitTenantId)] };
}
