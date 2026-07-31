import { env } from '../config/env.js';
import {
  PlatformTokenException,
  PlatformTokenInvalidException,
  TenantAccessDeniedException,
  TenantSelectionRequiredException,
} from './errors/platform-token.error.js';
import { TenantGrpcService } from './tenant-grpc.client.js';
import { TenantKeycloakSyncService } from './tenant-keycloak-sync.service.js';
import { Injectable } from '@nestjs/common';
import { ValkeyService } from '@omnixys/cache-ts';
import { MembershipRole, MembershipStatus } from '@omnixys/grpc-ts/types';
import type { TenantMembershipProjection } from '@omnixys/grpc-ts/types';
import * as jose from 'jose';
import { createHash, randomUUID } from 'node:crypto';

export interface PlatformTokenClaims extends jose.JWTPayload {
  ver?: string;
  tenant_id?: string;
  tenant_role?: string;
  realm_access?: { roles?: string[] };
  resource_access?: Record<string, { roles?: string[] }>;
  preferred_username?: string;
  email?: string;
}

export interface PlatformTokenProfile {
  realm_access?: { roles?: string[] };
  resource_access?: Record<string, { roles?: string[] }>;
  preferredUsername?: string;
  email?: string;
}

export interface IssuedPlatformToken {
  accessToken: string;
  expiresIn: number;
  tenantId: string;
  role?: string;
}

export interface SessionIssueOptions {
  /** Expliziter Tenant (Pflicht bei mehreren aktiven Memberships). */
  tenantId?: string;
  /** Keycloak-Zugriffstoken für Rollen-/Profil-Claims im Plattformtoken. */
  kcAccessToken?: string;
  /** Explizites Profil – gewinnt gegenüber den Claims aus kcAccessToken. */
  profile?: PlatformTokenProfile;
}

/**
 * TokenBroker: münzt nach erfolgreicher Keycloak-Authentifizierung den
 * kurzlebigen, eigenständigen Plattform-Access-Token (RS256) mit den Claims
 * `tenant_id`, `tenant_role`, `ver` und `jti`.
 *
 * Membership-Auflösung erfolgt autoritativ über den tenant-service (gRPC):
 *  - 0 aktive Memberships        → Zugriff strikt verweigert (fail-closed)
 *  - 1 aktives Membership        → Auto-Select
 *  - >1 aktive Memberships       → explizite Tenant-Auswahl erforderlich
 *
 * Revocation: `platform:revoked:{jti}` in Valkey (TTL = Token-TTL).
 * Der KC-`tenants`-Mirror wird über die TenantKeycloakSync-Outbox nachgezogen.
 */
@Injectable()
export class PlatformTokenService {
  private keyPromise: Promise<jose.CryptoKey> | undefined;

  constructor(
    private readonly tenants: TenantGrpcService,
    private readonly sync: TenantKeycloakSyncService,
    private readonly cache: ValkeyService,
  ) {}

  /**
   * Stellt einen Plattform-Session aus: Membership-Auflösung → Mint → Sync-Enqueue.
   */
  async issueSession(
    userId: string,
    options: SessionIssueOptions = {},
  ): Promise<IssuedPlatformToken> {
    const { activeTenantIds, resolved } = await this.resolveTenant(userId, options.tenantId);
    const { accessToken, expiresIn } = await this.mint(
      userId,
      resolved.tenantId,
      resolved.role,
      options,
    );
    await this.sync.enqueueIfChanged(userId, activeTenantIds);
    return {
      accessToken,
      expiresIn,
      tenantId: resolved.tenantId,
      role: resolved.role,
    };
  }

  /**
   * Wechsel des aktiven Tenants: vorheriges Token wird revidiert (jti), danach
   * neues Plattformtoken für den Ziel-Tenant gemünzt.
   */
  async switchTenant(
    previousAccessToken: string,
    userId: string,
    tenantId: string,
  ): Promise<IssuedPlatformToken> {
    const claims = await this.verifyToken(previousAccessToken);
    if (claims.sub !== userId) {
      throw new PlatformTokenException('platform-token.switchTenant.subject-mismatch');
    }
    if (claims.jti) {
      await this.revokeToken(claims.jti);
    }
    return this.issueSession(userId, {
      tenantId,
      profile: {
        realm_access: claims.realm_access,
        resource_access: claims.resource_access,
        preferredUsername: claims.preferred_username,
        email: claims.email,
      },
    });
  }

  /**
   * Verifiziert ein Plattformtoken (Issuer, RS256) inkl. Revocation-Check.
   */
  async verifyToken(token: string): Promise<PlatformTokenClaims> {
    const key = await this.signingKey();
    let payload: jose.JWTPayload;
    try {
      ({ payload } = await jose.jwtVerify(token, key, {
        issuer: env.PLATFORM_ISSUER,
        algorithms: ['RS256'],
      }));
    } catch (err) {
      throw new PlatformTokenInvalidException('verification-failed', err);
    }

    const jti = typeof payload.jti === 'string' ? payload.jti : undefined;
    if (jti && (await this.isRevoked(jti))) {
      throw new PlatformTokenInvalidException('revoked');
    }
    return payload;
  }

  /**
   * Widerruft ein Plattformtoken über die Revocation-Liste in Valkey.
   */
  async revokeToken(jti: string): Promise<void> {
    if (!jti) {
      return;
    }
    await this.cache.rawSet(`platform:revoked:${jti}`, '1', env.PLATFORM_TOKEN_TTL_SEC);
  }

  /**
   * Öffentliches JWKS für die Plattform-Token-Verifikation
   * (`GET /auth/oidc/certs`).
   */
  async getPublicJwks(): Promise<jose.JSONWebKeySet> {
    const jwk = await this.publicJwk();
    return {
      keys: [{ ...jwk, use: 'sig', alg: 'RS256', kid: await this.keyId() }],
    };
  }

  private async resolveTenant(
    userId: string,
    tenantId?: string,
  ): Promise<{
    activeTenantIds: string[];
    resolved: { tenantId: string; role?: string };
  }> {
    const { memberships } = await this.tenants.listUserTenants({ userId });
    const active = memberships.filter(
      (membership) => membership.status === MembershipStatus.ACTIVE,
    );

    if (active.length === 0) {
      throw new TenantAccessDeniedException();
    }

    let candidate: TenantMembershipProjection;
    if (tenantId) {
      const found = active.find((membership) => membership.tenantId === tenantId);
      if (!found) {
        throw new TenantAccessDeniedException(tenantId);
      }
      candidate = found;
    } else if (active.length === 1) {
      const first = active[0];
      if (!first) {
        throw new PlatformTokenException('platform-token.active-membership-missing');
      }
      candidate = first;
    } else {
      throw new TenantSelectionRequiredException(active.map((membership) => membership.tenantId));
    }

    const check = await this.tenants.validateMembership({
      tenantId: candidate.tenantId,
      userId,
    });
    if (!check.tenantExists || !check.tenantActive) {
      throw new TenantAccessDeniedException(candidate.tenantId);
    }

    return {
      activeTenantIds: active.map((membership) => membership.tenantId),
      resolved: {
        tenantId: candidate.tenantId,
        role: normalizeRole(candidate.role),
      },
    };
  }

  private async mint(
    userId: string,
    tenantId: string,
    role: string | undefined,
    options: SessionIssueOptions,
  ): Promise<{ accessToken: string; expiresIn: number }> {
    const key = await this.signingKey();
    const kid = await this.keyId();
    const now = Math.floor(Date.now() / 1000);
    const ttl = env.PLATFORM_TOKEN_TTL_SEC;

    const claims: Record<string, unknown> = {
      ver: env.PLATFORM_TOKEN_VERSION,
      tenant_id: tenantId,
    };
    if (role) {
      claims.tenant_role = role;
    }
    this.applyProfileClaims(claims, options);

    const accessToken = await new jose.SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(env.PLATFORM_ISSUER)
      .setSubject(userId)
      .setJti(randomUUID())
      .setIssuedAt(now)
      .setExpirationTime(now + ttl)
      .sign(key);

    return { accessToken, expiresIn: ttl };
  }

  private applyProfileClaims(claims: Record<string, unknown>, options: SessionIssueOptions): void {
    const profile = options.profile ?? {};
    if (options.kcAccessToken) {
      try {
        const decoded = jose.decodeJwt<PlatformTokenClaims>(options.kcAccessToken);
        claims.realm_access = decoded.realm_access ?? claims.realm_access;
        claims.resource_access = decoded.resource_access ?? claims.resource_access;
        claims.preferred_username = decoded.preferred_username ?? claims.preferred_username;
        claims.email = decoded.email ?? claims.email;
      } catch {
        // Kein gültiges KC-Token → explizites Profil verwenden
      }
    }
    if (profile.realm_access !== undefined) {
      claims.realm_access = profile.realm_access;
    }
    if (profile.resource_access !== undefined) {
      claims.resource_access = profile.resource_access;
    }
    if (profile.preferredUsername !== undefined) {
      claims.preferred_username = profile.preferredUsername;
    }
    if (profile.email !== undefined) {
      claims.email = profile.email;
    }
  }

  private async signingKey(): Promise<jose.CryptoKey> {
    if (!this.keyPromise) {
      const pem = env.PLATFORM_SIGNING_KEY;
      if (!pem) {
        throw new PlatformTokenException('platform-token.signing-key-missing');
      }
      this.keyPromise = jose.importPKCS8(pem, 'RS256');
    }
    return this.keyPromise;
  }

  private async publicJwk(): Promise<Record<string, unknown>> {
    const key = await this.signingKey();
    const full = await jose.exportJWK(key);
    const publicPart: Record<string, unknown> = {};
    for (const field of ['kty', 'n', 'e', 'alg', 'use'] as const) {
      if (full[field] !== undefined) {
        publicPart[field] = full[field];
      }
    }
    return publicPart;
  }

  private async keyId(): Promise<string> {
    const jwk = await this.publicJwk();
    const canonical = JSON.stringify({ kty: jwk.kty, n: jwk.n, e: jwk.e });
    return createHash('sha256').update(canonical).digest('hex').slice(0, 16);
  }

  private async isRevoked(jti: string): Promise<boolean> {
    return this.cache.exists(`platform:revoked:${jti}`);
  }
}

function normalizeRole(role: string | undefined): string | undefined {
  return role && isMembershipRole(role) ? role : undefined;
}

function isMembershipRole(role: string): boolean {
  const valid: string[] = [
    MembershipRole.OWNER,
    MembershipRole.ADMIN,
    MembershipRole.MEMBER,
    MembershipRole.GUEST,
  ];
  return valid.includes(role);
}
