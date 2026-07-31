import { AuthenticateBaseService } from '../authentication/services/keycloak-base.service.js';
import { paths } from '../config/keycloak.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { randomUUID } from 'node:crypto';

interface RawKeycloakUser {
  id?: string;
  attributes?: Record<string, string[]>;
}

const MAX_ATTEMPTS = 10;
const REVOCATION_BACKOFF_SECONDS = 60 * 60; // DLT-ähnlich nach Erschöpfung

/**
 * Spiegelung der autoritativen Tenant-Memberships (tenant-service) in das
 * Keycloak-`tenants`-Attribut (idempotenter Mirror) über die
 * `TenantKeycloakSync`-Outbox.
 *
 *  - `enqueueIfChanged` legt PENDING-Rows an (upsert pro User), ohne KC zu berühren.
 *  - `processPending` schreibt KC nur bei Abweichung (vergleichend, idempotent)
 *    und markiert SYNCED / FAILED (Retry mit Backoff).
 */
@Injectable()
export class TenantKeycloakSyncService extends AuthenticateBaseService {
  private readonly instanceId = randomUUID();

  constructor(
    logger: OmnixysLogger,
    http: HttpService,
    private readonly prisma: PrismaService,
  ) {
    super(logger, http);
  }

  async enqueueIfChanged(userId: string, tenantIds: string[]): Promise<void> {
    const normalized = normalizeTenantIds(tenantIds);
    const existing = await this.prisma.tenantKeycloakSync.findUnique({
      where: { userId },
    });

    if (existing && existing.state !== 'FAILED' && sameTenantSet(existing.tenantIds, normalized)) {
      return;
    }

    await this.prisma.tenantKeycloakSync.upsert({
      where: { userId },
      create: {
        userId,
        tenantIds: normalized,
        state: 'PENDING',
      },
      update: {
        tenantIds: normalized,
        state: 'PENDING',
        attempts: 0,
        lastError: null,
        nextAttemptAt: new Date(),
        lockedAt: null,
        lockedBy: null,
      },
    });
  }

  async processPending(batchSize = 50): Promise<number> {
    const due = await this.prisma.tenantKeycloakSync.findMany({
      where: {
        state: 'PENDING',
        nextAttemptAt: { lte: new Date() },
      },
      take: batchSize,
      orderBy: { nextAttemptAt: 'asc' },
    });

    let processed = 0;
    for (const row of due) {
      const claimed = await this.prisma.tenantKeycloakSync.updateMany({
        where: {
          id: row.id,
          state: 'PENDING',
          nextAttemptAt: { lte: new Date() },
        },
        data: { lockedAt: new Date(), lockedBy: this.instanceId },
      });
      if (claimed.count !== 1) {
        continue;
      }

      try {
        await this.applyMirror(row.userId, row.tenantIds);
        await this.prisma.tenantKeycloakSync.update({
          where: { id: row.id },
          data: {
            state: 'SYNCED',
            syncedAt: new Date(),
            lastError: null,
            lockedAt: null,
            lockedBy: null,
          },
        });
        processed++;
      } catch (err) {
        await this.markFailed(row.id, err);
      }
    }
    return processed;
  }

  /**
   * Vergleicht das KC-`tenants`-Attribut mit dem Ziel-Set und schreibt nur bei
   * Abweichung (idempotent). Andere KC-Attribute bleiben unangetastet.
   */
  private async applyMirror(userId: string, tenantIds: string[]): Promise<void> {
    const raw = await this.kcRequest<RawKeycloakUser>(
      'get',
      `${paths.users}/${encodeURIComponent(userId)}`,
    );
    if (!raw?.id) {
      throw new Error('Keycloak user not found for tenant mirror');
    }

    const current = tenantsAttribute(raw.attributes);
    if (sameTenantSet(current, tenantIds)) {
      return;
    }

    const attributes: Record<string, string[]> = {
      ...(raw.attributes ?? {}),
      tenants: tenantIds,
    };
    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(userId)}`, {
      data: { attributes },
      headers: await this.adminJsonHeaders(),
    });
  }

  private async markFailed(id: string, err: unknown): Promise<void> {
    const row = await this.prisma.tenantKeycloakSync.findUnique({
      where: { id },
    });
    if (!row) {
      return;
    }
    const attempts = row.attempts + 1;
    const deadLettered = attempts >= MAX_ATTEMPTS;
    const backoffSeconds = Math.min(REVOCATION_BACKOFF_SECONDS, Math.pow(2, attempts));

    await this.prisma.tenantKeycloakSync.update({
      where: { id },
      data: {
        attempts,
        lastError: err instanceof Error ? err.message.slice(0, 500) : String(err),
        state: deadLettered ? 'FAILED' : 'PENDING',
        nextAttemptAt: deadLettered
          ? row.nextAttemptAt
          : new Date(Date.now() + backoffSeconds * 1000),
        lockedAt: null,
        lockedBy: null,
      },
    });
  }
}

function normalizeTenantIds(tenantIds: string[]): string[] {
  return [...new Set(tenantIds)].sort();
}

function tenantsAttribute(attributes: Record<string, string[]> | undefined): string[] {
  const value = attributes?.tenants;
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry): entry is string => typeof entry === 'string');
}

function sameTenantSet(a: string[], b: string[]): boolean {
  const na = normalizeTenantIds(a);
  const nb = normalizeTenantIds(b);
  return na.length === nb.length && na.every((value, index) => value === nb[index]);
}
