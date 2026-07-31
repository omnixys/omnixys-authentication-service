import { TenantKeycloakSyncService } from './tenant-keycloak-sync.service.js';
import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import { OmnixysLogger } from '@omnixys/logger-ts';

/**
 * Prozessiert die `TenantKeycloakSync`-Outbox periodisch (Claim via Lock,
 * idempotenter KC-Write nur bei Abweichung, Retry mit Backoff).
 */
@Injectable()
export class TenantKeycloakSyncProcessor implements OnModuleDestroy {
  private readonly logger: ReturnType<OmnixysLogger['log']>;
  private running = true;

  constructor(
    private readonly syncService: TenantKeycloakSyncService,
    omnixysLogger: OmnixysLogger,
  ) {
    this.logger = omnixysLogger.log(TenantKeycloakSyncProcessor.name);
  }

  @Interval(30_000)
  async process(): Promise<void> {
    if (!this.running) {
      return;
    }
    try {
      const processed = await this.syncService.processPending();
      if (processed > 0) {
        this.logger.info('tenant_kc_sync_processed', { processed });
      }
    } catch (err) {
      this.logger.warn('tenant_kc_sync_failed', {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  onModuleDestroy(): void {
    this.running = false;
  }
}
