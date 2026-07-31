import { env } from '../config/env.js';
import { CoreHttpModule } from '../http.module.js';
import { PlatformTokenController } from './platform-token.controller.js';
import { PlatformTokenService } from './platform-token.service.js';
import { TenantGrpcService } from './tenant-grpc.client.js';
import { TenantKeycloakSyncProcessor } from './tenant-keycloak-sync.processor.js';
import { TenantKeycloakSyncService } from './tenant-keycloak-sync.service.js';
import { Global, Module } from '@nestjs/common';
import { GrpcClientModule } from '@omnixys/grpc-ts/clients';
import { fileURLToPath } from 'node:url';

/**
 * Plattform-Token-Broker:
 *  - gRPC-Client zum tenant-service (Membership-Auflösung, per-caller Bearer)
 *  - Plattformtoken (RS256, `ver`/`tenant_id`/`tenant_role`, Revocation via Valkey)
 *  - `GET /auth/oidc/certs` (JWKS)
 *  - `TenantKeycloakSync`-Outbox für den idempotenten KC-Mirror
 */
@Global()
@Module({
  imports: [
    CoreHttpModule,
    GrpcClientModule.register({
      package: 'omnixys.tenant',
      protoPath: fileURLToPath(import.meta.resolve('@omnixys/grpc-ts/proto/tenant.proto')),
      url: env.TENANT_GRPC_URL,
    }),
  ],
  controllers: [PlatformTokenController],
  providers: [
    TenantGrpcService,
    PlatformTokenService,
    TenantKeycloakSyncService,
    TenantKeycloakSyncProcessor,
  ],
  exports: [PlatformTokenService, TenantKeycloakSyncService],
})
export class PlatformTokenModule {}
