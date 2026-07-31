/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

import { RateLimitValkeyAdapterModule } from './adapter/rate-limit/rate-limit-valkey-adapter.module.js';
import { ZeroTrustValkeyAdapterModule } from './adapter/zero-trust/zero-trust-valkey-adapter.module.js';
import { AdminModule } from './admin/admin.module.js';
import { AuthenticationModule } from './authentication/authentication.module.js';
import { BannerService } from './banner.service.js';
import { env } from './config/env.js';
import { ScalarsModule } from './core/scalars/scalar.module.js';
import { HandlerModule } from './handlers/handler.module.js';
import { HealthModule } from './health/health.module.js';
import { PlatformTokenModule } from './platform-token/platform-token.module.js';
import { Module } from '@nestjs/common';
import { ValkeyModule } from '@omnixys/cache-ts';
import { ContextModule, trustedProxyPolicyFromAddresses } from '@omnixys/context-ts';
import { OmnixysGraphQLModule } from '@omnixys/graphql-ts';
import { OmnixysHttpModule } from '@omnixys/http-ts';
import { KafkaModule } from '@omnixys/kafka-ts';
import { LoggerModule } from '@omnixys/logger-ts';
import { ObservabilityModule } from '@omnixys/observability-ts';
import { SecurityModule } from '@omnixys/security-ts';
import type { FastifyReply, FastifyRequest } from 'fastify';

const {
  SCHEMA_TARGET,
  SERVICE,
  KAFKA_BROKER,
  TEMPO_URI,
  VALKEY_URL,
  VALKEY_PASSWORD,
  PC_JWE_KEY,
  RESET_TOKEN_HMAC_SECRET,
  DEVICE_FINGERPRINT_HMAC_SECRET,
  MAGIC_LINK_HMAC_SECRET,
  ENCRYPTION_KEY,
  FINGERPRINT_SECRET,
  NODE_ENV,
} = env;

@Module({
  imports: [
    ContextModule.forRoot({
      tenant: {
        mode: env.NODE_ENV === 'production' ? 'strict' : 'legacy',
        ...(env.DEFAULT_TENANT_ID ? { defaultTenantId: env.DEFAULT_TENANT_ID } : {}),
      },
      trustedProxyPolicy: trustedProxyPolicyFromAddresses(env.TRUSTED_PROXY_ADDRESSES),
    }),

    ValkeyModule.forRoot({
      serviceName: SERVICE,
      url: VALKEY_URL,
      password: VALKEY_PASSWORD,

      pubSub: { enabled: true },
      streams: { enabled: false },
    }),

    OmnixysGraphQLModule.forRoot({
      context: (req: FastifyRequest, reply: FastifyReply) => ({ req, reply }),
      autoSchemaFile:
        SCHEMA_TARGET === 'tmp'
          ? { path: '/tmp/schema.gql', federation: 2 }
          : SCHEMA_TARGET === 'false'
            ? false
            : { path: 'dist/schema.gql', federation: 2 },
      sortSchema: true,
    }),
    OmnixysHttpModule.forRoot({ serviceName: 'authentication' }),

    SecurityModule.forRoot({
      jwt: {
        issuer: env.PLATFORM_ISSUER,
        jwksUri: env.PLATFORM_JWKS_URI,
      },

      jwe: {
        keys: [
          {
            kid: 'v1',
            value: PC_JWE_KEY,
          },
        ],
      },

      rateLimit: {
        enabled: true,
        defaultLimit: 100,
        defaultWindowMs: 60000,
        imports: [RateLimitValkeyAdapterModule],
      },

      hash: {
        hmacResetToken: RESET_TOKEN_HMAC_SECRET,
        hmacDeviceFingerprint: DEVICE_FINGERPRINT_HMAC_SECRET,
        hmacMagicLink: MAGIC_LINK_HMAC_SECRET,

        encryptionKey: ENCRYPTION_KEY,
      },

      zeroTrust: {
        imports: [ZeroTrustValkeyAdapterModule],
      },

      fingerprintSecret: FINGERPRINT_SECRET,
      cookie: {
        secure: NODE_ENV === 'production',
        sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
        path: '/',
      },
      globalGuards: false,
    }),
    KafkaModule.forRoot({
      clientId: SERVICE,
      brokers: [KAFKA_BROKER],
      groupId: `${SERVICE}-group`,
      serviceName: SERVICE,
      retry: { maxRetries: 5 },
      idempotency: { enabled: true, ttlSeconds: 86_400 },
    }),

    ObservabilityModule.forRoot({
      serviceName: SERVICE,

      otel: {
        endpoint: TEMPO_URI,
        transport: 'http',
        samplingRatio: 1,
      },

      metrics: {
        port: 17501,
        enabled: true,
      },
    }),

    LoggerModule.forRoot({
      serviceName: SERVICE,
      registerGlobalInterceptor: true,

      batch: {
        enabled: true,
        maxSize: 50,
        flushInterval: 2000,
      },
    }),

    AdminModule,
    HealthModule,
    AuthenticationModule,
    PlatformTokenModule,
    ScalarsModule,
    HandlerModule,
  ],
  controllers: [],
  providers: [BannerService],
})
export class AppModule {}
