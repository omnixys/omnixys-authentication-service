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
import { BannerService } from './config/banner.service.js';
import { env } from './config/env.js';
import { ScalarsModule } from './core/scalars/scalar.module.js';
import { HandlerModule } from './handlers/handler.module.js';
import { HealthModule } from './health/health.module.js';
import { Module } from '@nestjs/common';
import { ValkeyModule } from '@omnixys/cache-ts';
import { ContextModule } from '@omnixys/context-ts';
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
  NODE_ENV,

  KC_URL,
  KC_REALM,

  TENANT_SERVICE_URL,
  TENANT_GRPC_SERVICE_TOKEN,

  KAFKA_BROKER,
  KAFKA_IDEMPOTENCY_ENABLE,
  KAFKA_IDEMPOTENCY_TTL,
  KAFKA_RETRY,

  OTEL_URI,
  OTEL_TRANSPORT_MODE,
  OTEL_SAMPLING_RATIO,
  PROMETHEUS_ENABLE,
  PROMETHEUS_PORT,

  VALKEY_URL,
  VALKEY_PASSWORD,

  PC_JWE_KEY,

  RESET_TOKEN_HMAC_SECRET,
  DEVICE_FINGERPRINT_HMAC_SECRET,
  MAGIC_LINK_HMAC_SECRET,
  ENCRYPTION_KEY,
  FINGERPRINT_SECRET,

  RATE_LIMIT_ENABLE,
  RATE_LIMIT_REQUESTS,
  RATE_LIMIT_WINDOW,

  LOG_BATCH_ENABLE,
  LOG_BATCH_FLUSH_INTERVAL,
  LOG_BATCH_MAX_SIZE,
} = env;

@Module({
  imports: [
    ContextModule.forRoot(),

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
    OmnixysHttpModule.forRoot({ serviceName: SERVICE }),

    SecurityModule.forRoot({
      jwt: {
        issuer: `${KC_URL}/realms/${KC_REALM}`,
        jwksUri: `${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/certs`,
      },

      tenantVerification: {
        url: TENANT_SERVICE_URL,
        callerToken: TENANT_GRPC_SERVICE_TOKEN,
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
        enabled: RATE_LIMIT_ENABLE,
        defaultLimit: RATE_LIMIT_REQUESTS,
        defaultWindowMs: RATE_LIMIT_WINDOW,
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
      retry: { maxRetries: KAFKA_RETRY },
      idempotency: { enabled: KAFKA_IDEMPOTENCY_ENABLE, ttlSeconds: KAFKA_IDEMPOTENCY_TTL },
    }),

    ObservabilityModule.forRoot({
      serviceName: SERVICE,

      otel: {
        endpoint: OTEL_URI,
        transport: OTEL_TRANSPORT_MODE as 'http' | 'grpc',
        samplingRatio: OTEL_SAMPLING_RATIO,
      },

      metrics: {
        port: PROMETHEUS_PORT,
        enabled: PROMETHEUS_ENABLE,
      },
    }),

    LoggerModule.forRoot({
      serviceName: SERVICE,
      registerGlobalInterceptor: true,

      batch: {
        enabled: LOG_BATCH_ENABLE,
        maxSize: LOG_BATCH_MAX_SIZE,
        flushInterval: LOG_BATCH_FLUSH_INTERVAL,
      },
    }),

    AdminModule,
    HealthModule,
    AuthenticationModule,
    ScalarsModule,
    HandlerModule,
  ],
  controllers: [],
  providers: [BannerService],
})
export class AppModule {}
