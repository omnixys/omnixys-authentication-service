import { keycloakConfig, paths } from '../../config/keycloak.js';
import {
  AuthenticationStateException,
  IdentityProviderResponseException,
} from '../errors/authentication.error.js';
import type {
  KeycloakAccessTokenResponse,
  KeycloakTokenPayload,
} from '../models/dtos/kc-token.dto.js';
import { AuthenticateBaseService } from '../services/keycloak-base.service.js';
import { AuthenticateReadService } from '../services/read.service.js';
import { MAIL_TOKEN_JWE } from './mail-token.crypto.js';
import { HttpService } from '@nestjs/axios';
import { Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ValkeyLockService, ValkeyService } from '@omnixys/cache-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { JweService } from '@omnixys/security-ts';
import { createHash } from 'node:crypto';

const CACHE_PREFIX = 'mail:downstream:v1';
const EXPIRY_SKEW_SECONDS = 15;

export interface MailTokenResponse {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

interface CachedMailToken {
  accessToken: string;
  tokenType: 'Bearer';
  expiresAt: number;
  subjectHash: string;
}

@Injectable()
export class MailTokenService extends AuthenticateBaseService {
  constructor(
    logger: OmnixysLogger,
    http: HttpService,
    private readonly readService: AuthenticateReadService,
    private readonly cache: ValkeyService,
    private readonly locks: ValkeyLockService,
    @Inject(MAIL_TOKEN_JWE) private readonly jwe: JweService,
  ) {
    super(logger, http);
  }

  async issue(subjectToken: string): Promise<MailTokenResponse> {
    const subject = await this.readService.verifyAccessToken(subjectToken);
    this.assertPlatformToken(subject);
    const subjectHash = createHash('sha256').update(subjectToken, 'utf8').digest('hex');
    const cached = await this.readCached(subjectHash);
    if (cached) {
      return cached;
    }

    const lockKey = this.cache.key(`lock:${CACHE_PREFIX}:${subjectHash}`);
    const lockToken = await this.locks.acquireLock(lockKey, 10_000);
    if (!lockToken) {
      const shared = await this.waitForCached(subjectHash);
      if (shared) {
        return shared;
      }
      throw new ServiceUnavailableException({
        code: 'MAIL_TOKEN_EXCHANGE_BUSY',
        message: 'Mail authentication is temporarily busy',
      });
    }

    try {
      const afterLock = await this.readCached(subjectHash);
      if (afterLock) {
        return afterLock;
      }
      return await this.exchangeAndCache(subjectToken, subjectHash, subject);
    } finally {
      await this.locks.releaseLock(lockKey, lockToken);
    }
  }

  private async exchangeAndCache(
    subjectToken: string,
    subjectHash: string,
    subject: KeycloakTokenPayload,
  ): Promise<MailTokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: keycloakConfig.clientId,
      client_secret: keycloakConfig.clientSecret,
      subject_token: subjectToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      scope: 'stalwart-downstream',
      audience: 'stalwart',
    });
    const exchanged = await this.kcRequest<KeycloakAccessTokenResponse>('post', paths.accessToken, {
      data: body.toString(),
      headers: this.loginHeaders,
      adminAuth: false,
    });
    if (exchanged.refresh_token) {
      throw new IdentityProviderResponseException('mail-token-exchange-refresh-token');
    }
    if (!exchanged.access_token || !Number.isFinite(exchanged.expires_in)) {
      throw new IdentityProviderResponseException('mail-token-exchange-response');
    }

    const downstream = await this.readService.verifyAccessToken(exchanged.access_token);
    this.assertDownstreamToken(subject, downstream);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const sourceRemaining = (subject.exp ?? nowSeconds) - nowSeconds;
    const expiresIn = Math.min(exchanged.expires_in, sourceRemaining, 300);
    const cacheTtl = Math.floor(expiresIn - EXPIRY_SKEW_SECONDS);
    if (cacheTtl <= 0) {
      throw new AuthenticationStateException('mail-token-lifetime-invalid');
    }
    const cached: CachedMailToken = {
      accessToken: exchanged.access_token,
      tokenType: 'Bearer',
      expiresAt: Date.now() + expiresIn * 1000,
      subjectHash,
    };
    await this.cache.rawSet(
      `${CACHE_PREFIX}:${subjectHash}`,
      await this.jwe.encrypt(cached),
      cacheTtl,
    );
    return this.toResponse(cached);
  }

  private assertPlatformToken(payload: KeycloakTokenPayload): void {
    if (
      !payload.sub ||
      !payload.preferred_username ||
      payload.azp !== keycloakConfig.clientId ||
      !payload.exp
    ) {
      throw new AuthenticationStateException('platform-token-shape-invalid');
    }
  }

  private assertDownstreamToken(
    source: KeycloakTokenPayload,
    downstream: KeycloakTokenPayload,
  ): void {
    const audiences = Array.isArray(downstream.aud)
      ? downstream.aud
      : downstream.aud
        ? [downstream.aud]
        : [];
    if (
      audiences.length !== 1 ||
      audiences[0] !== 'stalwart' ||
      downstream.azp !== keycloakConfig.clientId ||
      downstream.sub !== source.sub ||
      downstream.preferred_username !== source.preferred_username
    ) {
      throw new AuthenticationStateException('mail-token-shape-invalid');
    }
  }

  private async readCached(subjectHash: string): Promise<MailTokenResponse | null> {
    const encrypted = await this.cache.rawGet(`${CACHE_PREFIX}:${subjectHash}`);
    if (!encrypted) {
      return null;
    }
    try {
      const cached = await this.jwe.decrypt<CachedMailToken>(encrypted);
      if (
        cached.subjectHash !== subjectHash ||
        cached.tokenType !== 'Bearer' ||
        cached.expiresAt <= Date.now() + EXPIRY_SKEW_SECONDS * 1000
      ) {
        await this.cache.rawDelete(`${CACHE_PREFIX}:${subjectHash}`);
        return null;
      }
      return this.toResponse(cached);
    } catch {
      await this.cache.rawDelete(`${CACHE_PREFIX}:${subjectHash}`);
      return null;
    }
  }

  private async waitForCached(subjectHash: string): Promise<MailTokenResponse | null> {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      const cached = await this.readCached(subjectHash);
      if (cached) {
        return cached;
      }
    }
    return null;
  }

  private toResponse(cached: CachedMailToken): MailTokenResponse {
    return {
      accessToken: cached.accessToken,
      tokenType: 'Bearer',
      expiresIn: Math.max(0, Math.floor((cached.expiresAt - Date.now()) / 1000)),
    };
  }
}
