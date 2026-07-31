import { PlatformTokenService } from './platform-token.service.js';
import { Controller, Get } from '@nestjs/common';
import type * as jose from 'jose';

/**
 * Öffentliche JWKS-Endpunkte für die Plattform-Token-Verifikation.
 * Der `PLATFORM_JWKS_URI` (Standard `${PLATFORM_ISSUER}/auth/oidc/certs`)
 * zeigt auf diesen Endpoint; Gateway und Services validieren Plattform-Tokens
 * gegen diese Keys.
 */
@Controller('auth/oidc')
export class PlatformTokenController {
  constructor(private readonly platformTokens: PlatformTokenService) {}

  @Get('certs')
  async certs(): Promise<jose.JSONWebKeySet> {
    return this.platformTokens.getPublicJwks();
  }
}
