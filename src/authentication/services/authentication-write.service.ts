// TODO resolve eslint

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

import { Public } from '../../auth/decorators/public.decorator.js';
import { keycloakConfig, paths } from '../../config/keycloak.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import type { KeycloakToken } from '../models/dtos/kc-token.dto.js';
import type { LogInInput } from '../models/inputs/log-in.input.js';
import { toToken } from '../models/mappers/token.mapper.js';
import type { TokenPayload } from '../models/payloads/token.payload.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, UnauthorizedException } from '@nestjs/common';

/**
 * @file Mutierende Operationen gegen Keycloak (Authentication-Flows & User-Mutationen).
 *  - login/refresh/logout
 *  - signUp / update / password / delete
 *  - Attribute & Rollen
 *  - Kafka-Events bei signUp
 */
@Injectable()
export class AuthWriteService extends AuthenticateBaseService {
  constructor(logger: LoggerPlusService, trace: TraceContextProvider, http: HttpService) {
    super(logger, trace, http);
  }

  /**
   * Password-Login (ROPC).
   * @returns TokenPayload oder null (bei invalid_grant)
   */
  @Public()
  async login({ username, password }: LogInInput): Promise<TokenPayload> {
    return this.withSpan('authentication.login', async (_span) => {
      if (!username || !password) {
        throw new UnauthorizedException('username oder passwort fehlt!');
      }

      const body = new URLSearchParams({
        grant_type: 'password',
        username,
        password,
        scope: 'openid',
      });
      const data = await this.kcRequest<KeycloakToken>(
        'post',
        paths.accessToken,
        { data: body.toString(), headers: this.loginHeaders, adminAuth: false },
        { mapTo: 'null-on-401' },
      );
      if (!data) {
        throw new UnauthorizedException('username oder passwort falsch!');
      }
      return toToken(data);
    });
  }

  /**
   * Refresh-Flow.
   */
  @Public()
  async refresh(refresh_token: string | undefined): Promise<TokenPayload | null> {
    return this.withSpan('authentication.refresh', async (_span) => {
      if (!refresh_token) {
        return null;
      }

      const body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token,
      });
      const data = await this.kcRequest<KeycloakToken>(
        'post',
        paths.accessToken,
        { data: body.toString(), headers: this.loginHeaders, adminAuth: false },
        { mapTo: 'null-on-401' },
      );
      if (!data) {
        return null;
      }
      return toToken(data);
    });
  }

  /**
   * Logout (Refresh-Token invalidieren).
   */
  @Public()
  async logout(refreshToken: string | undefined): Promise<void> {
    return this.withSpan('authentication.logout', async (_span) => {
      if (!refreshToken) {
        return;
      }
      const body = new URLSearchParams({
        client_id: keycloakConfig.clientId ?? '',
        refresh_token: refreshToken,
      });
      await this.kcRequest('post', paths.logout, {
        data: body.toString(),
        headers: this.loginHeaders,
        adminAuth: false,
      });
    });
  }
}
