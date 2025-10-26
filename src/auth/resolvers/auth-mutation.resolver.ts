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

// /backend/auth/src/auth/resolvers/auth.mutation.resolver.ts
import { UseInterceptors } from '@nestjs/common';
import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';
import type { CookieOptions, Request, Response } from 'express';
import { Public } from 'nest-keycloak-connect';

import { getLogger } from '../../logger/logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';

import { KeycloakTokenPayload } from '../models/dtos/kc-token.dto.js';
import { LogInInput } from '../models/inputs/log-in.input.js';
import { SignUpInput0 } from '../models/inputs/sign-up.input.js';
import { SuccessPayload } from '../models/payloads/success.payload.js';
import { TokenPayload } from '../models/payloads/token.payload.js';
import { AdminWriteService } from '../services/admin-write.service.js';
import { AuthWriteService } from '../services/auth-write.service.js';
import { BadUserInputError } from '../utils/error.util.js';

// ---------- Context-Typ (falls noch nicht vorhanden) ----------
/** GraphQL-Kontext (HTTP Request/Response) */
export interface GqlCtx {
  req: Request & {
    cookies?: Record<string, string | undefined>;
    user?: KeycloakTokenPayload;
  };
  res: Response;
}

export interface CookieReq {
  cookies: {
    kc_access_token: string;
    kc_refresh_token: string;
  };
}

/** Liest den `kc_access_token` Cookie sicher und typisiert aus. */
export function readAccessTokenFromCookie(ctx: GqlCtx): string | undefined {
  if (!ctx.req) {
    return undefined;
  }
  const cookieReq: CookieReq = ctx.req;
  const value = cookieReq.cookies?.kc_access_token;
  return typeof value === 'string' ? value : undefined;
}

/**
 * @file GraphQL-Resolver für **schreibende** Auth-Operationen.
 *
 * @remarks
 * Enthält:
 * - `login`, `refresh`, `logout`
 * - `signIn` (User anlegen + Events)
 * - `updateUser`, `setUserPassword`, `deleteUser`
 * - `assignRealmRole`, `removeRealmRole`
 *
 * Setzt/aktualisiert HttpOnly-Cookies:
 *  - `kc_access_token`
 *  - `kc_refresh_token`
 *
 * Alle Endpunkte sind hier mit `@Public()` markiert. In Produktion
 * solltest du die Mutationen nach Bedarf mit Rollen absichern.
 */

const cookieOpts = (maxAgeMs?: number): CookieOptions => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'lax' : 'lax',
  path: '/',
  maxAge: maxAgeMs ?? undefined, // ms
});

function setCookieSafe(
  res: Response | undefined,
  name: string,
  value: string,
  opts: CookieOptions,
): void {
  if (!res) {
    return;
  }
  res.cookie(name, value, opts);
}

function clearCookieSafe(res: Response | undefined, name: string): void {
  if (!res) {
    return;
  }
  // Beim Löschen maxAge undefined lassen, sonst wird ein neues Cookie gesetzt
  res.clearCookie(name, cookieOpts(undefined));
}

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class AuthMutationResolver {
  private readonly logger = getLogger(AuthMutationResolver.name);

  constructor(
    private readonly authService: AuthWriteService,
    private readonly adminService: AdminWriteService,
  ) {}

  /**
   * Passwort-Login (ROPC). Setzt `kc_access_token` & `kc_refresh_token` als
   * HttpOnly-Cookies und gibt das Token-Payload zurück.
   */
  @Mutation(() => TokenPayload, { name: 'login' })
  @Public()
  async login(
    @Args('input', { type: () => LogInInput }) input: LogInInput,
    @Context() ctx: GqlCtx,
  ): Promise<TokenPayload> {
    this.logger.debug('login: input=%o', input);

    const { username, password } = input;
    this.logger.debug('login: username=%s', username);

    const result = await this.authService.login({ username, password });
    if (!result) {
      throw new BadUserInputError(
        'Falscher Benutzername oder falsches Passwort',
      );
    }

    setCookieSafe(
      ctx?.res,
      'kc_access_token',
      result.accessToken,
      cookieOpts(result.expiresIn * 1000),
    );
    setCookieSafe(
      ctx?.res,
      'kc_refresh_token',
      result.refreshToken,
      cookieOpts(result.refreshExpiresIn * 1000),
    );
    return result;
  }

  /**
   * Erneuert Tokens per `refreshToken`. Wenn kein Argument übergeben wird,
   * wird automatisch der `kc_refresh_token`-Cookie verwendet (falls vorhanden).
   * Setzt die Cookies erneut.
   */
  @Mutation(() => TokenPayload, { name: 'refresh' })
  @Public()
  async refresh(
    @Args('refreshToken', { type: () => String, nullable: true })
    refreshToken: string | null,
    @Context() ctx: GqlCtx,
  ): Promise<TokenPayload> {
    const cookieReq: CookieReq = ctx.req;
    const value = cookieReq.cookies?.kc_refresh_token;
    const token: string = refreshToken ?? value;

    const result = await this.authService.refresh(token);
    if (!result) {
      throw new BadUserInputError('Falscher oder abgelaufener Refresh-Token');
    }

    setCookieSafe(
      ctx?.res,
      'kc_access_token',
      result.accessToken,
      cookieOpts(result.expiresIn * 1000),
    );
    setCookieSafe(
      ctx?.res,
      'kc_refresh_token',
      result.refreshToken,
      cookieOpts(result.refreshExpiresIn * 1000),
    );
    return result;
  }

  /**
   * Logout: invalidiert den Refresh-Token bei Keycloak und leert die Cookies.
   */
  @Mutation(() => SuccessPayload, { name: 'logout' })
  @Public()
  async logout(@Context() ctx: GqlCtx): Promise<SuccessPayload> {
    const cookieReq: CookieReq = ctx.req;
    const value = cookieReq.cookies?.kc_refresh_token;
    const refreshToken = value;
    await this.authService.logout(refreshToken);

    clearCookieSafe(ctx?.res, 'kc_access_token');
    clearCookieSafe(ctx?.res, 'kc_refresh_token');

    return { ok: true, message: 'erfolgreich abgemeldet' };
  }

  /**
   * User anlegen (Sign-In/Onboarding).
   * - Erzeugt Username/Passwort
   * - Setzt invitationId/phoneNumber als Attribute (append)
   * - Weist Realm-Rolle `GUEST` zu
   * - Sendet Kafka-Events (addUser, sendUserCredentials)
   */
  // @Mutation(() => SignUpPayload, { name: 'guestSignUp' })
  // @Public()
  // async guestSignIn(
  //   @Args('input', { type: () => SignUpInput }) input: SignUpInput,
  // ): Promise<SignUpPayload> {
  //   this.logger.debug('signIn: input=%o', input);
  //   const result = await this.userService.signUp(input);
  //   if (!result) {
  //     throw new BadUserInputError('User konnte nicht angelegt werden');
  //   }
  //   // Shape entspricht SignInPayload { userId, username, password }
  //   return result;
  // }

  @Mutation(() => TokenPayload, { name: 'adminSignUp' })
  @Public()
  async adminSignIn(
    @Args('input', { type: () => SignUpInput0 }) input: SignUpInput0,
    @Context() ctx: GqlCtx,
  ): Promise<TokenPayload> {
    this.logger.debug('signIn: input=%o', input);
    const result = await this.adminService.signUp(input);

    setCookieSafe(
      ctx?.res,
      'kc_access_token',
      result.accessToken,
      cookieOpts(result.expiresIn * 1000),
    );
    setCookieSafe(
      ctx?.res,
      'kc_refresh_token',
      result.refreshToken,
      cookieOpts(result.refreshExpiresIn * 1000),
    );
    return result;
  }
}
