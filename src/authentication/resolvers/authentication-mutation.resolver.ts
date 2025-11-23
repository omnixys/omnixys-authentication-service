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

import { env } from '../../config/env.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { KeycloakTokenPayload } from '../models/dtos/kc-token.dto.js';
import { LogInInput } from '../models/inputs/log-in.input.js';
import { SuccessPayload } from '../models/payloads/success.payload.js';
import { TokenPayload } from '../models/payloads/token.payload.js';
import { AuthWriteService } from '../services/authentication-write.service.js';
import { BadUserInputException } from '../utils/error.util.js';
import { UseInterceptors } from '@nestjs/common';
import { Args, Context, ID, Mutation, Resolver } from '@nestjs/graphql';
import type { CookieOptions, Request, Response } from 'express';

/**
 * Represents the standard GraphQL execution context used by resolvers.
 * Provides access to both the incoming HTTP request and outgoing response.
 */
export interface GqlCtx {
  req: Request & {
    cookies?: Record<string, string | undefined>;
    user?: KeycloakTokenPayload;
  };
  res: Response;
}

/**
 * Express request type containing Keycloak cookies.
 */
export interface CookieReq {
  cookies: {
    kc_access_token: string;
    kc_refresh_token: string;
  };
}

/**
 * Safely reads and returns the `kc_access_token` cookie from the GraphQL context.
 *
 * @param ctx - The current GraphQL context
 * @returns The access token string if available; otherwise, `undefined`
 */
export function readAccessTokenFromCookie(ctx: GqlCtx): string | undefined {
  if (!ctx.req) {
    return undefined;
  }
  const cookieReq: CookieReq = ctx.req;
  const value = cookieReq.cookies?.kc_access_token;
  return typeof value === 'string' ? value : undefined;
}

/**
 * @fileoverview
 * GraphQL resolver handling **authentication write operations**.
 *
 * @remarks
 * Includes mutations for:
 * - `login`, `refresh`, `logout`
 * - `adminSignUp`
 * - (commented: `guestSignIn`)
 *
 * Automatically sets and updates the following HTTP-only cookies:
 *  - `kc_access_token`
 *  - `kc_refresh_token`
 *
 * All mutations are marked as `@Public()`. In production, access should
 * be restricted based on user roles and Keycloak policies.
 */

const { NODE_ENV } = env;

/**
 * Creates a configured set of cookie options based on the runtime environment.
 *
 * @param maxAgeMs - The cookie lifetime in milliseconds.
 * @returns Express-compatible {@link CookieOptions}.
 */
export const cookieOpts = (maxAgeMs?: number): CookieOptions => ({
  httpOnly: true,
  secure: NODE_ENV === 'production',
  sameSite: NODE_ENV === 'production' ? 'lax' : 'lax',
  path: '/',
  maxAge: maxAgeMs ?? undefined,
});

/**
 * Safely sets a cookie on the response if available.
 *
 * @param res - Express response object.
 * @param name - The cookie name.
 * @param value - The cookie value.
 * @param opts - Additional cookie options.
 */
export function setCookieSafe(
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

/**
 * Safely clears a cookie from the response if available.
 *
 * @param res - Express response object.
 * @param name - The cookie name to remove.
 */
function clearCookieSafe(res: Response | undefined, name: string): void {
  if (!res) {
    return;
  }
  res.clearCookie(name, cookieOpts(undefined));
}

/**
 * GraphQL resolver providing mutation endpoints for user authentication.
 *
 * @public
 */
@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class AuthMutationResolver {
  private readonly logger;

  /**
   * Constructs an {@link AuthMutationResolver} instance.
   *
   * @param loggerService - Provides structured logging utilities.
   * @param authService - Handles authentication and token operations.
   * @param adminService - Handles administrative user management.
   */
  constructor(
    private readonly loggerService: LoggerPlusService,
    private readonly authService: AuthWriteService,
  ) {
    this.logger = this.loggerService.getLogger(AuthMutationResolver.name);
  }

  /**
   * Performs a password-based login (ROPC flow).
   *
   * @remarks
   * - Sets `kc_access_token` and `kc_refresh_token` as HttpOnly cookies.
   * - Returns a {@link TokenPayload} object containing both tokens.
   *
   * @param input - User credentials (`username`, `password`).
   * @param ctx - GraphQL context containing HTTP request/response.
   * @returns {@link TokenPayload} containing access and refresh tokens.
   * @throws {@link BadUserInputError} If credentials are invalid.
   */
  @Mutation(() => TokenPayload, { name: 'login' })
  async login(
    @Args('input', { type: () => LogInInput }) input: LogInInput,
    @Context() ctx: GqlCtx,
  ): Promise<TokenPayload> {
    this.logger.debug('login: input=%o', input);
    const { username, password } = input;

    const result = await this.authService.login({ username, password });
    if (!result) {
      throw new BadUserInputException('Invalid username or password.');
    }

    setCookieSafe(
      ctx?.res,
      'access_token',
      result.accessToken,
      cookieOpts(result.expiresIn * 1000),
    );
    setCookieSafe(
      ctx?.res,
      'refresh_token',
      result.refreshToken,
      cookieOpts(result.refreshExpiresIn * 1000),
    );
    return result;
  }

  /**
   * Refreshes authentication tokens using a valid refresh token.
   *
   * @remarks
   * If no explicit token is passed as argument, this method automatically
   * uses the `kc_refresh_token` cookie (if available).
   *
   * @param refreshToken - Optional token string to refresh manually.
   * @param ctx - GraphQL context containing cookies and response.
   * @returns A refreshed {@link TokenPayload}.
   * @throws {@link BadUserInputError} If the refresh token is invalid or expired.
   */
  @Mutation(() => TokenPayload, { name: 'refresh' })
  async refresh(
    @Args('refreshToken', { type: () => ID })
    refreshToken: string,
    @Context() ctx: GqlCtx,
  ): Promise<TokenPayload> {
    const cookieReq: CookieReq = ctx.req;
    const cookieValue = cookieReq.cookies?.kc_refresh_token;
    const token: string = refreshToken ?? cookieValue;

    const result = await this.authService.refresh(token);
    if (!result) {
      throw new BadUserInputException('Invalid or expired refresh token.');
    }

    setCookieSafe(
      ctx?.res,
      'access_token',
      result.accessToken,
      cookieOpts(result.expiresIn * 1000),
    );
    setCookieSafe(
      ctx?.res,
      'refresh_token',
      result.refreshToken,
      cookieOpts(result.refreshExpiresIn * 1000),
    );
    return result;
  }

  /**
   * Logs out a user by invalidating their refresh token
   * and clearing all authentication cookies.
   *
   * @param ctx - GraphQL context containing the HTTP response.
   * @returns {@link SuccessPayload} indicating operation status.
   */
  @Mutation(() => SuccessPayload, { name: 'logout' })
  async logout(@Context() ctx: GqlCtx): Promise<SuccessPayload> {
    const cookieReq: CookieReq = ctx.req;
    const value = cookieReq.cookies?.kc_refresh_token;
    await this.authService.logout(value);

    clearCookieSafe(ctx?.res, 'access_token');
    clearCookieSafe(ctx?.res, 'refresh_token');

    return { ok: true, message: 'Successfully logged out.' };
  }
}
