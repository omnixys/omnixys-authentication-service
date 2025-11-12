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

import {
  BadRequestException,
  UnauthorizedException,
  UseInterceptors,
} from '@nestjs/common';
import { Args, Context, ID, Query, Resolver } from '@nestjs/graphql';
import { Public } from 'nest-keycloak-connect';

import { getLogger } from '../../logger/get-logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';

import { KeycloakReadService } from '../services/read.service.js';
import { BadUserInputException } from '../utils/error.util.js';

import { User } from '../models/entitys/user.entity.js';
import {
  type GqlCtx,
  readAccessTokenFromCookie,
} from './authentication-mutation.resolver.js';

/**
 * @file GraphQL-Resolver für **lesende** Authentication-Abfragen (ME/USERS).
 *
 * @remarks
 * - Nutzt den {@link KeycloakReadService} für sämtliche Leseoperationen.
 * - Liest das Access-Token bevorzugt aus dem HttpOnly-Cookie `kc_access_token`,
 *   alternativ aus dem optionalen Query-Argument `token`.
 * - Öffentliche Endpunkte sind mit `@Public()` gekennzeichnet.
 * - Strikt typisiert, keine Verwendung von `any`.
 *
 * @packageDocumentation
 */

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
/**
 * Stellt Queries rund um Benutzerinformationen bereit:
 * - `users`: Liste aller Realm-User
 * - `me`: Informationen zum aktuellen Benutzer (aus Access-Token)
 * - `getById`: Benutzer per ID
 */
export class AuthQueryResolver {
  private readonly logger = getLogger(AuthQueryResolver.name);

  constructor(private readonly read: KeycloakReadService) {}

  /**
   * Liste aller Benutzer im Realm.
   *
   * @returns Array von {@link User}
   *
   * @example
   * ```graphql
   * query {
   *   users { id username email }
   * }
   * ```
   */
  @Query(() => [User], { name: 'users' })
  @Public()
  async getUsers(): Promise<User[]> {
    this.logger.debug('Get All Users');
    return this.read.findAllUsers();
  }

  /**
   * Informationsabfrage zum aktuellen Benutzer.
   *
   * @param ctx GraphQL-Kontext (enthält `req/res` zum Auslesen der Cookies)
   * @param token Optionales Access-Token (Fallback, wenn kein Cookie vorhanden ist)
   * @returns {@link User}
   *
   * @example
   * ```graphql
   * query {
   *   me { id username email }
   * }
   * ```
   */
  @Query(() => User, { name: 'meByToken' })
  @Public()
  async meByToken(
    @Context() ctx: GqlCtx,
    @Args('token', { type: () => String, nullable: true }) token?: string,
  ): Promise<User> {
    this.logger.debug('me');
    const accessFromCookie = readAccessTokenFromCookie(ctx);
    const accessToken = accessFromCookie ?? token ?? undefined;

    if (!accessToken) {
      throw new BadUserInputException('Kein Access-Token gesetzt');
    }

    const user = await this.read.getUserInfo(accessToken);
    if (!user) {
      throw new BadUserInputException('Benutzer nicht gefunden');
    }
    return user;
  }

  @Query(() => User, { name: 'me' })
  async me(@Context() ctx: GqlCtx): Promise<User> {
    this.logger.debug('me');
    const user = ctx?.req.user;

    if (!user) {
      this.logger.warn('me() aufgerufen ohne gültigen Benutzer im Kontext');
      throw new BadRequestException(
        'Ungültige Benutzeranfrage – kein User im Kontext',
      );
    }

    this.logger.debug('user=%o', user);

    if (!user?.sub) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }

    return this.read.findById(user.sub);
  }

  /**
   * Holt einen Benutzer per **ID**.
   *
   * @param id Keycloak-UUID
   * @returns {@link User}
   *
   * @example
   * ```graphql
   * query {
   *   getById(id: "0b9d...") { id username email }
   * }
   * ```
   */
  @Query(() => User, { name: 'getById' })
  @Public()
  async getById(@Args('id', { type: () => ID }) id: string): Promise<User> {
    this.logger.debug('getById: id=%s', id);
    return this.read.findById(id);
  }

  @Query(() => User, { name: 'getByUsername' })
  @Public()
  async getByUsername(
    @Args('username', { type: () => String }) username: string,
  ): Promise<User> {
    this.logger.debug('getByUsername: username=%s', username);
    return this.read.findByUsername(username);
  }
}
