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

import { paths } from '../../config/keycloak.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { KafkaProducerService } from '../../messaging/kafka-producer.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import { GuestSignUpDTO } from '../models/dtos/sign-up.dto.js';
import { updatePasswortDTO } from '../models/dtos/update-password.dto.js';
import { Role } from '../models/enums/role.enum.js';
import { GuestSignUpInput, UserSignUpInput } from '../models/inputs/sign-up.input.js';
import { SignUpPayload } from '../models/payloads/sign-in.payload.js';
import { TokenPayload } from '../models/payloads/token.payload.js';
import { AdminWriteService } from './admin-write.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { KeycloakBaseService } from './keycloak-base.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, NotFoundException } from '@nestjs/common';

/**
 * @file Mutierende Operationen gegen Keycloak (Authentication-Flows & User-Mutationen).
 *  - login/refresh/logout
 *  - signUp / update / password / delete
 *  - Attribute & Rollen
 *  - Kafka-Events bei signUp
 */
@Injectable()
export class UserWriteService extends KeycloakBaseService {
  constructor(
    logger: LoggerPlusService,
    trace: TraceContextProvider,
    http: HttpService,
    private readonly kafka: KafkaProducerService,
    private authService: AuthWriteService,
    private adminService: AdminWriteService,
  ) {
    super(logger, trace, http);
  }

  /**
   * User anlegen (mit invitationId/phoneNumber Attributen) + Rolle + Kafka-Events.
   */
  async guestSignUp(input: GuestSignUpDTO | GuestSignUpInput): Promise<SignUpPayload> {
    return this.withSpan('authentication.signUp', async (span) => {
      void this.logger.debug('signUp: input=%o', input);

      const { firstName, lastName, email, invitationId, phoneNumbers } = input;

      const {
        username,
        email: finalEmail,
        password,
      } = await this.createUsernameAndEmailAndPassword({
        firstName,
        lastName,
        email,
      });

      const credentials: Array<Record<string, string | undefined | boolean>> = [
        { type: 'password', value: password, temporary: false },
      ];

      const body = {
        username,
        enabled: true,
        firstName,
        lastName,
        email: finalEmail,
        credentials,
      };

      await this.kcRequest('post', paths.users, {
        data: body,
        headers: await this.adminJsonHeaders(),
      });

      // id ermitteln
      const userId = await this.findUserIdByUsername(username);
      if (!userId) {
        throw new NotFoundException('User id could not be resolved after signUp');
      }

      // Rolle zuweisen
      await this.adminService.assignRealmRoleToUser(userId, Role.USER);

      const sc = span.spanContext();
      void this.kafka.sendUserId(
        { id: userId, firstName, lastName, email, phoneNumbers, invitationId },
        'authentication.guestSignUp',
        { traceId: sc.traceId, spanId: sc.spanId },
      );
      // TODO kafka nachrichten implementieren
      return { userId, username, password };
    });
  }

  async userSignUp(input: UserSignUpInput): Promise<TokenPayload> {
    return this.withSpan('authentication.signUp', async (span) => {
      void this.logger.debug('signUp: input=%o', input);

      const { firstName, lastName, email, username, password, phoneNumbers } = input;

      const credentials: Array<Record<string, string | undefined | boolean>> = [
        { type: 'password', value: password, temporary: false },
      ];

      const body = {
        username,
        enabled: true,
        firstName,
        lastName,
        email,
        credentials,
      };

      await this.kcRequest('post', paths.users, {
        data: body,
        headers: await this.adminJsonHeaders(),
      });

      // id ermitteln
      const userId = await this.findUserIdByUsername(username);
      if (!userId) {
        throw new NotFoundException('User id could not be resolved after signUp');
      }

      // Rolle zuweisen
      await this.adminService.assignRealmRoleToUser(userId, Role.USER);

      const sc = span.spanContext();

      void this.kafka.sendUserId(
        { id: userId, firstName, lastName, email, phoneNumbers },
        'authentication.userSignUp',
        { traceId: sc.traceId, spanId: sc.spanId },
      );
      // TODO kafka nachrichten implementieren

      const token = await this.authService.login({ username, password });
      return token;

      // return { userId, username, password };
    });
  }

  async changePassword({
    userId,
    username,
    oldPassword,
    newPassword,
  }: updatePasswortDTO): Promise<void> {
    // 1) Old password validieren via Token-Endpoint (ROPC)
    await this.authService.login({ username, password: oldPassword });

    // 2) Neues Passwort via Admin REST setzen
    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(userId)}/reset-password`, {
      data: { type: 'password', value: newPassword, temporary: false },
      headers: await this.adminJsonHeaders(),
    });
  }

  async sendPasswordResetNotification(id: string): Promise<void> {
    throw new Error(`Method not implemented.${id}`);
  }

  /**
   * Realm-Rolle von User entfernen.
   */
  async removeRealmRoleFromUser(userId: string, roleName: Role | string): Promise<void> {
    const role = await this.getRealmRole(roleName);
    await this.kcRequest(
      'delete',
      `${paths.users}/${encodeURIComponent(userId)}/role-mappings/realm`,
      { data: [role] },
    );
  }

  // ---------- Helpers (nur für Write-Service) ----------
  private async createUsernameAndEmailAndPassword(input: {
    firstName: string;
    lastName: string;
    email?: string;
  }): Promise<{ username: string; email: string; password: string }> {
    const base = (input.lastName.slice(0, 2) + input.firstName.slice(0, 2))
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
    const suffix = Math.floor(1000 + Math.random() * 9000).toString();
    const username = `${base}${suffix}`;
    const email = input.email ?? `${username}@omnixys.com`;
    const password = Math.random().toString(36).slice(-8);
    return { username, email, password };
  }
}
