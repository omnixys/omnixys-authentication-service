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
import { Args, ID, Mutation, Resolver } from '@nestjs/graphql';
import { Public } from 'nest-keycloak-connect';

import { getLogger } from '../../logger/logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';

import { Role } from '../models/enums/role.enum.js';
import {
  UpdateUserInput,
  UpdateUserPasswordInput,
} from '../models/inputs/update-user.input.js';
import { AdminWriteService } from '../services/admin-write.service.js';

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class AdminMutationResolver {
  private readonly logger = getLogger(AdminMutationResolver.name);

  constructor(private readonly adminService: AdminWriteService) {}

  // --------- User-Management ---------

  /**
   * Profilfelder aktualisieren (firstName/lastName/email).
   */
  @Mutation(() => Boolean, { name: 'adminUpdateUser' })
  @Public()
  async updateUser(
    @Args('id', { type: () => ID }) id: string,
    @Args('input', { type: () => UpdateUserInput }) input: UpdateUserInput,
  ): Promise<boolean> {
    this.logger.debug('');
    await this.adminService.updateUser(id, input);
    return true;
  }

  /**
   * Passwort setzen (nicht temporär).
   */
  @Mutation(() => Boolean, { name: 'adminChangePassword' })
  @Public()
  async changeUserPassword(
    @Args('input', { type: () => UpdateUserPasswordInput })
    input: UpdateUserPasswordInput,
  ): Promise<boolean> {
    await this.adminService.setUserPassword(input.id, input.newPassword);
    return true;
  }

  /**
   * Benutzer löschen.
   */
  @Mutation(() => Boolean, { name: 'deleteUser' })
  @Public()
  async deleteUser(
    @Args('id', { type: () => ID }) id: string,
  ): Promise<boolean> {
    await this.adminService.deleteUser(id);
    return true;
  }

  // --------- Rollen-Management ---------

  /**
   * Realm-Rolle einem Benutzer zuweisen.
   */
  @Mutation(() => Boolean, { name: 'assignRealmRole' })
  async assignRealmRole(
    @Args('id', { type: () => ID }) id: string,
    @Args('roleName', { type: () => Role }) roleName: Role,
  ): Promise<boolean> {
    this.logger.debug('assignRealmRole: roleName=%s', roleName);
    await this.adminService.assignRealmRoleToUser(id, roleName);
    return true;
  }

  /**
   * Realm-Rolle von einem Benutzer entfernen.
   */
  @Mutation(() => Boolean, { name: 'removeRealmRole' })
  async removeRealmRole(
    @Args('id', { type: () => ID }) id: string,
    @Args('roleName', { type: () => Role }) roleName: Role,
  ): Promise<boolean> {
    await this.adminService.removeRealmRoleFromUser(id, roleName);
    return true;
  }
}
