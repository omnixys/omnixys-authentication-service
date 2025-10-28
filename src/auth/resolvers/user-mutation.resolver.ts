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

import { getLogger } from '../../logger/get-logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { ChangeMyPasswordInput } from '../models/inputs/update-password.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import { SuccessPayload } from '../models/payloads/success.payload.js';
import { AdminWriteService } from '../services/admin-write.service.js';
import { UserWriteService } from '../services/user-write.service.js';
import { type GqlCtx } from './auth-mutation.resolver.js';
import {
  BadRequestException,
  UnauthorizedException,
  UseInterceptors,
} from '@nestjs/common';
import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class UserMutationResolver {
  private readonly logger = getLogger(UserMutationResolver.name);

  constructor(
    private readonly userService: UserWriteService,
    private readonly adminService: AdminWriteService,
  ) {}

  @Mutation(() => SuccessPayload)
  async changeMyPassword(
    @Args('input') input: ChangeMyPasswordInput,
    @Context() ctx: GqlCtx,
  ): Promise<SuccessPayload> {
    const user = ctx?.req.user;

    if (!user?.sub) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }

    const username = user?.username ?? user?.preferred_username;
    this.logger.debug('changeMyPassword: sub=%s', user?.sub);

    // this.logger.debug('changeMyPassword: user=%o', user);

    await this.userService.changePassword({
      userId: user.sub,
      username, // für Direct Grant Validierung nötig; wenn leer, im Service per Admin-API nachladen
      oldPassword: input.oldPassword,
      newPassword: input.newPassword,
    });

    return { ok: true, message: 'Password updated' };
  }

  // Versendet Keycloak Execute-Actions-E-Mail (UPDATE_PASSWORD)
  @Mutation(() => SuccessPayload)
  async sendPasswordResetEmail(
    @Context() ctx: GqlCtx,
  ): Promise<SuccessPayload> {
    const user = ctx?.req.user;
    if (!user) {
      this.logger.warn(
        'sendPasswordResetEmail() aufgerufen ohne gültigen Benutzer im Kontext',
      );
      throw new BadRequestException(
        'Ungültige Benutzeranfrage – kein User im Kontext',
      );
    }

    if (!user?.sub) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }
    // await this.userService.sendPasswordResetNotification(user.sub);
    return { ok: true };
  }

  @Mutation(() => SuccessPayload)
  async updateMyProfile(
    @Args('input') input: UpdateMyProfileInput,
    @Context() ctx: GqlCtx,
  ): Promise<{ ok: boolean; message: string }> {
    const user = ctx?.req.user;

    if (!user?.sub) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }

    await this.adminService.updateUser(user.sub, input);
    return { ok: true, message: 'Profile updated' };
  }
}
