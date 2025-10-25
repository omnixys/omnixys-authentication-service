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

// TODO eslint kommentare lösen
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
// /backend/auth/src/auth/resolvers/auth.mutation.resolver.ts
import { getLogger } from '../../logger/logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { ChangeMyPasswordInput } from '../models/inputs/update-password.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import { SuccessPayload } from '../models/payloads/success.payload.js';
import { AdminWriteService } from '../services/admin-write.service.js';
import { UserWriteService } from '../services/user-write.service.js';
import { GqlCtx } from './auth-mutation.resolver.js';
import { UnauthorizedException, UseInterceptors } from '@nestjs/common';
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

    const username = user?.username ?? '';
    this.logger.debug('changeMyPassword: sub=%s', user?.sub);

    this.logger.debug('changeMyPassword: user=%o', user);

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
    this.logger.debug(`user=%o${user}`);

    if (!user?.sub) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }
    await this.userService.sendPasswordResetNotification(user.sub);
    return { ok: true };
  }

  @Mutation(() => SuccessPayload)
  async updateMyProfile(
    @Args('input') input: UpdateMyProfileInput,
    @Context() ctx: GqlCtx,
  ) {
    const user = ctx?.req.user;

    if (!user?.sub) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }

    await this.adminService.updateUser(user.sub, input);
    return { ok: true, message: 'Profile updated' };
  }
}
