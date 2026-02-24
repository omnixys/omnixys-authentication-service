/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Resolver, Mutation, Args } from '@nestjs/graphql';

import { UseGuards, UseInterceptors } from '@nestjs/common';

import { BackupCodeService } from '../services/backup-code.service.js';
import { TotpService } from '../services/totp.service.js';
import { WebAuthnService } from '../services/web-authn.service.js';

import {
  CurrentUser,
  CurrentUserData,
} from '../../auth/decorators/current-user.decorator.js';
import { CookieAuthGuard } from '../../auth/guards/cookie-auth.guard.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { TotpSetupPayload } from '../models/payloads/mfa.types.js';

@Resolver()
@UseGuards(CookieAuthGuard)
@UseInterceptors(ResponseTimeInterceptor)
export class MfaMutationResolver {
  constructor(
    private readonly totpService: TotpService,
    private readonly webAuthnService: WebAuthnService,
    private readonly backupCodeService: BackupCodeService,
  ) {}

  // @Mutation(() => Boolean)
  // async setMfaPreference(
  //   @CurrentUser() currentUser: CurrentUserData,
  //   @Args('method') method: string,
  // ): Promise<boolean> {
  //  const userId = currentUser.id;

  //   await this.prisma.authUser.update({
  //     where: { id: userId },
  //     data: { mfaPreference: method },
  //   });

  //   return true;
  // }

  /* =======================================================
     TOTP
  ======================================================= */

  @Mutation(() => TotpSetupPayload)
  async enableTotp(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<TotpSetupPayload> {
    const userId = currentUser.id;
    const email = currentUser.email;

    return this.totpService.generateForUser(userId, email);
  }

  @Mutation(() => Boolean)
  async confirmTotp(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('code') code: string,
  ): Promise<boolean> {
    const userId = currentUser.id;

    return this.totpService.enable(userId, code);
  }

  /* =======================================================
     WEBAUTHN REGISTRATION
  ======================================================= */

  @Mutation(() => String)
  async generateWebAuthnRegistrationOptions(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<string> {
    const userId = currentUser.id;
    const email = currentUser.email;

    const options = await this.webAuthnService.generateOptions(userId, email);

    return JSON.stringify(options);
  }

  @Mutation(() => Boolean)
  async verifyWebAuthnRegistration(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('response') response: string,
  ): Promise<boolean> {
    const userId = currentUser.id;

    return this.webAuthnService.verifyRegistration(
      userId,
      JSON.parse(response),
    );
  }

  /* =======================================================
     BACKUP CODES
  ======================================================= */

  @Mutation(() => [String])
  async regenerateBackupCodes(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<string[]> {
    const userId = currentUser.id;

    return this.backupCodeService.generate(userId);
  }
}
