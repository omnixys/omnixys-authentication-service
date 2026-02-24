/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Resolver, Mutation, Args } from '@nestjs/graphql';

import { BadRequestException, UnauthorizedException, UseGuards, UseInterceptors } from '@nestjs/common';

import { BackupCodeService } from '../services/backup-code.service.js';
import { TotpService } from '../services/totp.service.js';
import { WebAuthnService } from '../services/web-authn.service.js';

import {
  CurrentUser,
  CurrentUserData,
} from '../../auth/decorators/current-user.decorator.js';
import { CookieAuthGuard } from '../../auth/guards/cookie-auth.guard.js';
import { JsonScalar } from '../../core/scalars/json.scalar.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { TotpSetupPayload } from '../models/payloads/mfa.types.js';
import { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

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

  @Mutation(() => JsonScalar)
  async generateWebAuthnRegistrationOptions(
    @CurrentUser() currentUser: CurrentUserData,
  ) {
    const userId = currentUser.id;
    const email = currentUser.email;

    const options = await this.webAuthnService.generateOptions(userId, email);

    return options;
  }

  @Mutation(() => Boolean)
  async verifyWebAuthnRegistration(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('response') response: JsonScalar,
  ): Promise<boolean> {
    const userId = currentUser.id;

    return this.webAuthnService.verifyRegistration(
      userId,
      response as unknown as RegistrationResponseJSON,
    );
  }

  /* =======================================================
     BACKUP CODES
  ======================================================= */

  /* =======================================================
     WEBAUTHN AUTHENTICATION (Step-up / Login verification)
  ======================================================= */

  @Mutation(() => JsonScalar)
  async generateWebAuthnAuthOptions(
    @CurrentUser() currentUser: CurrentUserData,
  ) {
    const userId = currentUser.id;

    // Generates challenge + allowCredentials and stores challenge in Valkey (inside service).
    return this.webAuthnService.generateAuthOptions(userId);
  }

  @Mutation(() => Boolean)
  async verifyWebAuthnAuthentication(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('response', { type: () => JsonScalar }) response: unknown,
  ): Promise<boolean> {
    const userId = currentUser.id;

    if (!response || typeof response !== 'object') {
      throw new BadRequestException('Invalid WebAuthn response');
    }

    const challenge =
      await this.webAuthnService.getAuthenticationChallenge(userId);
    if (!challenge) {
      // English comment tailored for VS:
      // Missing challenge usually means it expired or was already consumed.
      throw new UnauthorizedException('WebAuthn challenge expired');
    }

    const ok = await this.webAuthnService.verifyAuthenticationForUser(
      userId,
      response as AuthenticationResponseJSON,
      challenge,
    );

    if (!ok) {
      throw new UnauthorizedException('WebAuthn verification failed');
    }

    await this.webAuthnService.consumeAuthenticationChallenge(userId);

    return true;
  }

  @Mutation(() => [String])
  async regenerateBackupCodes(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<string[]> {
    const userId = currentUser.id;

    return this.backupCodeService.generate(userId);
  }
}
