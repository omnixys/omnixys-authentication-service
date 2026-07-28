/* eslint-disable @typescript-eslint/explicit-function-return-type */
import {
  Args,
  Field,
  Mutation,
  ObjectType,
  Query,
  Resolver,
} from '@nestjs/graphql';

import { UseGuards } from '@nestjs/common';

import { JsonScalar } from '../../core/scalars/json.scalar.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import {
  AuthenticationInputException,
  AuthenticationStateException,
} from '../errors/authentication.error.js';
import { MfaPreference } from '../models/dtos/reset-verification-result.dto.js';
import { SecurityQuestionMapper } from '../models/mappers/security-question.mapper.js';
import { TotpSetupPayload } from '../models/payloads/mfa.types.js';
import { SecurityQuestionPayload } from '../models/payloads/security-question.payload.js';
import { BackupCodeService } from '../services/backup-code.service.js';
import { SecurityQuestionService } from '../services/security-question.service.js';
import { TotpService } from '../services/totp.service.js';
import { WebAuthnService } from '../services/web-authn.service.js';
import { getLogger } from '@omnixys/logger';
import {
  CookieAuthGuard,
  CurrentUser,
  CurrentUserData,
  InvalidCredentialsException,
} from '@omnixys/security';
import {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

@ObjectType()
export class WebAuthnDevicePayload {
  @Field()
  credentialId!: string;

  @Field({ nullable: true })
  nickname?: string;

  @Field()
  deviceType!: string;

  @Field()
  backedUp!: boolean;

  @Field()
  createdAt!: Date;

  @Field({ nullable: true })
  lastUsedAt?: Date;

  @Field({ nullable: true })
  revokedAt?: Date;
}

@Resolver()
export class MfaMutationResolver {
  readonly #logger = getLogger(MfaMutationResolver.name);

  constructor(
    private readonly totpService: TotpService,
    private readonly webAuthnService: WebAuthnService,
    private readonly backupCodeService: BackupCodeService,
    private readonly prisma: PrismaService,
    private readonly securityQuestionService: SecurityQuestionService,
  ) {}

  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean)
  async setMfaPreference(
    @CurrentUser() user: CurrentUserData,
    @Args('method', { type: () => MfaPreference })
    method: MfaPreference,
  ): Promise<boolean> {
    await this.prisma.authUser.update({
      where: { id: user.id },
      data: { mfaPreference: method },
    });

    return true;
  }

  @UseGuards(CookieAuthGuard)
  @Query(() => [WebAuthnDevicePayload])
  async listWebAuthnDevices(@CurrentUser() currentUser: CurrentUserData) {
    // : Promise<WebAuthnDevicePayload[]>
    const userId = currentUser.id;

    return this.webAuthnService.listDevices(userId);
  }

  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean)
  async revokeWebAuthnCredential(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('credentialId') credentialId: string,
  ): Promise<boolean> {
    const userId = currentUser.id;

    if (!credentialId) {
      throw new AuthenticationInputException('credential-id-missing');
    }

    const ok = await this.webAuthnService.revokeDevice(userId, credentialId);

    if (!ok) {
      this.#logger.warn({ userId, credentialId }, 'webauthn_revoke_not_found');
      throw new AuthenticationStateException(
        'webauthn-device-not-found-or-revoked',
      );
    }

    this.#logger.debug({ userId, credentialId }, 'webauthn_credential_revoked');
    return true;
  }

  /* =======================================================
     TOTP
  ======================================================= */

  @UseGuards(CookieAuthGuard)
  @Mutation(() => TotpSetupPayload)
  async enableTotp(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<TotpSetupPayload> {
    const userId = currentUser.id;
    const email = currentUser.email;

    this.#logger.debug({ userId }, 'totp_setup_started');
    return this.totpService.generateForUser(userId, email);
  }

  @UseGuards(CookieAuthGuard)
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

  @UseGuards(CookieAuthGuard)
  @Mutation(() => JsonScalar)
  async generateWebAuthnRegistrationOptions(
    @CurrentUser() currentUser: CurrentUserData,
  ) {
    const userId = currentUser.id;
    const email = currentUser.email;

    const options = await this.webAuthnService.generateOptions(userId, email);

    return options;
  }

  @UseGuards(CookieAuthGuard)
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
     WEBAUTHN AUTHENTICATION (Step-up / Login verification)
  ======================================================= */

  @UseGuards(CookieAuthGuard)
  @Mutation(() => JsonScalar, { name: 'generateWebAuthnAuthOptions2' })
  async generateWebAuthnAuthOptions(
    @CurrentUser() currentUser: CurrentUserData,
  ) {
    const userId = currentUser.id;

    // Generates challenge + allowCredentials and stores challenge in Valkey (inside service).
    return this.webAuthnService.generateAuthOptions(userId);
  }

  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean, { name: 'verifyWebAuthnAuthentication2' })
  async verifyWebAuthnAuthentication(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('response', { type: () => JsonScalar }) response: unknown,
  ): Promise<boolean> {
    const userId = currentUser.id;

    if (!response || typeof response !== 'object') {
      this.#logger.warn({ userId }, 'webauthn_response_invalid');
      throw new AuthenticationInputException('webauthn-response-invalid');
    }

    const ok = await this.webAuthnService.verifyAuthenticationForUser(
      userId,
      response as AuthenticationResponseJSON,
    );

    if (!ok) {
      this.#logger.warn({ userId }, 'webauthn_auth_failed');
      throw new InvalidCredentialsException('WebAuthn verification failed');
    }

    this.#logger.debug({ userId }, 'webauthn_auth_success');
    return true;
  }

  /* =======================================================
     BACKUP CODES
  ======================================================= */

  @UseGuards(CookieAuthGuard)
  @Mutation(() => [String])
  async regenerateBackupCodes(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<string[]> {
    const userId = currentUser.id;

    this.#logger.debug({ userId }, 'backup_codes_regenerated');
    return this.backupCodeService.generate(userId);
  }

  /* =====================================================
   DEVICE RENAME
===================================================== */
  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean)
  async renameWebAuthnCredential(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('credentialId') credentialId: string,
    @Args('nickname') nickname: string,
  ): Promise<boolean> {
    const ok = await this.webAuthnService.renameDevice(
      currentUser.id,
      credentialId,
      nickname,
    );

    if (!ok) {
      this.#logger.warn(
        {
          userId: currentUser.id,
          credentialId,
        },
        'webauthn_rename_failed',
      );
      throw new AuthenticationInputException('webauthn-device-rename-failed');
    }

    this.#logger.debug(
      {
        userId: currentUser.id,
        credentialId,
        nickname,
      },
      'webauthn_device_renamed',
    );
    return true;
  }

  @Query(() => [SecurityQuestionPayload])
  async getSecurityQuestions(): Promise<SecurityQuestionPayload[]> {
    const securityQuestions =
      await this.securityQuestionService.getAllQuestions();
    return securityQuestions
      ? SecurityQuestionMapper.toPayloadList(securityQuestions)
      : [];
  }
}
