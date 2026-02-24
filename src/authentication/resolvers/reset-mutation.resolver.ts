/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-argument */

import { JsonScalar } from '../../core/scalars/json.scalar.js';
import { MfaPreference } from '../models/dtos/reset-verification-result.dto.js';
import { ResetService } from '../services/resest.service.js';
import { BadRequestException } from '@nestjs/common';
import { Args, Mutation, Resolver } from '@nestjs/graphql';
import { Field, InputType, ObjectType } from '@nestjs/graphql';
import { AuthenticationResponseJSON } from '@simplewebauthn/server';

/* =======================================================
   GraphQL Types
======================================================= */

@ObjectType()
export class ResetVerificationPayload {
  @Field(() => Boolean)
  mfaRequired!: boolean;

  @Field(() => MfaPreference)
  mfaMethod!: MfaPreference;

  /**
   * Optional: you can expose a reset correlation id here if you store it.
   * For now we keep it minimal and do NOT expose internals.
   */
}

/* =======================================================
   GraphQL Inputs
======================================================= */

@InputType()
export class SecurityQuestionAnswerInput {
  @Field(() => String)
  questionId!: string;

  @Field(() => String)
  answer!: string;
}

@InputType()
export class StepUpVerificationInputGql {
  @Field(() => String)
  token!: string;

  /**
   * Used for TOTP and backup codes.
   */
  @Field(() => String, { nullable: true })
  code?: string;

  /**
   * WebAuthn client response JSON.
   * Use GraphQLJSON to avoid brittle schema coupling.
   */
  @Field(() => JsonScalar, { nullable: true })
  credentialResponse?: AuthenticationResponseJSON;

  /**
   * Security questions.
   */
  @Field(() => [SecurityQuestionAnswerInput], { nullable: true })
  answers?: SecurityQuestionAnswerInput[];
}

@InputType()
export class CompleteResetInputGql {
  @Field(() => String)
  token!: string;

  @Field(() => String)
  newPassword!: string;
}

/* =======================================================
   Resolver
======================================================= */

@Resolver()
export class ResetMutationResolver {
  constructor(private readonly resetService: ResetService) {}

  /**
   * Requests a password reset email.
   *
   * - Must not leak whether the user exists.
   * - Always returns true.
   */
  @Mutation(() => Boolean)
  async requestPasswordReset(
    @Args('email', { type: () => String }) email: string,
  ): Promise<boolean> {
    // English comment tailored for VS:
    // Always return true to avoid user enumeration.
    await this.resetService.requestReset(email, {
      ip: '0.0.0.0',
      userAgent: 'graphql',
    } as any);
    return true;
  }

  /**
   * Verifies the email token.
   * Returns whether step-up is required and which MFA method is expected.
   */
  @Mutation(() => ResetVerificationPayload)
  async verifyPasswordResetToken(
    @Args('token', { type: () => String }) token: string,
  ): Promise<ResetVerificationPayload> {
    return this.resetService.verifyResetToken(token);
  }

  /**
   * Performs step-up verification depending on user's MFA preference.
   */
  @Mutation(() => Boolean)
  async verifyPasswordResetStepUp(
    @Args('input', { type: () => StepUpVerificationInputGql })
    input: StepUpVerificationInputGql,
  ): Promise<boolean> {
    await this.resetService.verifyStepUp({
      token: input.token,
      code: input.code,
      credentialResponse: input.credentialResponse,
      answers: input.answers,
    } as any);

    return true;
  }

  /**
   * Completes reset: set password in Keycloak + invalidate sessions + invalidate reset tokens.
   */
  @Mutation(() => Boolean)
  async completePasswordReset(
    @Args('input', { type: () => CompleteResetInputGql })
    input: CompleteResetInputGql,
  ): Promise<boolean> {
    if (!input.newPassword || input.newPassword.length < 12) {
      throw new BadRequestException('Password does not meet requirements');
    }

    await this.resetService.completeReset({
      token: input.token,
      newPassword: input.newPassword,
    } as any);

    return true;
  }
}
