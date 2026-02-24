import { Field, ObjectType, registerEnumType } from '@nestjs/graphql';

export enum MfaPreference {
  NONE = 'NONE',
  TOTP = 'TOTP',
  WEBAUTHN = 'WEBAUTHN',
  BACKUP_CODES = 'BACKUP_CODES',
  SECURITY_QUESTIONS = 'SECURITY_QUESTIONS',
}

registerEnumType(MfaPreference, { name: 'MfaPreference' });

@ObjectType()
export class ResetVerificationResult {
  @Field(() => Boolean)
  mfaRequired!: boolean;

  @Field(() => MfaPreference)
  mfaMethod!: MfaPreference;

  /**
   * Opaque identifier for the reset flow (not the token itself).
   * Use this in subsequent step-up and complete calls.
   */
  @Field(() => String)
  resetId!: string;
}
