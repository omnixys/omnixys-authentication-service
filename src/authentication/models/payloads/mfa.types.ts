import { Field, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class TotpSetupPayload {
  @Field({ nullable: true })
  otpauth?: string;

  @Field({ nullable: true })
  secret?: string;

  @Field({ nullable: true })
  uri?: string;
}

@ObjectType()
export class WebAuthnOptionsPayload {
  @Field()
  challenge!: string;

  @Field(() => String)
  options!: string; // JSON serialized
}
