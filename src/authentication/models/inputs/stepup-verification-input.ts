/* eslint-disable @typescript-eslint/no-unsafe-call */
import { Type } from 'class-transformer';
import { IsOptional, IsString, ValidateNested, IsArray } from 'class-validator';

export class SecurityQuestionAnswerDto {
  @IsString()
  questionId!: string;

  @IsString()
  answer!: string;
}

export class StepUpVerificationInput {
  @IsString()
  token!: string;

  // TOTP / Backup code
  @IsOptional()
  @IsString()
  code?: string;

  // WebAuthn (client response JSON)
  @IsOptional()
  credentialResponse?: unknown;

  // Security questions
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => SecurityQuestionAnswerDto)
  answers?: SecurityQuestionAnswerDto[];
}
