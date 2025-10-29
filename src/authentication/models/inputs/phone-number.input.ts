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

import { PhoneKind } from '../enums/phone-kind.enum.js';
import { Field, InputType } from '@nestjs/graphql';
import { IsEnum, IsOptional, IsString, Matches } from 'class-validator';

export const PHONE_RE = /^\+?[0-9 .\-()]{6,20}$/;

@InputType()
export class PhoneNumberInput {
  @Field(() => PhoneKind)
  @IsEnum(PhoneKind)
  kind!: PhoneKind;

  @Field(() => String)
  @IsString()
  @Matches(PHONE_RE, { message: 'invalid phone number format' })
  value!: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  label?: string;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  isPrimary?: boolean;
}
