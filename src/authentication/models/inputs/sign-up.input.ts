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

import { PhoneNumberInput } from './phone-number.input.js';
import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class SignUpInput0 {
  @Field(() => String, { nullable: true })
  username!: string;

  @Field(() => String, { nullable: true })
  email!: string;

  @Field(() => String, { nullable: true })
  password!: string;

  @Field(() => String)
  firstName!: string;

  @Field(() => String)
  lastName!: string;

  @Field(() => [PhoneNumberInput], { nullable: true })
  phoneNumbers?: PhoneNumberInput[];

  @Field(() => [String], { nullable: true })
  ticketIds?: string[];

  @Field(() => [String], { nullable: true })
  invitationIds?: string[];

  @Field({ nullable: true, description: 'Sende VERIFY_EMAIL Required Action' })
  sendVerifyEmail?: boolean;

  @Field({
    nullable: true,
    description: 'Redirect nach VERIFY_EMAIL (optional)',
  })
  verifyRedirectUri?: string;

  @Field({
    nullable: true,
    description:
      'Nach erfolgreichem Signup sofort Tokens ausstellen (Server only)',
  })
  autoSignIn?: boolean;
}

@InputType()
export class SignUpInput {
  @Field(() => String, { nullable: true })
  username?: string;

  @Field(() => String, { nullable: true })
  email?: string;

  @Field(() => String, { nullable: true })
  password?: string;

  @Field(() => String)
  firstName!: string;

  @Field(() => String)
  lastName!: string;

  @Field(() => [PhoneNumberInput], { nullable: true })
  phoneNumbers?: PhoneNumberInput[];

  @Field(() => [String], { nullable: true })
  ticketIds?: string[];

  @Field(() => [String], { nullable: true })
  invitationIds?: string[];

  @Field({ nullable: true, description: 'Sende VERIFY_EMAIL Required Action' })
  sendVerifyEmail?: boolean;

  @Field({
    nullable: true,
    description: 'Redirect nach VERIFY_EMAIL (optional)',
  })
  verifyRedirectUri?: string;

  @Field({
    nullable: true,
    description:
      'Nach erfolgreichem Signup sofort Tokens ausstellen (Server only)',
  })
  autoSignIn?: boolean;
}
