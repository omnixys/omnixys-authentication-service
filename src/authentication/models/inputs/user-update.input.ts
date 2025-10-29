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

import { Role } from '../enums/role.enum.js';
import { PhoneNumberInput } from './phone-number.input.js';
import { Field, ID, InputType } from '@nestjs/graphql';

@InputType()
export class UpdateMyProfileInput {
  @Field({ nullable: true })
  username?: string;

  @Field({ nullable: true })
  firstName?: string;

  @Field({ nullable: true })
  lastName?: string;

  @Field({ nullable: true })
  email?: string;

  // Strukturierte Phones (werden in KC-Attribute gemappt)
  @Field(() => [PhoneNumberInput], { nullable: true })
  phoneNumbers?: PhoneNumberInput[];

  // Optional: explizite Single-Phones überschreiben
  @Field({ nullable: true })
  privatePhone?: string;

  @Field({ nullable: true })
  workPhone?: string;

  @Field({ nullable: true })
  whatsappPhone?: string;

  // Tickets / Invitations inkrementell pflegen
  @Field(() => [String], { nullable: true })
  addTicketIds?: string[];

  @Field(() => [String], { nullable: true })
  removeTicketIds?: string[];

  @Field(() => [String], { nullable: true })
  addInvitationIds?: string[];

  @Field(() => [String], { nullable: true })
  removeInvitationIds?: string[];
}

@InputType()
export class AdminUpdateUserInput extends UpdateMyProfileInput {
  @Field(() => ID)
  userId!: string;

  @Field(() => Role)
  role?: string;
}
