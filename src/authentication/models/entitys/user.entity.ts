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
import { PhoneNumber } from './phone-number.entity.js';
import { Field, ID, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class User {
  @Field(() => ID)
  id!: string;

  @Field(() => String)
  username!: string;

  @Field(() => String)
  firstName!: string;

  @Field(() => String)
  lastName!: string;

  @Field(() => String)
  email!: string;

  @Field(() => [PhoneNumber], { nullable: true })
  phoneNumbers?: PhoneNumber[];

  @Field(() => [String], { nullable: true })
  ticketIds?: string[];

  @Field(() => [String])
  invitationIds!: string[];

  @Field(() => [Role])
  roles!: Role[];

  @Field(() => [String], { nullable: true })
  eventIds?: string[];
}
