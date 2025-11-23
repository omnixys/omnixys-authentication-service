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

import { Field, ID, InputType } from '@nestjs/graphql';

@InputType()
export class UpdateKcUserInput {
  @Field(() => String, { nullable: true })
  firstName?: string;

  @Field(() => String, { nullable: true })
  lastName?: string;

  @Field(() => String, { nullable: true })
  email?: string;

  // Passwort separat hier mit drin – wird über reset-password gesetzt
  @Field(() => String, { nullable: true })
  password?: string;
}

@InputType()
export class UpdateUserPasswordInput {
  @Field(() => ID, { nullable: true })
  id!: string;

  @Field(() => String, { nullable: true })
  newPassword!: string;
}
