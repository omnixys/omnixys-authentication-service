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

import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class ChangeMyPasswordInput {
  @Field()
  oldPassword!: string;

  @Field()
  newPassword!: string;
}

@InputType()
export class PasswordResetEmailInput {
  @Field({ nullable: true })
  userId?: string;

  @Field({ nullable: true })
  email?: string; // Wenn userId fehlt, per E-Mail suchen

  @Field({ nullable: true })
  redirectUri?: string; // Optionaler Redirect nach erfolgreichem Update
}
