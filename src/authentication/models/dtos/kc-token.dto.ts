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

import type * as jose from 'jose';

export type KeycloakTokenPayload = jose.JWTPayload & {
  sub?: string;
  username: string;
  first_name?: string;
  last_name?: string;
  email: string;
  email_verified?: boolean;
  realm_access?: { roles?: string[] };
  iss?: string; // issuer
  azp?: string; // authorized party (client)
};

export interface KeycloakToken {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  refresh_expires_in: number;
  id_token: string;
  scope: string;
}
