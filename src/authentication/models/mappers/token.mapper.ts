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

import type { KeycloakToken } from '../dtos/kc-token.dto.js';
import type { TokenPayload } from '../payloads/token.payload.js';

export function toToken(tokenPayload: KeycloakToken): TokenPayload {
  const token: TokenPayload = {
    accessToken: tokenPayload.access_token,
    expiresIn: tokenPayload.expires_in,
    refreshToken: tokenPayload.refresh_token,
    refreshExpiresIn: tokenPayload.refresh_expires_in,
    idToken: tokenPayload.id_token,
    scope: tokenPayload.scope,
  };

  return token;
}
