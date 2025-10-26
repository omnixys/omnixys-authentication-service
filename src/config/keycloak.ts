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

import { env } from './env.js';
import { httpsOptions } from './https.js';
import {
  type KeycloakConnectConfig,
  PolicyEnforcementMode,
  TokenValidation,
} from 'nest-keycloak-connect';
import { Agent } from 'node:https';

const { KC_CLIENT_ID, KC_REALM, KC_URL, KC_CLIENT_SECRET } = env;
const authServerUrl = KC_URL;
const realm = KC_REALM;
const clientId = KC_CLIENT_ID;
const tokenValidation = TokenValidation.ONLINE;

export const keycloakConnectOptions: KeycloakConnectConfig = {
  authServerUrl,
  realm,
  clientId,
  secret:
    KC_CLIENT_SECRET ?? 'ERROR: Umgebungsvariable CLIENT_SECRET nicht gesetzt!',
  policyEnforcement: PolicyEnforcementMode.PERMISSIVE,
  tokenValidation,
};

/** Pfade für den REST-Client zu Keycloak */
export const paths = {
  accessToken: `realms/${realm}/protocol/openid-connect/token`,
  logout: `realms/${realm}/protocol/openid-connect/logout`,
  userInfo: `realms/${realm}/protocol/openid-connect/userinfo`,
  introspect: `realms/${realm}/protocol/openid-connect/token/introspect`,
  users: `admin/realms/${realm}/users`,
  roles: `admin/realms/${realm}/roles`,
};

/** Agent für Axios für Requests bei selbstsigniertem Zertifikat */
export const httpsAgent = new Agent({
  requestCert: true,
  rejectUnauthorized: false,
  ca: httpsOptions ? (httpsOptions.cert as Buffer) : undefined,
});
