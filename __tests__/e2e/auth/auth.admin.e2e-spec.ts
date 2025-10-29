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

/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

import { gqlRequest } from '../graphql-client.js';
import { createTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

/**
 * 💡 Dieser Test deckt den gesamten Admin Flow ab:
 * - Login mit Admin-Credentials
 * - AdminSignUp (legt neuen Benutzer an)
 * - UpdateUser (Profilfelder)
 * - assignRealmRole / removeRealmRole
 * - deleteUser
 */
describe('🛡️ Auth E2E - Admin Operations (Full Flow)', () => {
  let app: INestApplication;
  let cookies: string[] = [];
  let accessToken: string | null = null;
  let authHeaders: Record<string, string> = {};
  let createdUserId: string | null = null;
  let createdUsername: string | null = null;

  const log = (msg: string): void =>
    console.info(
      JSON.stringify({ level: 'INFO', message: msg, service: 'auth-admin' }),
    );

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;

    // 🔹 Login als Admin
    const loginQ = `
      mutation {
        login(input: {
          username: "${process.env.OMNIXYS_ADMIN_USERNAME ?? 'admin'}",
          password: "${process.env.OMNIXYS_ADMIN_PASSWORD ?? 'p'}"
        }) { accessToken }
      }
    `;
    const { data, cookies: setCookies } = await gqlRequest(app, loginQ);
    cookies = setCookies ?? [];
    accessToken = data?.login?.accessToken;
    authHeaders = { Authorization: `Bearer ${accessToken}` };

    expect(accessToken).toBeDefined();
    log('✅ Admin logged in successfully');
  });

  afterAll(async () => {
  });

  // -----------------------------------------------------
  // 🔹 ADMIN SIGN-UP (neuer Benutzer)
  // -----------------------------------------------------
  it('should create a new user via adminSignUp', async () => {
    const unique = Date.now();
    createdUsername = `admin-op-${unique}`;
    const email = `admin-op-${unique}@omnixys.com`;

    const query = `
      mutation {
        adminSignUp(
          input: {
            username: "${createdUsername}"
            email: "${email}"
            password: "TempPass123!"
            firstName: "E2E"
            lastName: "AdminFlow"
            phoneNumbers: []
          }
        ) {
          accessToken
        }
      }
    `;
    const { data, errors } = await gqlRequest(app, query, authHeaders, cookies);
    expect(errors).toBeUndefined();
    expect(data?.adminSignUp?.accessToken).toBeDefined();
    log(`👤 New user created via adminSignUp → ${createdUsername}`);
  });

  // -----------------------------------------------------
  // 🔹 GET USER ID (getByUsername)
  // -----------------------------------------------------
  it('should fetch the created user by username', async () => {
    const query = `
      query {
        getByUsername(username: "${createdUsername}") {
          id
          username
          email
        }
      }
    `;
    const { data, errors } = await gqlRequest(app, query, authHeaders, cookies);
    expect(errors).toBeUndefined();
    createdUserId = data?.getByUsername?.id ?? null;
    expect(createdUserId).toMatch(/^[\w-]+$/);
    log(`📇 getByUsername successful → ID=${createdUserId}`);
  });

  // -----------------------------------------------------
  // 🔹 UPDATE USER PROFILE
  // -----------------------------------------------------
  it('should update the user profile (adminUpdateUser)', async () => {
    const query = `
      mutation {
        adminUpdateUser(
          id: "${createdUserId}",
          input: {
            firstName: "Updated"
            lastName: "AdminUser"
            email: "updated-${createdUsername}@omnixys.com"
          }
        )
      }
    `;
    const { data, errors } = await gqlRequest(app, query, authHeaders, cookies);
    expect(errors).toBeUndefined();
    expect(data?.adminUpdateUser).toBe(true);
    log('✏️ adminUpdateUser successful');
  });

  // -----------------------------------------------------
  // 🔹 ASSIGN + REMOVE ROLE
  // -----------------------------------------------------
  it('should assign and remove ADMIN role', async () => {
    const assign = `mutation { assignRealmRole(id: "${createdUserId}", roleName: ADMIN) }`;
    const remove = `mutation { removeRealmRole(id: "${createdUserId}", roleName: ADMIN) }`;

    const a = await gqlRequest(app, assign, authHeaders, cookies);
    const r = await gqlRequest(app, remove, authHeaders, cookies);

    expect(a.errors ?? []).toHaveLength(0);
    expect(r.errors ?? []).toHaveLength(0);
    expect(a.data?.assignRealmRole).toBe(true);
    expect(r.data?.removeRealmRole).toBe(true);
    log('🧩 Role assign/remove successful');
  });

  // -----------------------------------------------------
  // 🔹 DELETE USER
  // -----------------------------------------------------
  it('should delete the created user', async () => {
    const query = `mutation { deleteUser(id: "${createdUserId}") }`;
    const { data, errors } = await gqlRequest(app, query, authHeaders, cookies);
    expect(errors).toBeUndefined();
    expect(data?.deleteUser).toBe(true);
    log('🗑️ deleteUser successful');
  });
});
