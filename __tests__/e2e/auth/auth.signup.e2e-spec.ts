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
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable no-console */

import { gqlRequest } from '../graphql-client.js';
import { createTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

/**
 * 💡 Vollständiger User-Onboarding-Flow (inkl. Delete):
 * 1️⃣ AdminSignUp (neuer User)
 * 2️⃣ Login mit neuem Benutzer
 * 3️⃣ getByUsername + getById
 * 4️⃣ updateMyProfile
 * 5️⃣ changeMyPassword
 * 6️⃣ Login mit neuem Passwort
 * 7️⃣ deleteUser
 */
describe('👑 Auth E2E - User SignUp Flow (Full Lifecycle)', () => {
  let app: INestApplication;
  let cookies: string[] = [];
  let createdUserId: string | null = null;
  let createdUsername: string | null = null;
  let createdEmail: string | null = null;
  let userAccessToken: string | null = null;
  let userAuthHeaders: Record<string, string> = {};

  const log = (msg: string): void =>
    console.info(
      JSON.stringify({ level: 'INFO', message: msg, service: 'auth-signup' }),
    );

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
  });

  afterAll(async () => {});

  // -----------------------------------------------------
  // 🔹 SIGN UP NEW USER
  // -----------------------------------------------------
  it('should sign up a new user successfully', async () => {
    const unique = Date.now();
    createdUsername = `live-test-${unique}`;
    createdEmail = `caleb+${unique}@omnixys.com`;

    const query = `
      mutation {
        adminSignUp(
          input: {
            username: "${createdUsername}"
            email: "${createdEmail}"
            password: "OldPass123!"
            firstName: "Caleb"
            lastName: "SignupFlow"
            phoneNumbers: []
          }
        ) {
          accessToken
        }
      }
    `;
    const { data, errors } = await gqlRequest(app, query);
    expect(errors).toBeUndefined();
    expect(data?.adminSignUp?.accessToken).toBeDefined();

    log(`👑 AdminSignUp successful → ${createdUsername}`);
  });

  // -----------------------------------------------------
  // 🔹 LOGIN WITH NEW USER
  // -----------------------------------------------------
  it('should login with the new user credentials', async () => {
    expect(createdUsername).toBeDefined();

    const query = `
      mutation {
        login(input: {
          username: "${createdUsername}",
          password: "OldPass123!"
        }) {
          accessToken
          refreshToken
        }
      }
    `;
    const { data, errors, cookies: setCookies } = await gqlRequest(app, query);
    expect(errors).toBeUndefined();

    cookies = setCookies ?? [];
    userAccessToken = data?.login?.accessToken ?? null;
    userAuthHeaders = { Authorization: `Bearer ${userAccessToken}` };

    expect(userAccessToken).toBeDefined();
    log('🔑 New user login successful');
  });

  // -----------------------------------------------------
  // 🔹 QUERY: GetByUsername + GetById
  // -----------------------------------------------------
  it('should fetch user by username and verify ID', async () => {
    const query = `
      query {
        getByUsername(username: "${createdUsername}") {
          id username email
        }
      }
    `;
    const { data, errors } = await gqlRequest(app, query, {}, cookies);
    expect(errors).toBeUndefined();

    createdUserId = data?.getByUsername?.id ?? null;
    expect(createdUserId).toMatch(/^[\w-]+$/);

    const verifyQuery = `
      query {
        getById(id: "${createdUserId}") { id username email }
      }
    `;
    const verify = await gqlRequest(app, verifyQuery, {}, cookies);
    expect(verify.errors).toBeUndefined();
    expect(verify.data?.getById?.id).toBe(createdUserId);
    log(`📇 getByUsername/getById successful → ${createdUserId}`);
  });

  // -----------------------------------------------------
  // 🔹 USER MUTATION: UpdateMyProfile
  // -----------------------------------------------------
  it('should update user profile successfully', async () => {
    const query = `
      mutation {
        updateMyProfile(
          input: {
            firstName: "Caleb"
            lastName: "Updated"
            email: "${createdEmail}"
          }
        ) {
          ok
          message
        }
      }
    `;
    const { data, errors } = await gqlRequest(
      app,
      query,
      userAuthHeaders,
      cookies,
    );

    if (errors?.length) {
      console.error('UpdateMyProfile Errors:', errors);
    }
    expect(errors ?? []).toHaveLength(0);
    expect(data?.updateMyProfile?.ok).toBe(true);

    log('🙋 updateMyProfile successful');
  });

  // -----------------------------------------------------
  // 🔹 USER MUTATION: ChangeMyPassword
  // -----------------------------------------------------
  it('should change the user password successfully', async () => {
    const query = `
      mutation {
        changeMyPassword(
          input: {
            oldPassword: "OldPass123!"
            newPassword: "NewPass123!"
          }
        ) {
          ok
          message
        }
      }
    `;
    const { data, errors } = await gqlRequest(
      app,
      query,
      userAuthHeaders,
      cookies,
    );

    if (errors?.length) {
      console.error('ChangeMyPassword Errors:', errors);
    }
    expect(errors ?? []).toHaveLength(0);
    expect(data?.changeMyPassword?.ok).toBe(true);

    log('🔐 changeMyPassword successful');
  });

  // -----------------------------------------------------
  // 🔹 VERIFY LOGIN WITH NEW PASSWORD
  // -----------------------------------------------------
  it('should login again with the new password', async () => {
    const query = `
      mutation {
        login(input: {
          username: "${createdUsername}"
          password: "NewPass123!"
        }) {
          accessToken
        }
      }
    `;
    const { data, errors } = await gqlRequest(app, query);
    expect(errors).toBeUndefined();
    expect(data?.login?.accessToken).toBeDefined();
    log('✅ Login with new password successful');
  });

  // -----------------------------------------------------
  // 🔹 DELETE USER (als Admin)
  // -----------------------------------------------------
  it('should delete the created user as admin', async () => {
    expect(createdUserId).toBeDefined();

    // 🔐 Login als Admin
    const adminLoginQuery = `
      mutation {
        login(input: {
          username: "${process.env.KEYCLOAK_ADMIN_USERNAME ?? 'admin'}",
          password: "${process.env.KEYCLOAK_ADMIN_PASSWORD ?? 'p'}"
        }) { accessToken }
      }
    `;
    const {
      data: adminData,
      cookies: adminCookies,
      errors: adminErrors,
    } = await gqlRequest(app, adminLoginQuery);

    expect(adminErrors ?? []).toHaveLength(0);
    const adminAccessToken = adminData?.login?.accessToken;
    expect(adminAccessToken).toBeDefined();

    const adminAuthHeaders = { Authorization: `Bearer ${adminAccessToken}` };

    // 🗑️ Benutzer löschen
    const deleteQuery = `mutation { deleteUser(id: "${createdUserId}") }`;
    const { data, errors } = await gqlRequest(
      app,
      deleteQuery,
      adminAuthHeaders,
      adminCookies,
    );

    expect(errors).toBeUndefined();
    expect(data?.deleteUser).toBe(true);

    log(`🗑️ deleteUser successful (deleted ${createdUserId})`);
    createdUserId = null; // verhindert doppelten Cleanup
  });
});
