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

import { env } from '../../env.js';
import { gqlRequest } from '../graphql-client.js';
import { createTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('👤 Authentication E2E - User Operations', () => {
  let app: INestApplication;
  let cookies: string[] = [];
  let accessToken: string | null = null;
  let authHeaders: Record<string, string> = {};

  const log = (msg: string): void =>
    console.info(
      JSON.stringify({
        level: 'INFO',
        message: msg,
        service: 'authentication-user',
      }),
    );

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
    const q = `
      mutation {
        login(input: {
          username: "${env.OMNIXYS_USER_USERNAME}",
          password: "${env.OMNIXYS_USER_PASSWORD}"
        }) { accessToken }
      }
    `;
    const { data, cookies: setCookies } = await gqlRequest(app, q);
    cookies = setCookies ?? [];
    accessToken = data?.login?.accessToken;
    authHeaders = { Authorization: `Bearer ${accessToken}` };
  });

  afterAll(async () => {});

  it('should query me()', async () => {
    const query = `query { me { id username email } }`;
    const { data, errors } = await gqlRequest(app, query, authHeaders, cookies);
    expect(errors).toBeUndefined();
    expect(data?.me?.username).toBeDefined();
    log('🙋 me() successful');
  });

  it('should send password reset email', async () => {
    const query = `mutation { sendPasswordResetEmail { ok } }`;
    const { data, errors } = await gqlRequest(app, query, authHeaders, cookies);
    expect(errors ?? []).toHaveLength(0);
    expect(data?.sendPasswordResetEmail?.ok).toBe(true);
    log('📨 sendPasswordResetEmail successful');
  });
});
