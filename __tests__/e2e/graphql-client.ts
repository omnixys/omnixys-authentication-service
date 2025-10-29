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

import { type INestApplication } from '@nestjs/common';
import type { Server } from 'http';
import request, { type Response } from 'supertest';

interface GraphQLResponse<TData = unknown> {
  data?: TData;
  errors?: Array<{ message: string }>;
  cookies?: string[];
  res: Response;
}

/**
 * Globale Cookie-Liste (wird zwischen Testläufen automatisch gemerkt)
 */
let globalCookies: string[] = [];

/**
 * Führt eine GraphQL-Query oder -Mutation gegen die Test-App aus.
 * - Merkt Cookies (Session Handling)
 * - Gibt { data, errors, cookies, res } zurück
 */
export async function gqlRequest<
  TData = unknown,
  TVariables extends Record<string, unknown> = Record<string, unknown>,
>(
  app: INestApplication,
  query: string,
  headersOrVariables?: TVariables | Record<string, string>,
  cookies?: string[],
): Promise<GraphQLResponse<TData>> {
  const agent = app.getHttpServer() as Server;

  // Unterscheide, ob der zweite Parameter Header oder Variables sind
  const isHeaderObject =
    typeof headersOrVariables === 'object' &&
    Object.keys(headersOrVariables ?? {}).some((k) =>
      ['authorization', 'Authorization'].includes(k),
    );

  const headers = isHeaderObject
    ? (headersOrVariables as Record<string, string>)
    : undefined;

  const variables = isHeaderObject ? {} : (headersOrVariables as TVariables);

  const payload = { query, variables: variables ?? {} };

  let req = request(agent).post('/graphql');

  // Cookies hinzufügen (z. B. kc_access_token)
  if (cookies?.length || globalCookies.length) {
    req = req.set('Cookie', cookies?.length ? cookies : globalCookies);
  }

  // Optional: Bearer-Token oder zusätzliche Header setzen
  if (headers) {
    for (const [k, v] of Object.entries(headers)) {
      if (v) {
        req = req.set(k, v);
      }
    }
  }

  const res = await req.send(payload);

  const setCookies = res.headers['set-cookie'] as string[] | undefined;
  if (setCookies) {
    globalCookies = setCookies;
  }

  const body = res.body as {
    data?: TData;
    errors?: Array<{ message: string }>;
  };
  if (body.errors && body.errors.length > 0) {
    console.error(
      JSON.stringify(
        {
          level: 'ERROR',
          service: 'authentication-e2e',
          message: 'GraphQL Errors',
          details: body.errors,
        },
        null,
        2,
      ),
    );
  }

  return {
    res,
    data: body.data,
    errors: body.errors,
    cookies: setCookies,
  };
}

/**
 * Reset der gespeicherten Cookies (z. B. vor einem neuen Testlauf)
 */
export function resetCookies(): void {
  globalCookies = [];
}
