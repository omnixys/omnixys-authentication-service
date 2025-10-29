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

import { env } from '../config/env.js';
import type { RedisOptions } from 'ioredis';

const { REDIS_URL, REDIS_PORT, REDIS_HOST, REDIS_USERNAME, REDIS_PASSWORD } =
  env;

/**
 * Prüft, ob eine REDIS_URL gesetzt ist.
 */
export function isRedisUrl(): boolean {
  const url = REDIS_URL;
  return typeof url === 'string' && url.trim().length > 0;
}

/**
 * Erzeugt ein standardisiertes RedisOptions-Objekt für ioredis.
 */
export function makeRedisOptions(): RedisOptions {
  const port = Number(REDIS_PORT ?? 6379);

  return {
    host: REDIS_HOST,
    port: Number.isFinite(port) ? port : 6379,
    username: REDIS_USERNAME,
    password: REDIS_PASSWORD,
    retryStrategy: (times: number): number =>
      Math.min(100 + times * 200, 5_000),
    reconnectOnError: (err: Error): boolean =>
      /READONLY|ETIMEDOUT|ECONNRESET|EAI_AGAIN/i.test(err.message),
    maxRetriesPerRequest: null,
    enableAutoPipelining: true,
    enableReadyCheck: true,
  };
}
