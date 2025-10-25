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

// TODO eslint kommentare lösen
/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
// src/infra/redis/redis.client.ts
import { isRedisUrl, makeRedisOptions } from './redis.config.js';
import type { RedisClient, RedisConstructor } from './redis.types.js';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const Redis = require('ioredis') as RedisConstructor;

export function makeRedisClient(label: 'pub' | 'sub' | 'app'): RedisClient {
  const opts = makeRedisOptions();
  const client: RedisClient = isRedisUrl()
    ? new (Redis as any)(process.env.REDIS_URL)
    : new (Redis as any)(opts);

  client.on(
    'ready',
    () =>
      process.env.NODE_ENV !== 'test' && console.log(`[redis:${label}] ready`),
  );
  client.on(
    'reconnecting',
    () =>
      process.env.NODE_ENV !== 'test' &&
      console.warn(`[redis:${label}] reconnecting…`),
  );
  client.on(
    'error',
    (e) =>
      process.env.NODE_ENV !== 'test' &&
      console.error(`[redis:${label}] error:`, e?.message ?? e),
  );

  return client;
}
