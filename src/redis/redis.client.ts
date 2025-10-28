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

/**
 * Factory for creating Redis clients with unified logging and options.
 *
 * This utility builds either a URL-based or option-based `ioredis` client
 * and automatically attaches standard event listeners for connection health.
 *
 * @category Infrastructure
 */

import { LoggerPlus } from '../logger/logger-plus.js';
import { isRedisUrl, makeRedisOptions } from './redis.config.js';
import type { RedisClient, RedisConstructor } from './redis.types.js';
import { createRequire } from 'node:module';

export function safeErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  if (typeof err === 'string' || typeof err === 'number') {
    return String(err);
  }
  try {
    return JSON.stringify(err);
  } catch {
    return 'Unknown error';
  }
}

// Use createRequire for ESM compatibility
const require = createRequire(import.meta.url);
const Redis = require('ioredis') as RedisConstructor;

/**
 * Builds a configured Redis client for pub/sub/app usage.
 *
 * @param label - A label identifying the client instance (pub | sub | app)
 * @returns A ready-to-use Redis client instance
 */
export function makeRedisClient(label: 'pub' | 'sub' | 'app'): RedisClient {
  const logger = new LoggerPlus(`RedisClient:${label}`);
  const opts = makeRedisOptions();

  // Create either URL- or config-based client safely
  const client: RedisClient = isRedisUrl()
    ? new Redis(String(process.env.REDIS_URL))
    : new Redis(opts);

  // Attach listeners with consistent logging
  client.on('ready', () => {
    if (process.env.NODE_ENV !== 'test') {
      logger.log(`[redis:${label}] ready`);
    }
  });

  client.on('reconnecting', () => {
    if (process.env.NODE_ENV !== 'test') {
      logger.warn(`[redis:${label}] reconnecting…`);
    }
  });

  client.on('error', (e: unknown) => {
    if (process.env.NODE_ENV !== 'test') {
      logger.error(`[redis:${label}] error: ${safeErrorMessage(e)}`);
    }
  });

  return client;
}
