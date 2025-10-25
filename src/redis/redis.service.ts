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
/* eslint-disable @typescript-eslint/explicit-function-return-type */
// src/infra/redis/redis.service.ts
import { makeRedisClient } from './redis.client.js';
import type { RedisClient } from './redis.types.js';
import { Injectable, OnApplicationShutdown } from '@nestjs/common';

@Injectable()
export class RedisService implements OnApplicationShutdown {
  private readonly client: RedisClient = makeRedisClient('app');

  get raw(): RedisClient {
    return this.client;
  }

  async onApplicationShutdown() {
    try {
      await this.client.quit();
    } catch {
      /* noop */
    }
  }
}
