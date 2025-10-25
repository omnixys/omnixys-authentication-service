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

// src/infra/redis/redis-lock.service.ts
import { RedisService } from './redis.service.js';
import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';

const LUA_RELEASE = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
else
  return 0
end
`;

@Injectable()
export class RedisLockService {
  constructor(private readonly redis: RedisService) {}

  async acquire(key: string, ttlMs = 5000): Promise<string | null> {
    const token = randomBytes(16).toString('hex');
    const ok = await this.redis.raw.set(key, token, 'PX', ttlMs, 'NX');
    return ok ? token : null;
  }

  async release(key: string, token: string): Promise<boolean> {
    const res = await this.redis.raw.eval(LUA_RELEASE, 1, key, token);
    return res === 1;
  }
}
