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

import { RedisLockService } from './redis-lock.service.js';
import { RedisService } from './redis.service.js';
import { Module, OnModuleDestroy } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@Module({
  imports: [],
  providers: [RedisService, RedisPubSub, RedisLockService],
  exports: [RedisService, RedisPubSub, RedisLockService],
})
export class RedisModule implements OnModuleDestroy {
  constructor(
    private readonly redis: RedisService,
    private readonly pubsub: RedisPubSub,
    private readonly lock: RedisLockService,
  ) {}

  async onModuleDestroy(): Promise<void> {
    const close = async (client: any, name: string) => {
      try {
        if (client?.quit) await client.quit();
        else if (client?.disconnect) await client.disconnect();
        console.log(`[RedisModule] 🧹 Closed ${name}`);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : JSON.stringify(err);
        console.warn(`[RedisModule] ⚠️ Error closing ${name}: ${message}`);
      }
    };

    await Promise.allSettled([
      close(this.redis, 'RedisService'),
      close(this.pubsub, 'RedisPubSub'),
      close(this.lock, 'RedisLockService'),
    ]);
  }
}
