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
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
// src/infra/redis/redis-pubsub.ts
import { makeRedisClient } from './redis.client.js';
import { ensureReady, closeClients } from './redis.health.js';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PubSub } from 'graphql-subscriptions';
export { TRIGGER } from './redis-triggers.js';

const useInMemory = process.env.GQL_PUBSUB_INMEMORY === '1';

let pubsub: any;
let publisher: any;
let subscriber: any;

if (useInMemory) {
  pubsub = new PubSub();
} else {
  const g = globalThis as any;
  const KEY = '__REDIS_PUBSUB_SINGLETON__';
  if (!g[KEY]) {
    const pub = makeRedisClient('pub');
    const sub = makeRedisClient('sub');
    const rps = new RedisPubSub({ publisher: pub, subscriber: sub });
    g[KEY] = { publisher: pub, subscriber: sub, pubsub: rps };
  }
  ({ publisher, subscriber, pubsub } = (globalThis as any)[KEY]);
}

export { pubsub, publisher, subscriber };

export async function ensurePubSubReady(timeout = 3000) {
  if (useInMemory) {
    return true;
  }
  return ensureReady(publisher, timeout);
}

export async function closeRedisPubSub() {
  if (useInMemory) {
    return;
  }
  await closeClients(publisher, subscriber);
}
