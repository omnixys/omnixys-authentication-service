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

import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PubSub } from 'graphql-subscriptions';
import type { Redis } from 'ioredis';

import { makeRedisClient } from './redis.client.js';
import { ensureReady, closeClients } from './redis.health.js';
export { TRIGGER } from './redis-triggers.js';

/**
 * Wenn GQL_PUBSUB_INMEMORY=1 gesetzt ist, wird stattdessen der einfache In-Memory PubSub verwendet.
 */
const useInMemory = process.env.GQL_PUBSUB_INMEMORY === '1';

interface RedisPubSubSingleton {
  publisher: Redis;
  subscriber: Redis;
  pubsub: RedisPubSub;
}

let publisher: Redis | undefined;
let subscriber: Redis | undefined;
let pubsub: RedisPubSub | PubSub;

/**
 * Initialisierung – sorgt für Singleton-Instanz über Hot Reloads hinweg (z. B. bei Next.js oder Gateway Reload).
 */
if (useInMemory) {
  pubsub = new PubSub();
} else {
  const globalRef = globalThis as unknown as {
    __REDIS_PUBSUB_SINGLETON__?: RedisPubSubSingleton;
  };

  if (!globalRef.__REDIS_PUBSUB_SINGLETON__) {
    const pub = makeRedisClient('pub');
    const sub = makeRedisClient('sub');
    const redisPubSub = new RedisPubSub({
      publisher: pub,
      subscriber: sub,
    });

    globalRef.__REDIS_PUBSUB_SINGLETON__ = {
      publisher: pub,
      subscriber: sub,
      pubsub: redisPubSub,
    };
  }

  const singleton = globalRef.__REDIS_PUBSUB_SINGLETON__;
  publisher = singleton.publisher;
  subscriber = singleton.subscriber;
  pubsub = singleton.pubsub;
}

/**
 * Gibt den verwendeten PubSub-Adapter (Redis oder InMemory) zurück.
 */
export { pubsub, publisher, subscriber };

/**
 * Prüft, ob der Redis-PubSub-Client einsatzbereit ist.
 */
export async function ensurePubSubReady(timeout = 3000): Promise<boolean> {
  if (useInMemory || !publisher) {
    return true;
  }
  return ensureReady(publisher, timeout);
}

/**
 * Schließt die Redis-Verbindungen, wenn PubSub über Redis betrieben wird.
 */
export async function closeRedisPubSub(): Promise<void> {
  if (useInMemory || !publisher || !subscriber) {
    return;
  }
  await closeClients(publisher, subscriber);
}
