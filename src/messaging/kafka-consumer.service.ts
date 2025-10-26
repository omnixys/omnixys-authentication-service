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

import type { MyKafkaEvent } from '../auth/models/my-kafka-event.js';
import { createKafkaConsumer } from '../config/kafka.js';
import { LoggerPlus } from '../logger/logger-plus.js';
import { TraceContextProvider } from '../trace/trace-context.provider.js';
import { KafkaEventDispatcherService } from './kafka-event-dispatcher.service.js';
import { getKafkaTopicsBy } from './kafka-topic.properties.js';
import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';

@Injectable()
export class KafkaConsumerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new LoggerPlus(KafkaConsumerService.name);
  private readonly consumer = createKafkaConsumer();
  private isConnected = false;

  constructor(private readonly dispatcher: KafkaEventDispatcherService) {}

  async onModuleInit(): Promise<void> {
    try {
      await this.consumer.connect();
      this.isConnected = true;
      this.logger.info('Kafka consumer connected');

      const topics = getKafkaTopicsBy(['auth']).slice();
      await this.consumer.subscribe({ topics, fromBeginning: false });
      this.logger.info('Subscribed to topics: %o', topics);

      await this.consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
          const rawValue = message.value?.toString();
          if (!rawValue) {
            return;
          }

          try {
            const payload = JSON.parse(rawValue) as MyKafkaEvent<unknown>;

            // TraceContext aus Headern extrahieren
            const traceId = message.headers?.['x-trace-id']?.toString();
            const spanId = message.headers?.['x-span-id']?.toString();

            void TraceContextProvider.run(
              { traceId: traceId ?? 'unknown-trace', spanId: spanId ?? 'unknown-span' },
              async () => {
                this.logger.info('📩 Received Kafka event on topic: %s', topic);
                await this.dispatcher.dispatch(topic, payload, {
                  topic,
                  partition,
                  offset: message.offset,
                  headers: Object.fromEntries(
                    Object.entries(message.headers ?? {}).map(([k, v]) => [k, v?.toString() ?? '']),
                  ),
                  timestamp: message.timestamp,
                });
              },
            );
          } catch (err) {
            this.logger.error('Error while processing Kafka message on %s → %o', topic, err);
          }
        },
      });

      this.logger.info('Kafka consumer started and running');
    } catch (err) {
      this.logger.error('Kafka consumer initialization failed %o', err);
      throw err;
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (!this.isConnected) {
      return;
    }
    try {
      await this.consumer.disconnect();
      this.isConnected = false;
      this.logger.info('Kafka consumer disconnected');
    } catch (err) {
      this.logger.warn('Kafka consumer disconnect failed %o', err);
    }
  }
}
