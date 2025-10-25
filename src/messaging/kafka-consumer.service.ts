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
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
// kafka-consumer.service.ts
// ✅ Kafka Consumer Service mit Lifecycle-Management und Dispatcher-Aufruf

import { createKafkaConsumer } from '../config/kafka.js';
import { KafkaEventDispatcherService } from './kafka-event-dispatcher.service.js';
import { getKafkaTopicsBy } from './kafka-topic.properties.js';
import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';

/**
 * KafkaConsumerService
 * Verwaltet das Abonnieren und Verarbeiten von Kafka-Nachrichten
 */
@Injectable()
export class KafkaConsumerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(KafkaConsumerService.name);
  private readonly consumer = createKafkaConsumer('checkpoint-auth');

  constructor(private readonly dispatcher: KafkaEventDispatcherService) {}

  /**
   * Startet den Kafka-Consumer bei Anwendungsstart.
   */
  async onModuleInit(): Promise<void> {
    await this.consumer.connect();

    // 👉 mehrere Subscriptions
    await this.consumer.subscribe({
      topics: getKafkaTopicsBy(['auth']),
      fromBeginning: false,
    });

    await this.consumer.run({
      eachMessage: async ({ topic, partition, message }) => {
        try {
          const rawValue = message.value?.toString();
          if (!rawValue) {
            return;
          }

          const payload = JSON.parse(rawValue);

          this.logger.log(`📩 Event erfolgreich empfangen: ${topic}`);

          await this.dispatcher.dispatch(topic, payload, {
            topic,
            partition,
            offset: message.offset,
            headers: message.headers,
            timestamp: message.timestamp,
          });
        } catch (err) {
          this.logger.error('Fehler beim Verarbeiten der Kafka-Nachricht', err);
        }
      },
    });
  }

  /**
   * Trenne Verbindung beim Shutdown
   */
  async onModuleDestroy(): Promise<void> {
    await this.consumer.disconnect();
  }
}
