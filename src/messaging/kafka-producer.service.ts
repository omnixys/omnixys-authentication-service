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
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

import type { PhoneNumberInput } from '../authentication/models/inputs/phone-number.input.js';
import { LoggerPlusService, setGlobalKafkaProducer } from '../logger/logger-plus.service.js';
import type { TraceContext } from '../trace/trace-context.util.js';
import type { KafkaEnvelope } from './decorators/kafka-envelope.type.js';
import { KafkaHeaderBuilder } from './kafka-header-builder.js';
import { KafkaTopics } from './kafka-topic.properties.js';
import { Inject, Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import type { Producer, ProducerRecord } from 'kafkajs';

/**
 * Verwaltet den Kafka Producer als langlebige, wiederverwendbare Instanz.
 * Fire-and-Forget-sicher, Trace- und Logging-fähig.
 */
@Injectable()
export class KafkaProducerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger;

  constructor(
    @Inject('KAFKA_PRODUCER') private readonly producer: Producer,
    private readonly loggerService: LoggerPlusService,
  ) {
    this.logger = this.loggerService.getLogger(KafkaProducerService.name);
  }

  async onModuleInit(): Promise<void> {
    try {
      await this.producer.connect();
      setGlobalKafkaProducer(this);

      this.logger.info('Kafka producer connected');
    } catch (err) {
      this.logger.error('Kafka producer connection failed %o', err);
      throw err;
    }
  }

  /**
   * Sendet eine Nachricht an das angegebene Topic.
   * Fehler führen nicht zum Abbruch (Fire-and-Forget).
   */
  async send<T>(topic: string, message: KafkaEnvelope<T>, trace?: TraceContext): Promise<void> {
    const headers = KafkaHeaderBuilder.buildStandardHeaders(
      topic,
      message.event,
      trace,
      message.version,
      message.service,
    );
    const record: ProducerRecord = {
      topic,
      messages: [{ value: JSON.stringify(message), headers }],
    };

    // Fire-and-Forget
    void this.producer.send(record).catch((err) => {
      this.logger.error('Kafka send failed for topic %s → %o', topic, err);
    });
  }

  /**
   * Convenience-Methoden für spezifische Events.
   */
  async addUser(
    payload: { userId: string; invitationId: string },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'addUserId',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.invitation.addUser, envelope, trace);
  }

  async sendUserCredentials(
    payload: {
      userId: string;
      firstName: string;
      username: string;
      password: string;
      phoneNumbers?: PhoneNumberInput[];
    },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'sendCredentials',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.notification.sendCredentials, envelope, trace);
  }

  async disconnect(): Promise<void> {
    if (this.producer) {
      await this.producer.disconnect();
      this.logger.log('[KafkaProducerService] 🧹 Disconnected cleanly');
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.disconnect();
  }

  async onApplicationShutdown(): Promise<void> {
    await this.disconnect();
  }
}
