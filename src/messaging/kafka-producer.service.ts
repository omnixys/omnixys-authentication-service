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
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
// kafka-producer.service.ts
// ✅ Verwaltet den Kafka Producer als langlebige Instanz

import { PhoneNumberInput } from '../auth/models/inputs/phone-number.input.js';
import { TraceContext } from '../trace/trace-context.util.js';
import { KafkaEnvelope } from './decorators/kafka-envelope.type.js';
import { KafkaTopics } from './kafka-topic.properties.js';
import { Inject, Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Producer } from 'kafkajs';

/**
 * KafkaProducerService
 * Bietet eine einfache API zum Versenden von Nachrichten an Kafka.
 */
@Injectable()
export class KafkaProducerService implements OnModuleInit, OnModuleDestroy {
  constructor(
    @Inject('KAFKA_PRODUCER')
    private readonly producer: Producer,
  ) {}

  /**
   * Initialisiert die Verbindung zum Kafka-Cluster beim Start.
   */
  async onModuleInit(): Promise<void> {
    if (!this.producer) {
      return;
    }
    await this.producer.connect();
  }

  /**
   * Sendet eine Nachricht an das angegebene Topic.
   * @param topic - Kafka Topic
   * @param message - Datenobjekt
   */
  async send<T>(topic: string, message: KafkaEnvelope<T>) {
    console.debug(`send message: ${JSON.stringify(message)} of topic: ${topic}`);
    await this.producer.send({
      topic,
      messages: [{ value: JSON.stringify(message) }],
    });
  }

  /**
   * Convenience-Methode für Einladungsgenehmigung: sendet an auth.create
   * @param payload - Nutzdaten des Benutzers
   * @param service - Ursprungs-Service
   * @param trace - Optionaler Tracing-Kontext
   */
  async addUser(
    payload: { userId: string; invitationId: string },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const topic = KafkaTopics.invitation.addUser;
    const message = {
      event: 'addUserId',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(topic, message);
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
  ) {
    const topic = KafkaTopics.notification.sendCredentials;
    const message = {
      event: 'sendCredentials',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(topic, message);
  }

  /**
   * Trennt die Verbindung zum Kafka-Cluster beim Shutdown.
   */
  async onModuleDestroy(): Promise<void> {
    if (!this.producer) {
      return;
    }
    await this.producer.disconnect();
  }
}
