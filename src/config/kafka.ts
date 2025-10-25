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
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
// kafka.ts (früher kafka.config.ts)
// ✅ Zentrale Kafka-Instanz mit korrektem Partitioner und Timeouts

import { Kafka, Partitioners, logLevel } from 'kafkajs';

/**
 * Kafka-Konfiguration für den Microservice.
 * Diese Instanz wird als Singleton verwendet.
 */
export const kafka = new Kafka({
  clientId: 'checkpoint-auth',
  brokers: ['localhost:9092'],
  logLevel: logLevel.INFO,
  connectionTimeout: 10000,
  requestTimeout: 30000,
});

/**
 * KafkaJS Producer mit Legacy Partitioner (wichtig für stabile Verteilung)
 */
export const kafkaProducer = kafka.producer({
  createPartitioner: Partitioners.LegacyPartitioner,
});

/**
 * KafkaJS Consumer Factory
 * @param groupId - ConsumerGroup-ID
 */
export const createKafkaConsumer = (groupId: string) =>
  kafka.consumer({
    groupId,
    sessionTimeout: 30000,
    heartbeatInterval: 3000,
  });
