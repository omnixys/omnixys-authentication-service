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

import { KafkaProducerService } from '../messaging/kafka-producer.service.js';
import { LoggerPlus } from './logger-plus.js';
import { Injectable } from '@nestjs/common';

/**
 * LoggerService erstellt pro Kontext eine LoggerPlus-Instanz mit Kafka-Anbindung.
 */
@Injectable()
export class LoggerService {
  readonly kafka: KafkaProducerService;

  constructor(kafka: KafkaProducerService) {
    this.kafka = kafka;
  }

  getLogger(context: string): LoggerPlus {
    return new LoggerPlus(
      context,
      // this.kafka
    );
  }
}

// Verwendung in einem Service:
// constructor(private readonly loggerService: LoggerService) {}
// const logger = this.loggerService.getLogger('MyService');
// await logger.info('methode', 'Nachricht', traceId);
