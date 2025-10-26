/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * For full license text, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file kafka.module.ts
 * Vollständiges Kafka-Nest-Modul inkl. Discovery für Handler-Autoregistrierung.
 * Macht KafkaProducerService und KafkaConsumerService global verfügbar.
 */

import { TraceModule } from '../trace/trace.module.js';
import {
  kafkaBootstrapProvider,
  KAFKA_INSTANCE,
  KAFKA_PRODUCER,
} from './kafka-bootstrap.provider.js';
import { KafkaConsumerService } from './kafka-consumer.service.js';
import { KafkaEventDispatcherService } from './kafka-event-dispatcher.service.js';
import { KafkaHeaderBuilder } from './kafka-header-builder.js';
import { KafkaProducerService } from './kafka-producer.service.js';
import { Global, Module } from '@nestjs/common';
import { DiscoveryModule, Reflector } from '@nestjs/core';

@Global()
@Module({
  imports: [DiscoveryModule, TraceModule],
  providers: [
    KafkaProducerService,
    KafkaConsumerService,
    KafkaEventDispatcherService,
    KafkaHeaderBuilder,
    Reflector,
    ...kafkaBootstrapProvider,
  ],
  exports: [
    KafkaProducerService,
    KafkaConsumerService,
    KafkaEventDispatcherService,
    KafkaHeaderBuilder,
    KAFKA_PRODUCER,
    KAFKA_INSTANCE,
  ],
})
export class KafkaModule {}
