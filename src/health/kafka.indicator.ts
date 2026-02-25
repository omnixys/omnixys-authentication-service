/**
 * Kafka Health Indicator (Terminus v10+ compatible)
 */

import { KafkaProducerService } from '../kafka/kafka-producer.service.js';
import { Inject, Injectable } from '@nestjs/common';
import { HealthIndicatorResult } from '@nestjs/terminus';
import { Kafka } from 'kafkajs';

@Injectable()
export class KafkaIndicator {
  constructor(
    @Inject('KAFKA_INSTANCE') private readonly kafka: Kafka,
    private readonly producerService: KafkaProducerService,
  ) {}

  async isHealthy(): Promise<HealthIndicatorResult> {
    const admin = this.kafka.admin();

    try {
      await admin.connect();
      await admin.disconnect();

      const circuitState =
        this.producerService['circuit']?.getState?.() ?? 'UNKNOWN';

      return {
        kafka: {
          status: 'up',
          circuitState,
        },
      };
    } catch {
      return {
        kafka: {
          status: 'down',
          message: 'Kafka not reachable',
        },
      };
    }
  }
}
