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

// kafka-bootstrap.provider.ts

import { kafka, kafkaProducer } from '../config/kafka.js';
import type { Provider } from '@nestjs/common';

export const KAFKA_INSTANCE = 'KAFKA_INSTANCE';
export const KAFKA_PRODUCER = 'KAFKA_PRODUCER';

export const kafkaInstanceProvider: Provider = {
  provide: KAFKA_INSTANCE,
  useValue: kafka,
};

export const kafkaProducerProvider: Provider = {
  provide: KAFKA_PRODUCER,
  useFactory: async () => {
    await kafkaProducer.connect();
    return kafkaProducer;
  },
};

export const kafkaBootstrapProvider: Provider[] = [
  kafkaInstanceProvider,
  kafkaProducerProvider,
];
