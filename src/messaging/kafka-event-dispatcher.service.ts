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
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
// src/messaging/kafka-event-dispatcher.service.ts

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';

import { KAFKA_EVENT_METADATA, KAFKA_HANDLER } from './decorators/kafka-event.decorator.js';
import type { KafkaEventHandler } from './interface/kafka-event.interface.js';

@Injectable()
export class KafkaEventDispatcherService implements OnModuleInit {
  private readonly logger = new Logger(KafkaEventDispatcherService.name);
  private readonly topicToHandler = new Map<
    string,
    {
      handler: KafkaEventHandler;
      methodName: string;
    }
  >();

  constructor(
    private readonly discoveryService: DiscoveryService,
    private readonly metadataScanner: MetadataScanner,
    private readonly reflector: Reflector,
  ) {}

  onModuleInit(): void {
    const providers = this.discoveryService.getProviders();

    for (const wrapper of providers) {
      const { instance } = wrapper;

      if (!instance) {
        continue;
      }

      const handlerName = this.reflector.get<string>(KAFKA_HANDLER, instance.constructor);
      if (!handlerName) {
        continue;
      }

      this.logger.debug(`📦 KafkaHandler erkannt: ${instance.constructor.name}`);

      const prototype = Object.getPrototypeOf(instance);
      const methodNames = this.metadataScanner.getAllMethodNames(prototype);

      for (const methodName of methodNames) {
        const methodRef = prototype[methodName];
        const metadata = this.reflector.get(KAFKA_EVENT_METADATA, methodRef);

        if (!metadata) {
          continue;
        }

        const { topics } = metadata;

        for (const topic of topics) {
          this.logger.debug(
            `📩 Registriere Topic "${topic}" für ${instance.constructor.name}.${methodName}()`,
          );
          this.topicToHandler.set(topic, { handler: instance, methodName });
        }
      }
    }

    this.logger.debug(
      `✅ Kafka Topics registriert: ${Array.from(this.topicToHandler.keys()).join(', ')}`,
    );
  }

  async dispatch(topic: string, payload: any, context: any): Promise<void> {
    const match = this.topicToHandler.get(topic);

    if (!match) {
      this.logger.warn(`⚠ Kein Kafka-Handler für Topic "${topic}" gefunden.`);
      return;
    }

    const { handler, methodName } = match;

    try {
      const fn = (handler as unknown as Record<string, unknown>)[methodName];

      if (typeof fn === 'function') {
        await (fn as (...args: any[]) => any)(topic, payload, context);
      } else {
        this.logger.warn(
          `⚠ Kein gültiger Handler für Topic "${topic}" (Method "${methodName}") gefunden.`,
        );
      }
    } catch (err) {
      this.logger.error(`❌ Fehler bei der Verarbeitung von Topic "${topic}"`);
      this.logger.error(err);
    }
  }
}
