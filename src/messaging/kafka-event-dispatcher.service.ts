// TODO eslint fehler lösen
/* eslint-disable @typescript-eslint/no-unsafe-function-type */
/* eslint-disable @typescript-eslint/no-base-to-string */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi – Omnixys Technologies
 *
 * For full license text, see <https://www.gnu.org/licenses/>.
 */

// src/messaging/kafka-event-dispatcher.service.ts
// ✅ Stabiler Kafka Event Dispatcher mit Typisierung & SafeLogger

import { LoggerPlus } from '../logger/logger-plus.js';
import { TraceContextProvider } from '../trace/trace-context.provider.js';
import { KAFKA_EVENT_METADATA, KAFKA_HANDLER } from './decorators/kafka-event.decorator.js';
import type { KafkaEventContext, KafkaEventHandlerFn } from './interface/kafka-event.interface.js';
import { Injectable, OnModuleInit } from '@nestjs/common';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';

interface RegisteredHandler {
  handler: object;
  methodName: string;
}

@Injectable()
export class KafkaEventDispatcherService implements OnModuleInit {
  private readonly logger = new LoggerPlus(KafkaEventDispatcherService.name);
  private readonly topicToHandler = new Map<string, RegisteredHandler>();

  constructor(
    private readonly discoveryService: DiscoveryService,
    private readonly metadataScanner: MetadataScanner,
    private readonly reflector: Reflector,
  ) {}

  onModuleInit(): void {
    const providers = this.discoveryService.getProviders();

    for (const wrapper of providers) {
      const instance = wrapper.instance as object | undefined;
      if (!instance) {
        continue;
      }

      const handlerName = this.reflector.get<string>(KAFKA_HANDLER, instance.constructor);
      if (!handlerName) {
        continue;
      }

      this.logger.debug('📦 KafkaHandler erkannt: %s', instance.constructor.name);

      const prototype = Object.getPrototypeOf(instance);
      const methodNames = this.metadataScanner.getAllMethodNames(prototype);

      for (const methodName of methodNames) {
        const methodRef = prototype[methodName] as Function;
        const metadata = this.reflector.get<{ topics: string[] }>(KAFKA_EVENT_METADATA, methodRef);

        if (!metadata) {
          continue;
        }

        for (const topic of metadata.topics) {
          this.logger.debug(
            '📩 Registriere Topic "%s" für %s.%s()',
            topic,
            instance.constructor.name,
            methodName,
          );
          this.topicToHandler.set(topic, { handler: instance, methodName });
        }
      }
    }

    const allTopics = Array.from(this.topicToHandler.keys());
    this.logger.info('✅ Kafka Topics registriert: %s', allTopics.join(', ') || '— none —');
  }

  /**
   * Führt den passenden Kafka-Handler für ein Topic aus.
   */
  async dispatch<TPayload>(
    topic: string,
    payload: TPayload,
    context: Record<string, unknown>,
  ): Promise<void> {
    const match = this.topicToHandler.get(topic);

    if (!match) {
      this.logger.warn('⚠ Kein Kafka-Handler für Topic "%s" gefunden.', topic);
      return;
    }

    const { handler, methodName } = match;
    const fn = (handler as Record<string, unknown>)[methodName];

    if (typeof fn !== 'function') {
      this.logger.warn('⚠ Ungültiger Handler für Topic "%s" → %s', topic, methodName);
      return;
    }

    // TraceContext aus Headern extrahieren
    const headers = (context.headers ?? {}) as Record<string, string | undefined>;
    const traceId = headers['x-trace-id'] ?? 'unknown-trace';
    const spanId = headers['x-span-id'] ?? 'unknown-span';

    // ✅ KORREKT typisiertes Context-Objekt erzeugen
    const kafkaContext: KafkaEventContext = {
      topic: String(context.topic ?? topic),
      partition: Number(context.partition ?? 0),
      offset: String(context.offset ?? '0'),
      headers,
      timestamp: String(context.timestamp ?? new Date().toISOString()),
    };

    await TraceContextProvider.run(
      { traceId: traceId ?? 'unknown-trace', spanId: spanId ?? 'unknown-span' },
      async () => {
        try {
          await (fn as KafkaEventHandlerFn)(topic, payload, kafkaContext);
          this.logger.debug('✅ Topic "%s" erfolgreich verarbeitet.', topic);
        } catch (err) {
          this.logger.error('❌ Fehler bei der Verarbeitung von "%s" → %o', topic, err);
        }
      },
    );
  }
}
