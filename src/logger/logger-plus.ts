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
/* eslint-disable @typescript-eslint/member-ordering */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import type { TraceContext } from '../trace/trace-context.util.js';
import { getLogger } from './logger.js';
import type { SpanContext, Tracer } from '@opentelemetry/api';
import { trace, context, SpanKind, SpanStatusCode } from '@opentelemetry/api';
import { format } from 'util';

const LogLevel = {
  TRACE: 'TRACE',
  DEBUG: 'DEBUG',
  INFO: 'INFO',
  WARN: 'WARN',
  ERROR: 'ERROR',
} as const;

export type LogLevel = (typeof LogLevel)[keyof typeof LogLevel];

export interface LogEventDTO {
  level: LogLevel;
  message: string;
  service: string;
  context: string;
  traceContext?: TraceContext;
  timestamp: string;
}

export class LoggerPlus {
  private traceContext?: TraceContext;
  readonly #context: string;
  // readonly #kafka: KafkaProducerService;
  // readonly #serviceName: string;
  readonly #tracer: Tracer;

  constructor(
    context: string,
    // kafka: KafkaProducerService,
    // serviceName: string = 'shopping-cart-service',
  ) {
    this.#context = context;
    // this.#kafka = kafka;
    // this.#serviceName = serviceName;
    this.logger = getLogger(this.#context);
    this.#tracer = trace.getTracer('logger-plus');
  }

  private readonly logger;

  public withContext(traceContext?: TraceContext): LoggerPlus {
    this.traceContext = traceContext;
    return this;
  }

  // private getCaller(): string {
  //   const err = new Error();
  //   const stack = err.stack?.split('\n') ?? [];

  //   for (const line of stack) {
  //     if (
  //       line.includes('LoggerPlus.') === false && // rausfiltern
  //       line.includes('at ') &&
  //       !line.includes('node:') // optional: interne Node-Calls ausschließen
  //     ) {
  //       const match = line.match(/at\s+([^\s]+)\s/);
  //       if (match) {
  //         const fullMethod = match[1]; // z.B. InvitationWriteService.create
  //         const methodName = fullMethod?.split('.').pop() ?? 'unknown';
  //         return `${this.#context}#${methodName}`;
  //       }
  //     }
  //   }

  //   return `${this.#context}#unknown`;
  // }

  private async sendLog(
    level: LogLevel,
    // message: string
  ) {
    // Entscheide, ob ein manueller TraceContext gesetzt wurde
    const isExternalTraceContext = !!this.traceContext;

    let traceContext = this.traceContext;
    if (!traceContext) {
      const activeSpan = trace.getSpan(context.active());
      if (activeSpan) {
        const spanContext = activeSpan.spanContext();
        traceContext = {
          traceId: spanContext.traceId,
          spanId: spanContext.spanId,
          sampled: spanContext.traceFlags === 1,
        };
      }
    }

    // Optionale Span-Verlinkung bei manuellem TraceContext
    const links: Array<{ context: SpanContext }> = [];

    if (
      isExternalTraceContext &&
      traceContext?.traceId &&
      traceContext?.spanId
    ) {
      links.push({
        context: {
          traceId: traceContext.traceId,
          spanId: traceContext.spanId,
          traceFlags: traceContext.sampled ? 1 : 0,
          // 👇 isRemote ist optional, wird aber vom SDK verstanden
          isRemote: true,
        },
      });
    }

    await this.#tracer.startActiveSpan(
      `logger.${level.toLowerCase()}`,
      {
        kind: SpanKind.INTERNAL,
        links,
      },
      async (span) => {
        try {
          // await this.#kafka.sendEvent(
          //     KafkaTopics.logstream.log,
          //     'log',
          //     logPayload,
          //     this.#serviceName,
          //     'v1',
          //     traceContext,
          // );

          span.setStatus({ code: SpanStatusCode.OK });
        } catch (err) {
          span.recordException(err as Error);
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: (err as Error).message,
          });
        } finally {
          span.end();
        }
      },
    );
  }

  async debug(message: string, ...args: unknown[]) {
    const msg = format(message, ...args);
    this.logger.debug(msg);
    // await this.sendLog(LogLevel.DEBUG, msg);
  }

  async info(message: string, ...args: unknown[]) {
    const msg = format(message, ...args);
    this.logger.info(msg);
    await this.sendLog(
      LogLevel.INFO,
      // msg
    );
  }

  async warn(message: string, ...args: unknown[]) {
    const msg = format(message, ...args);
    this.logger.warn(msg);
    await this.sendLog(
      LogLevel.WARN,
      // msg
    );
  }

  async error(message: string, ...args: unknown[]) {
    const msg = format(message, ...args);
    this.logger.error(msg);
    await this.sendLog(
      LogLevel.ERROR,
      // msg
    );
  }

  async trace(message: string, ...args: unknown[]) {
    const msg = format(message, ...args);
    this.logger.trace?.(msg); // trace ist in Pino optional
    // await this.sendLog(LogLevel.TRACE, msg);
  }
}

// Verwendung:
// const logger = loggerService.getLogger(MyService.name).withContext(traceContext);
// await logger.info('myMethod', 'Meine Nachricht');
