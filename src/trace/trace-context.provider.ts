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

import { TraceContext } from './trace-context.util.js';
import { Injectable, Scope } from '@nestjs/common';

/**
 * Kontext-Provider für Trace-Daten (z.B. aus Zipkin via x-b3-traceid).
 * Wird z.B. in LoggerPlus oder Kafka verwendet.
 */
@Injectable({ scope: Scope.DEFAULT })
export class TraceContextProvider {
  private context?: TraceContext;

  #context: TraceContext | undefined;

  setContext(context: TraceContext): void {
    this.context = context;
  }

  getContext(): TraceContext | undefined {
    return this.context;
  }

  clear(): void {
    this.#context = undefined;
  }

  has(): boolean {
    return !!this.#context?.traceId;
  }
}

@Injectable({ scope: Scope.REQUEST })
export class TraceContextProviderHTTP {
  private context?: TraceContext;

  setContext(context: TraceContext): void {
    this.context = context;
  }

  getContext(): TraceContext | undefined {
    return this.context;
  }
}

// Verwendung z.B. im KafkaConsumer:
// this.traceContextProvider.setContext(TraceContextUtil.fromHeaders(headers));
// const logger = this.loggerService.getLogger(...).withContext(this.traceContextProvider.getContext());
