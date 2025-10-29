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

import type { LoggerPlus } from '../../logger/logger-plus.js';
import type { Span } from '@opentelemetry/api';
/**
 * Das Modul besteht aus den Klassen für die Fehlerbehandlung bei GraphQL.
 * @packageDocumentation
 */

import { GraphQLError } from 'graphql';

/**
 * Error-Klasse für GraphQL, die einen Response mit `errors` und
 * code `BAD_USER_INPUT` produziert.
 */
export class BadUserInputError extends GraphQLError {
  constructor(message: string, exception?: Error) {
    super(message, {
      originalError: exception,
      extensions: {
        code: 'BAD_USER_INPUT',
      },
    });
  }
}

export function handleSpanError(
  span: Span,
  error: unknown,
  logger: LoggerPlus,
  method: string,
): never {
  if (error instanceof Error) {
    span.recordException(error);
    span.setStatus({ code: 2, message: error.message });
    void logger.error(`${method}: Fehler`, error);
  } else {
    span.setStatus({ code: 2, message: 'Unbekannter Fehler' });
    void logger.error(`${method}: Unbekannter Fehler`, error);
  }
  throw error;
}
