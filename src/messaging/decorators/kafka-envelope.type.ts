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
// kafka-envelope.type.ts
// ✅ Typisierte Event-Hülle für Kafka-Nachrichten zur Standardisierung von Payloads

/**
 * KafkaEnvelope
 * Einheitliches Nachrichtenformat für Kafka-Nachrichten in allen Services.
 *
 * @template T - Nutzdatenstruktur (Payload)
 */
export interface KafkaEnvelope<T = unknown> {
  /**
   * Event-Name (z. B. "acceptRsvp", "deleteUser")
   */
  event: string;

  /**
   * Ursprungs-Service (z. B. "invitation-service")
   */
  service: string;

  /**
   * Versionskennung (z. B. "v1")
   */
  version: string;

  /**
   * Tracing-/Correlation-Kontext
   */
  trace?: Record<string, any>;

  /**
   * Nutzdaten (z. B. Benutzer, Einladung, etc.)
   */
  payload: T;
}
