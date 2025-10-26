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

// kafka-event.interface.ts
// ✅ Schnittstelle für alle Kafka-Event-Handler-Klassen

/**
 * KafkaEventHandler
 * Muss von allen Klassen implementiert werden, die @KafkaEvent nutzen.
 */
export interface KafkaEventHandler {
  /**
   * Handle-Funktion, die beim Empfang eines Events aufgerufen wird.
   * @param topic - Kafka Topic, von dem die Nachricht stammt
   * @param data - Deserialisierte Nachricht
   * @param context - Kafka-Metadaten (z.B. Header, Partition)
   */
  handle(
    topic: string,
    data: unknown,
    context?: KafkaEventContext,
  ): Promise<void>;
}

export interface KafkaEventContext {
  topic: string;
  partition: number;
  offset: string;
  headers: Record<string, string | undefined>;
  timestamp: string;
}

export interface KafkaEventHandler {
  handle(
    topic: string,
    data: unknown,
    context: KafkaEventContext,
  ): Promise<void>;
}
