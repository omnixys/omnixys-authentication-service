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

/**
 * Zentrale Konfiguration aller Kafka-Topics im System.
 * Dient der Typsicherheit, Übersichtlichkeit und Wiederverwendbarkeit in Publishern und Handlern.
 */

export const KafkaTopics = {
  invitation: {
    addUser: 'invitation.add.user',
  },
  notification: {
    sendCredentials: 'notification.notify.user',
  },
  auth: {
    create: 'auth.create.user',
    delete: 'auth.delete.user',
    addAttribute: 'auth.add-attribute.user',
    setAttribute: 'auth.set-attribute.user',
  },
  logstream: {
    log: 'logstream.log.auth',
  },
  admin: {
    restart: 'auth.restart.admin',
    shutdown: 'auth.shutdown.admin',
    allRestart: 'all.restart.admin',
    allShutdown: 'all.shutdown.admin',
  },
} as const;

/**
 * Type-safe Zugriff auf Topic-Namen.
 * Beispiel: `KafkaTopics.Invitation.CustomerDeleted`
 */
export type KafkaTopicsType = typeof KafkaTopics;

/**
 * Hilfsfunktion zur Auflistung aller konfigurierten Topic-Namen (z.B. für Subscriptions).
 */
export function getAllKafkaTopics(): readonly string[] {
  const flatten = (obj: Record<string, unknown>): string[] =>
    Object.values(obj).flatMap((value) =>
      typeof value === 'string'
        ? [value]
        : flatten(value as Record<string, unknown>),
    );
  return flatten(KafkaTopics);
}

/**
 * Gibt alle Kafka-Topics zurück, optional gefiltert nach Top-Level-Kategorien.
 * @param keys z.B. ['Invitation', 'Notification']
 */
export function getKafkaTopicsBy<K extends keyof KafkaTopicsType>(
  keys: readonly K[],
): readonly string[] {
  const result: string[] = [];
  for (const key of keys) {
    const section = KafkaTopics[key];
    if (section && typeof section === 'object') {
      result.push(...Object.values(section));
    }
  }
  return result;
}
