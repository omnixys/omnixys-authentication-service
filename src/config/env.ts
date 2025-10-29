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

import 'dotenv/config';
import process from 'node:process';

// TODO auf englisch Übersetzen
/**
 * Umgebungsvariablen-Konfiguration für den Node-basierten Server.
 *
 * Diese Datei stellt zentral alle ENV-Parameter bereit, die über
 * `.env` oder Systemvariablen gesetzt werden.
 *
 * @remarks
 * - Alle Werte sind explizit typsicher erfasst.
 * - Fehlende Variablen erhalten sinnvolle Standardwerte (nur für DEV).
 * - Booleans werden aus "true"/"false" Strings korrekt umgewandelt.
 */
export const env = {
  /**
   * Umgebungstyp:
   * - `production` → Cloud-/Produktivbetrieb
   * - `development` → lokale Entwicklung
   * - `test` → Testausführung
   */
  NODE_ENV: process.env.NODE_ENV ?? 'development',

  SCHEMA_TARGET: process.env.SCHEMA_TARGET ?? 'true',

  /** Standard-Log-Level (z. B. info, debug, warn, error) */
  LOG_DEFAULT: process.env.LOG_DEFAULT === 'true',
  /** Standard-Log-Level (z. B. info, debug, warn, error) */
  LOG_DIRECTORY: process.env.LOG_DIRECTORY ?? 'log',
  LOG_FILE_DEFAULT_NAME: process.env.LOG_FILE_DEFAULT_NAME ?? 'server.log',
  LOG_PRETTY: process.env.LOG_PRETTY === 'true',
  LOG_LEVEL: process.env.LOG_LEVEL ?? 'info',

  /** Aktiviert HTTPS (true/false) */
  HTTPS: process.env.HTTPS === 'true',

  /** Pfad zu Key-/Zertifikatsdateien */
  KEYS_PATH: process.env.KEYS_PATH ?? './keys',

  /** Tempo-Tracing-Endpoint */
  TEMPO_URI: process.env.TEMPO_URI ?? '',

  /** Port, auf dem der Node-/NestJS-Server läuft */
  PORT: Number(process.env.PORT ?? 4000),

  /** Geheimer Schlüssel für OAuth / API-Clients */
  KC_CLIENT_SECRET: process.env.KC_CLIENT_SECRET ?? '',
  KC_URL: process.env.KC_URL ?? 'http://localhost:18080/auth',
  KC_REALM: process.env.KC_REALM ?? 'camunda-platform',
  KC_CLIENT_ID: process.env.KC_CLIENT_ID ?? 'camunda-identity',
  KC_ADMIN_USERNAME: process.env.KC_ADMIN_USERNAME ?? 'admin',
  KC_ADMIN_PASSWORD: process.env.KC_ADMIN_PASSWORD ?? 'admin',

  KAFKA_BROKER: process.env.KAFKA_BROKER ?? 'localhost:9092',
  SERVICE: process.env.SERVICE ?? '',

  KEYCLOAK_HEALTH_URL: process.env.KEYCLOAK_HEALTH_URL ?? '',
  TEMPO_HEALTH_URL: process.env.TEMPO_HEALTH_URL ?? '',
  PROMETHEUS_HEALTH_URL: process.env.PROMETHEUS_HEALTH_URL ?? '',

  GQL_PUBSUB_INMEMORY: process.env.GQL_PUBSUB_INMEMORY === 'true',
  REDIS_PC_JWE_KEY: process.env.REDIS_PC_JWE_KEY ?? '',
  REDIS_PC_TTL_SEC: Number(process.env.REDIS_PC_TTL_SEC ?? 60 * 60 * 24 * 30),
  REDIS_URL: process.env.REDIS_URL ?? '',
  REDIS_PORT: process.env.REDIS_PORT ?? '6379',
  REDIS_HOST: process.env.REDIS_HOST ?? 'localhost',
  REDIS_USERNAME: process.env.REDIS_USERNAME ?? undefined,
  REDIS_PASSWORD: process.env.REDIS_PASSWORD ?? undefined,
} as const;
