/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi – Omnixys Technologies.
 *
 * Dieses Programm ist freie Software: Sie können es unter den Bedingungen
 * der GNU General Public License, Version 3 oder später, verbreiten und/oder
 * modifizieren.
 *
 * Dieses Programm wird in der Hoffnung bereitgestellt, dass es nützlich ist,
 * jedoch OHNE JEDE GEWÄHRLEISTUNG – sogar ohne die implizite Gewährleistung
 * der MARKTGÄNGIGKEIT oder der EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
 *
 * Eine Kopie der GNU GPL v3 finden Sie unter <https://www.gnu.org/licenses/>.
 */
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

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
  KAFKA_BROKER: process.env.KAFKA_BROKER ?? '9092',
  SERVICE: process.env.SERVICE ?? '',
} as const;

// Wenn vorhanden, lade zusätzlich .health.env
const healthEnvPath = path.resolve(process.cwd(), '.health.env');
if (fs.existsSync(healthEnvPath)) {
  const result = await import('dotenv').then((dotenv) =>
    dotenv.config({ path: healthEnvPath }),
  );
  if (result.error) {
    console.warn('⚠️ Konnte .health.env nicht laden:', result.error);
  }
}

export const healthEnv = {
  KEYCLOAK_HEALTH_URL: process.env.KEYCLOAK_HEALTH_URL ?? '',
  TEMPO_HEALTH_URL: process.env.TEMPO_HEALTH_URL ?? '',
  PROMETHEUS_HEALTH_URL: process.env.PROMETHEUS_HEALTH_URL ?? '',
} as const;
