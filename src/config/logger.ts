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

import { env } from './env.js';
import { nodeConfig } from './node.js';
import { resolve } from 'node:path';
import type { DestinationStream } from 'pino';
import pino, { type Logger, type TransportMultiOptions } from 'pino';
import { type PrettyOptions } from 'pino-pretty';

/**
 * Dynamische Logger-Konfiguration.
 * Unterstützt:
 * - Datei-Logging (pino/file)
 * - Konsolen-Logging mit pino-pretty
 * - Umschaltung über ENV-Variablen
 */
const { nodeEnv } = nodeConfig;

export const loggerDefaultValue = env.LOG_DEFAULT;
const logDir = env.LOG_DIRECTORY;
const logFileNameDefault = env.LOG_FILE_DEFAULT_NAME;

const logFile = resolve(logDir, logFileNameDefault);
const pretty = env.LOG_PRETTY;

// Log-Levels: fatal, error, warn, info, debug, trace
/** Log-Level bestimmen */
let logLevel = 'info';
if (logLevel === 'debug' && nodeEnv !== 'production' && !loggerDefaultValue) {
  logLevel = 'debug';
}

/** Debug-Ausgabe nur bei aktivem DEV */
if (!loggerDefaultValue && nodeEnv !== 'production') {
  console.debug(
    `logger config: logLevel=${logLevel}, logFile=${logFile}, pretty=${pretty}, loggerDefaultValue=${loggerDefaultValue}`,
  );
}

/** Datei-Transport für persistentes Logging */
const fileOptions = {
  level: logLevel,
  target: 'pino/file',
  options: { destination: logFile, mkdir: true },
};

/** Pretty-Print-Transport für Entwicklungsmodus */
const prettyOptions: PrettyOptions = {
  translateTime: 'SYS:standard',
  singleLine: true,
  colorize: true,
  ignore: 'pid,hostname',
};

const prettyTransportOptions = {
  level: logLevel,
  target: 'pino-pretty',
  options: prettyOptions,
  redact: ['name', 'kunde', 'id'],
};

/** Zusammenstellung der Logger-Optionen */
const options: TransportMultiOptions = pretty
  ? { targets: [fileOptions, prettyTransportOptions] }
  : { targets: [fileOptions] };

/** Transport für Pino erzeugen */
const transports = pino.transport<Record<string, unknown>>(
  options,
) as unknown as DestinationStream;

/**
 * Haupt-Logger-Instanz für die Anwendung.
 * - Standard: Pino mit Transporten (Datei + optional pretty)
 * - Falls LOG_DEFAULT aktiv ist → einfacher Datei-Logger
 */
export const parentLogger: Logger = loggerDefaultValue
  ? pino(pino.destination(logFile))
  : pino({ level: logLevel }, transports);
