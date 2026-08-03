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
import { httpsOptions } from './https.js';
import { keycloakConfig } from './keycloak.js';
import type { HttpsOptions } from '@nestjs/common/interfaces/external/https-options.interface.js';
import { hostname } from 'node:os';

export interface NodeConfig {
  host: string;
  port: number;
  nodeEnv: 'development' | 'production' | 'test';
  serviceName: string;

  httpsOptions: HttpsOptions | undefined;
  protocoll: boolean;
  keysPath: string;

  tempo: string;
  otel: string;
  otelTransportMode: string;

  keycloak: typeof keycloakConfig;

  logger: LogDetail;

  kafkaUri: string;
}

interface LogDetail {
  logDefault: boolean;
  logDir: string;
  logFileName: string;
  logPretty: boolean;
  logLevel: string;
}

const {
  NODE_ENV,
  TEMPO_URI,
  PORT,
  HTTPS,
  KEYS_PATH,
  LOG_DEFAULT,
  LOG_DIRECTORY,
  LOG_FILE_DEFAULT_NAME,
  LOG_PRETTY,
  LOG_LEVEL,
  SERVICE,
  KAFKA_BROKER,
  OTEL_URI,
  OTEL_TRANSPORT_MODE,
} = env;

/**
 * Die Konfiguration für den _Node_-basierten Server:
 * - Rechnername
 * - IP-Adresse
 * - Port
 * - `PEM`- und Zertifikat-Datei mit dem öffentlichen und privaten Schlüssel
 *   für TLS
 */

export const nodeConfig: NodeConfig = {
  host: hostname(),
  port: PORT,
  httpsOptions,
  nodeEnv: NODE_ENV as 'development' | 'production' | 'test',
  tempo: TEMPO_URI,
  otel: OTEL_URI,
  otelTransportMode: OTEL_TRANSPORT_MODE,
  protocoll: HTTPS,
  keysPath: KEYS_PATH,
  keycloak: keycloakConfig,
  logger: {
    logDefault: LOG_DEFAULT,
    logDir: LOG_DIRECTORY,
    logFileName: LOG_FILE_DEFAULT_NAME,
    logPretty: LOG_PRETTY,
    logLevel: LOG_LEVEL,
  },
  serviceName: SERVICE,
  kafkaUri: KAFKA_BROKER,
} as const;
