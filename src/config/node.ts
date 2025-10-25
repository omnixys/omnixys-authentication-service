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
import type { HttpsOptions } from '@nestjs/common/interfaces/external/https-options.interface.js';
import { hostname } from 'node:os';

export interface NodeConfig {
  host: string;
  port: number;
  httpsOptions: HttpsOptions | undefined;
  nodeEnv: 'development' | 'production' | 'test';
  tempo: string;
}

const { NODE_ENV, TEMPO_URI, PORT } = env;
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
} as const;
