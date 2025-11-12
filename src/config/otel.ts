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

// src/observability/otel.ts
import { LoggerPlus } from '../logger/logger-plus.js';
import { env } from './env.js';
import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import {
  detectResources,
  envDetector,
  hostDetector,
  osDetector,
  processDetector,
  resourceFromAttributes,
  defaultResource,
} from '@opentelemetry/resources';
import { NodeSDK } from '@opentelemetry/sdk-node';

diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.INFO);
const logger = new LoggerPlus('otel.ts');

const traceExporter = new OTLPTraceExporter({
  url: env.TEMPO_URI,
});

const prometheusExporter = new PrometheusExporter(
  {
    port: 9464,
    endpoint: '/metrics',
  },
  () => {
    logger.log(
      '✅ Prometheus exporter läuft auf http://localhost:9464/metrics',
    );
  },
);

let sdk: NodeSDK; // <<< global deklariert

export async function startOtelSDK(): Promise<void> {
  const detected = detectResources({
    detectors: [envDetector, hostDetector, osDetector, processDetector],
  });

  const resource = defaultResource()
    .merge(detected)
    .merge(
      resourceFromAttributes({
        'service.name': 'shopping-cart-service',
      }),
    );

  sdk = new NodeSDK({
    traceExporter,
    metricReader: prometheusExporter,
    resource,
    instrumentations: [getNodeAutoInstrumentations()],
  });

  sdk.start();
  logger.log(
    '✅ OpenTelemetry gestartet – mit service.name = shopping-cart-service',
  );
}

export async function shutdownOtelSDK(): Promise<void> {
  if (sdk) {
    await sdk.shutdown();
    logger.log('🛑 OpenTelemetry SDK gestoppt');
  } else {
    console.warn('⚠️ OpenTelemetry SDK war nicht initialisiert');
  }
}
