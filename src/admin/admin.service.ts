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

/* eslint-disable no-process-exit */
import { LoggerPlusService } from '../logger/logger-plus.service.js';
import { Injectable } from '@nestjs/common';

@Injectable()
export class AdminService {
  private readonly logger;

  constructor(private readonly loggerService: LoggerPlusService) {
    this.logger = this.loggerService.getLogger(AdminService.name);
  }

  /**
   * Initiates a controlled application shutdown.
   *
   * @remarks
   * This method schedules a process exit with code `0` after a short delay,
   * allowing pending logs or responses to complete before termination.
   *
   * When running inside Docker (with `restart: always` or similar),
   * the container will **not automatically restart** after a graceful shutdown.
   * Use {@link restart} if you want to trigger a container restart instead.
   *
   * @example
   * ```bash
   * curl -X POST http://localhost:7501/admin/shutdown \
   *   -H "x-api-key: super-secret-key"
   * ```
   *
   * @returns A Promise that resolves once the shutdown has been triggered.
   */
  async shutdown(): Promise<void> {
    this.logger.warn('Shutdown signal received — initiating graceful exit...');
    setTimeout(() => process.exit(0), 1000);
  }

  /**
   * Initiates a controlled application restart.
   *
   * @remarks
   * This method schedules a process exit with code `1` after a short delay.
   * Container supervisors (e.g., Docker, systemd, PM2) interpret this as a failure
   * and automatically restart the container or process.
   *
   * The restart logic does **not** manually spawn a new Node.js process,
   * avoiding port conflicts and ensuring consistent runtime state.
   *
   * @example
   * Trigger restart via Kafka:
   * ```json
   * {
   *   "topic": "admin.restart",
   *   "payload": {}
   * }
   * ```
   *
   * @example
   * Trigger restart via REST:
   * ```bash
   * curl -X POST http://localhost:7501/admin/restart \
   *   -H "x-api-key: super-secret-key"
   * ```
   *
   * @returns A Promise that resolves once the restart has been initiated.
   */
  async restart(): Promise<void> {
    this.logger.warn('Restart requested — exiting process so container supervisor restarts it...');
    setTimeout(() => process.exit(1), 1000);
  }

  /**
   * Simulates a configuration reload without restarting the process.
   *
   * @remarks
   * In production systems, this could be extended to refresh
   * cached environment variables, feature flags, or configuration files.
   *
   * @example
   * ```bash
   * curl -X POST http://localhost:7501/admin/reload-config \
   *   -H "x-api-key: super-secret-key"
   * ```
   *
   * @returns A human-readable message confirming the reload.
   */
  async reloadConfig(): Promise<string> {
    this.logger.log('Reloading configuration (mock implementation)...');
    // TODO: implement actual config reload if needed (e.g., Redis, file watcher)
    return 'Configuration reloaded successfully.';
  }

  /**
   * Returns the current health status of the service.
   *
   * @remarks
   * This is a lightweight endpoint to verify service availability.
   * It can be extended with additional checks (DB, Redis, Kafka, etc.).
   *
   * @example
   * ```bash
   * curl http://localhost:7501/admin/health
   * ```
   *
   * @returns An object with the service status and uptime in seconds.
   */
  async getHealth(): Promise<{ status: string; uptime: number }> {
    const health = { status: 'ok', uptime: process.uptime() };
    this.logger.debug(`Health check: ${JSON.stringify(health)}`);
    return health;
  }
}
