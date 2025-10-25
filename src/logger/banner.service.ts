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
 * BannerService - Service zur Anzeige von Anwendungsinformationen und einem Startbanner.
 * BannerService
 * Dieser Service gibt beim Start der Anwendung ein Banner und wichtige Anwendungsinformationen aus.
 */

import { nodeConfig } from '../config/node.js';
import { getLogger } from './logger.js';
import { Injectable, type OnApplicationBootstrap } from '@nestjs/common';
import cFonts from 'cfonts';
import chalk from 'chalk';
import { release, type, userInfo } from 'node:os';
import process from 'node:process';

/**
 * BannerService - Service zum Generieren und Ausgeben von Anwendungsinformationen sowie einem Banner.
 * Dieser Service wird beim Bootstrap der Anwendung verwendet, um sowohl ein benutzerdefiniertes Banner
 * als auch wichtige Systeminformationen auszugeben.
 */
@Injectable()
export class BannerService implements OnApplicationBootstrap {
  readonly #logger = getLogger(BannerService.name);

  /**
   * @description Wird beim Bootstrap der Anwendung ausgeführt, um Anwendungsinformationen und ein Banner auszugeben.
   */
  onApplicationBootstrap() {
    const { host, nodeEnv, port, tempo } = nodeConfig;

    // Banner generieren und ausgeben
    this.#generateBanner();

    // Umgebungsinformationen mit Farben ausgeben
    this.#logger.info(chalk.green('=== Anwendungsinformationen ==='));
    this.#logger.info(chalk.cyan('Anwendungsname: ') + chalk.yellow('Authentication'));
    this.#logger.info(chalk.cyan('Node.js-Version: ') + chalk.yellow(process.version));
    this.#logger.info(chalk.cyan('Umgebung: ') + chalk.yellow(nodeEnv));
    this.#logger.info(chalk.cyan('Host: ') + chalk.yellow(host));
    this.#logger.info(chalk.cyan('Port: ') + chalk.yellow(port.toString()));
    this.#logger.info(chalk.cyan('Betriebssystem: ') + chalk.yellow(`${type()} (${release()})`));
    this.#logger.info(chalk.cyan('Benutzer: ') + chalk.yellow(userInfo().username));
    this.#logger.info(chalk.cyan('Tempo URI: ') + chalk.yellow(tempo));
    this.#logger.info(chalk.green('===============================')); // Endmarkierung für die Anwendungsinformationen
  }

  /**
   * @description Banner generieren und ausgeben.
   */
  #generateBanner() {
    cFonts.say('Authentication', {
      font: 'block', // Schriftart des Banners
      align: 'left', // Ausrichtung des Textes
      gradient: ['white', 'black'], // Farbverlauf für das Banner
      background: 'transparent', // Hintergrund des Banners
      letterSpacing: 1, // Buchstabenabstand
      lineHeight: 1, // Zeilenhöhe
    });
  }
}
