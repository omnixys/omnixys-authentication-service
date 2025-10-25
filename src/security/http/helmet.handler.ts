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

// TODO eslint kommentre lösen
/* eslint-disable @typescript-eslint/no-unsafe-call */

/**
 * Das Modul besteht aus Security-Funktionen für z.B. CSP, XSS, Click-Jacking,
 * HSTS und MIME-Sniffing, die durch Helmet bereitgestellt werden.
 * @packageDocumentation
 */

// Alternative zu helmet: lusca von Kraken
import {
  contentSecurityPolicy,
  frameguard,
  hidePoweredBy,
  hsts,
  noSniff,
  xssFilter,
} from 'helmet';

/**
 * Security-Funktionen für z.B. CSP, XSS, Click-Jacking, HSTS und MIME-Sniffing.
 */
export const helmetHandlers = [
  // CSP = Content Security Policy
  contentSecurityPolicy({
    useDefaults: true,
    directives: {
      defaultSrc: ["https: 'self'"],
      // fuer GraphQL IDE => GraphiQL
      scriptSrc: ["https: 'unsafe-inline' 'unsafe-eval'"],
      // fuer GraphQL IDE => GraphiQL
      imgSrc: ["data: 'self'"],
    },
    reportOnly: false,
  }),

  // XSS = Cross-site scripting attacks: Header X-XSS-Protection
  xssFilter(),

  // Clickjacking
  frameguard(),

  // HSTS = HTTP Strict Transport Security:
  hsts(),

  // MIME-sniffing: im Header X-Content-Type-Options
  noSniff(),

  // Im Header z.B. "X-Powered-By: Express" unterdruecken
  hidePoweredBy(),
];
