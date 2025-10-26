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

// /backend/auth/src/auth/services/keycloak-base.service.ts
import { keycloakConnectOptions, paths } from '../../config/keycloak.js';
import type { LoggerPlus } from '../../logger/logger-plus.js';
import type { LoggerService } from '../../logger/logger.service.js';
import type { TraceContextProvider } from '../../trace/trace-context.provider.js';
import type { User } from '../models/entitys/user.entity.js';
import { PhoneKind } from '../models/enums/phone-kind.enum.js';
import type { Role, RoleData } from '../models/enums/role.enum.js';
import { ROLE_NAME_MAP } from '../models/enums/role.enum.js';
import { BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import type { Tracer } from '@opentelemetry/api';
import { context as otelContext, trace } from '@opentelemetry/api';
import type { AxiosError, AxiosInstance, AxiosRequestConfig, RawAxiosRequestHeaders } from 'axios';
import axios from 'axios';
import * as jose from 'jose';

/**
 * @file Gemeinsame Basisklasse für Keycloak-Read/Write-Services:
 *  - Einheitlicher Axios-Request mit Admin-Auth & Fehler-Mapping
 *  - Admin-Token-Caching (mit Ablauf-Puffer)
 *  - JWKS-Caching und JWT-Verify-Helfer
 *  - OTel-Span-Helfer
 *  - Hilfsfunktionen (z. B. Rollen auflösen)
 *
 *  Keine Business-Methoden – nur shared Infrastruktur.
 */
export abstract class KeycloakBaseService {
  /** HTTP-Client auf Keycloak-BaseURL */
  protected readonly kc: AxiosInstance;
  /** Basic-Auth Header für /token|/logout etc. */
  protected readonly loginHeaders: RawAxiosRequestHeaders;

  protected readonly tracer: Tracer;
  protected readonly loggerService: LoggerService;
  protected readonly logger: LoggerPlus;
  protected readonly traceContext: TraceContextProvider;

  /** JWKS-Cache pro Issuer */
  #jwksCache = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();
  /** Admin-Token Cache (Token + Ablaufzeitpunkt, ms) */
  #adminToken?: { token: string; expiresAt: number };

  protected constructor(loggerService: LoggerService, traceContextProvider: TraceContextProvider) {
    const { authServerUrl, clientId, secret } = keycloakConnectOptions;

    // Basic Auth für client credentials / logout / refresh
    const authorization = Buffer.from(`${clientId}:${secret}`, 'utf8').toString('base64');
    this.loginHeaders = {
      Authorization: `Basic ${authorization}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    this.kc = axios.create({ baseURL: authServerUrl });

    this.tracer = trace.getTracer(this.constructor.name);
    this.loggerService = loggerService;
    this.logger = this.loggerService.getLogger(this.constructor.name);
    this.traceContext = traceContextProvider;
  }

  /**
   * Einheitlicher KC-Request (GET/POST/PUT/DELETE) mit optionaler Admin-Auth und sauberem Fehlermapping.
   *
   * @param method HTTP-Methode
   * @param url Pfad relativ zur Keycloak-BaseURL (z. B. `paths.users`)
   * @param cfg Axios-Konfiguration (params, data, headers, adminAuth)
   * @param behavior Fehler-Mapping (z. B. `null-on-401` für Login/Refresh)
   */
  protected async kcRequest<T = unknown>(
    method: 'get' | 'post' | 'put' | 'delete',
    url: string,
    cfg: {
      params?: Record<string, unknown>;
      data?: unknown;
      headers?: RawAxiosRequestHeaders;
      adminAuth?: boolean; // true = Authorization: Bearer <admin>
    } = {},
    behavior: { mapTo?: 'null-on-401' | 'throw-on-error' } = {
      mapTo: 'throw-on-error',
    },
  ): Promise<T> {
    const headers: RawAxiosRequestHeaders = { ...cfg.headers };

    if (cfg.adminAuth !== false) {
      const token = await this.getAdminToken();
      headers.Authorization = `Bearer ${token}`;
    }

    const request: AxiosRequestConfig = {
      method,
      url,
      params: cfg.params,
      data: cfg.data,
      headers,
    };

    try {
      const res = await this.kc.request<T>(request);
      return res.data;
    } catch (err) {
      const ax = err as AxiosError;
      const status = ax.response?.status ?? 500;

      if (behavior.mapTo === 'null-on-401' && (status === 400 || status === 401)) {
        void this.logger.warn(
          '%s %s -> %s %o',
          method.toUpperCase(),
          url,
          status,
          ax.response?.data,
        );
        return null as T;
      }

      const body = ax.response?.data;
      const msg =
        typeof body === 'string'
          ? body
          : body && typeof body === 'object'
            ? JSON.stringify(body)
            : ax.message;

      if (status === 401) {
        throw new UnauthorizedException(msg);
      }
      if (status === 404) {
        throw new NotFoundException(msg);
      }
      if (status >= 400 && status < 500) {
        throw new BadRequestException(msg);
      }

      throw new Error(
        `Keycloak request failed: ${method.toUpperCase()} ${url} -> ${status} ${msg}`,
      );
    }
  }

  /**
   * JWT verifizieren (lädt/ cached JWKS pro Issuer).
   * @param token Access-Token
   * @param issuer Erwarteter Issuer
   */
  protected async verifyJwt<T extends object>(token: string, issuer: string): Promise<T> {
    const JWKS = this.getJwks(issuer);
    const { payload } = await jose.jwtVerify(token, JWKS, { issuer });
    return payload as T;
  }

  /**
   * Admin-Token holen (mit 30s Ablaufpuffer).
   */
  protected async getAdminToken(): Promise<string> {
    const now = Date.now();
    if (this.#adminToken && this.#adminToken.expiresAt > now) {
      return this.#adminToken.token;
    }

    const username = process.env.KC_ADMIN_USER;
    const password = process.env.KC_ADMIN_PASS;
    if (!username || !password) {
      throw new UnauthorizedException('KC_ADMIN_USER / KC_ADMIN_PASS fehlen');
    }

    const params = new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username,
      password,
    });

    const res = await this.kc.post<{
      access_token: string;
      expires_in: number;
    }>(`/realms/master/protocol/openid-connect/token`, params.toString(), {
      headers: this.loginHeaders,
    });

    const token = res.data.access_token;
    const expiresIn = Number(res.data.expires_in ?? 60);
    this.#adminToken = {
      token,
      expiresAt: Date.now() + Math.max(1, expiresIn - 30) * 1000,
    };
    return token;
  }

  /**
   * Admin JSON-Header (Bearer + Content-Type).
   */
  protected async adminJsonHeaders(): Promise<RawAxiosRequestHeaders> {
    return {
      Authorization: `Bearer ${await this.getAdminToken()}`,
      'Content-Type': 'application/json',
    };
  }

  /**
   * Realm-Rolle laden und validieren.
   */
  protected async getRealmRole(roleName: Role | string): Promise<RoleData> {
    const effective = this.mapRoleInput(roleName);
    try {
      const role = await this.kc.get<RoleData>(`${paths.roles}/${encodeURIComponent(effective)}`, {
        headers: await this.adminJsonHeaders(),
      });
      const data = role.data;
      if (!data?.id || !data?.name) {
        throw new Error(`Rollenobjekt unvollständig (name='${effective}')`);
      }
      return { id: data.id, name: data.name };
    } catch {
      throw new NotFoundException(`Realm-Rolle '${effective}' nicht gefunden.`);
    }
  }

  /**
   * User-Rollen (Realm) laden.
   */
  protected async getUserRealmRoles(userId: string): Promise<RoleData[]> {
    const { data } = await this.kc.get<RoleData[]>(
      `${paths.users}/${encodeURIComponent(userId)}/role-mappings/realm`,
      { headers: await this.adminJsonHeaders() },
    );
    return data ?? [];
  }

  /**
   * Username → userId auflösen.
   */
  protected async findUserIdByUsername(username: string): Promise<string | null> {
    const data = await this.kcRequest<Array<{ id?: string }>>('get', paths.users, {
      params: { username, exact: true },
    });
    return data?.[0]?.id ?? null;
  }

  /**
   * Enum ('ADMIN') **oder** freier String ('admin') nach Keycloak-Rollenname mappen.
   */
  protected mapRoleInput(input: Role | string): string {
    const key = String(input).toUpperCase() as Role;
    return ROLE_NAME_MAP[key] ?? String(input);
  }

  /**
   * OTel-Span Helper.
   */
  protected async withSpan<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const span = this.tracer.startSpan(name);
    try {
      return await otelContext.with(trace.setSpan(otelContext.active(), span), fn);
    } catch (err) {
      // hier optional zusätzliche Span-Attribute oder handleSpanError(...)
      void this.logger.error('%s failed: %s', name, (err as Error).message);
      throw err;
    } finally {
      span.end();
    }
  }

  protected buildAttributesFromPhones(
    phones?: Array<{ kind: PhoneKind; value: string }>,
  ): Record<string, string[] | undefined> {
    const attributes: Record<string, string[] | undefined> = {};
    if (!phones?.length) {
      return attributes;
    }

    const get = (k: PhoneKind): string | undefined =>
      phones.find((p) => p.kind === k)?.value?.trim();
    const priv = get(PhoneKind.PRIVATE);
    const work = get(PhoneKind.WORK);
    const wa = get(PhoneKind.WHATSAPP);

    const others = phones
      .filter((p) => p.kind === PhoneKind.OTHER)
      .map((p) => (p.value ?? '').trim())
      .filter(Boolean);

    if (priv) {
      attributes.privatePhone = [priv];
    }
    if (work) {
      attributes.workPhone = [work];
    }
    if (wa) {
      attributes.whatsappPhone = [wa];
    }
    if (others.length) {
      attributes.phoneNumbers = Array.from(new Set(others));
    }

    return attributes;
  }

  // ---- Helper: Domain → KC-Attribute-Map (string[]) ----
  protected attrsFromDomainUser(u: User): Record<string, string[]> {
    const out: Record<string, string[]> = {};
    const phones = u.phoneNumbers ?? [];

    const getFirst = (k: PhoneKind): string | undefined =>
      phones.find((p) => p.kind === k)?.value?.trim();

    const privatePhone = getFirst(PhoneKind.PRIVATE);
    const workPhone = getFirst(PhoneKind.WORK);
    const whatsappPhone = getFirst(PhoneKind.WHATSAPP);

    const others = phones
      .filter((p) => p.kind === PhoneKind.OTHER)
      .map((p) => (p.value ?? '').trim())
      .filter(Boolean);

    if (privatePhone) {
      out.privatePhone = [privatePhone];
    }
    if (workPhone) {
      out.workPhone = [workPhone];
    }
    if (whatsappPhone) {
      out.whatsappPhone = [whatsappPhone];
    }

    if (others.length) {
      out.phoneNumbers = Array.from(new Set(others));
    }

    if (u.ticketIds?.length) {
      out.ticketIds = [...u.ticketIds];
    }
    if (u.invitationIds?.length) {
      out.invitationIds = [...u.invitationIds];
    }

    // KC-Attribut "roles" (nur Infowert; echte Realm-Rollen separat zuweisen)
    if (u.roles?.length) {
      out.roles = u.roles.map((r) => String(r));
    }

    return out;
  }

  private getJwks(issuer: string): RemoteJwkSet {
    const url = new URL(`${issuer}/protocol/openid-connect/certs`);
    const key = url.href;
    let jwks = this.#jwksCache.get(key);
    if (!jwks) {
      jwks = jose.createRemoteJWKSet(url);
      this.#jwksCache.set(key, jwks);
    }
    return jwks;
  }
}

// TODO type in /models
export type RemoteJwkSet = ReturnType<typeof jose.createRemoteJWKSet>;
