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

import { env } from '../../config/env.js';
import { keycloakConnectOptions, paths } from '../../config/keycloak.js';
import type { LoggerPlus } from '../../logger/logger-plus.js';
import type { LoggerPlusService } from '../../logger/logger-plus.service.js';
import type { TraceContextProvider } from '../../trace/trace-context.provider.js';
import type { User } from '../models/entitys/user.entity.js';
import { PhoneKind } from '../models/enums/phone-kind.enum.js';
import type { Role, RoleData } from '../models/enums/role.enum.js';
import { ROLE_NAME_MAP } from '../models/enums/role.enum.js';
import type { HttpService } from '@nestjs/axios';
import { BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import type { Tracer } from '@opentelemetry/api';
import { context as otelContext, trace } from '@opentelemetry/api';
import * as jose from 'jose';
import { firstValueFrom } from 'rxjs';

export type RemoteJwkSet = ReturnType<typeof jose.createRemoteJWKSet>;

const { KC_ADMIN_PASSWORD, KC_ADMIN_USERNAME } = env;

/**
 * Shared base class for Keycloak read/write services.
 *
 * Provides unified Keycloak request handling with:
 * - Admin authentication and error mapping
 * - Admin token caching with expiration buffer
 * - JWKS caching and JWT verification
 * - OpenTelemetry tracing helpers
 * - Utility methods for role and attribute mapping
 *
 * This class only provides shared infrastructure, not business logic.
 */
export abstract class KeycloakBaseService {
  /** Basic authentication headers for token/logout requests. */
  protected readonly loginHeaders: Record<string, string>;

  /** OpenTelemetry tracer instance. */
  protected readonly tracer: Tracer;

  /** Logger service wrapper. */
  protected readonly loggerService: LoggerPlusService;

  /** Local logger instance. */
  protected readonly logger: LoggerPlus | Console;

  /** Trace context provider for distributed tracing. */
  protected readonly traceContext: TraceContextProvider;

  /** Cached JSON Web Key Sets per issuer. */
  #jwksCache = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();

  /** Cached admin token with expiration timestamp (ms). */
  #adminToken?: { token: string; expiresAt: number };

  /**
   * Initializes a new instance of the KeycloakBaseService.
   *
   * @param loggerService - The centralized logger service.
   * @param traceContextProvider - The trace context provider for OpenTelemetry.
   * @param http - The injected NestJS HttpService.
   */
  protected constructor(
    loggerService: LoggerPlusService,
    traceContextProvider: TraceContextProvider,
    protected readonly http: HttpService,
  ) {
    const { clientId, secret } = keycloakConnectOptions;
    const authorization = Buffer.from(`${clientId}:${secret}`, 'utf8').toString('base64');
    this.loginHeaders = {
      Authorization: `Basic ${authorization}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    this.tracer = trace.getTracer(this.constructor.name);
    this.loggerService = loggerService;
    this.logger = loggerService ? loggerService.getLogger(this.constructor.name) : console;
    this.traceContext = traceContextProvider;
  }

  /**
   * Executes a unified Keycloak HTTP request with optional admin authentication.
   *
   * @param method - The HTTP method (get, post, put, delete).
   * @param url - The path relative to the Keycloak base URL.
   * @param cfg - Optional request configuration.
   * @param behavior - Defines how errors should be handled.
   * @returns The parsed response data.
   * @throws {UnauthorizedException | NotFoundException | BadRequestException | Error}
   */
  protected async kcRequest<T = unknown>(
    method: 'get' | 'post' | 'put' | 'delete',
    url: string,
    cfg: {
      params?: Record<string, unknown>;
      data?: unknown;
      headers?: Record<string, string>;
      adminAuth?: boolean;
    } = {},
    behavior: { mapTo?: 'null-on-401' | 'throw-on-error' } = { mapTo: 'throw-on-error' },
  ): Promise<T> {
    const headers: Record<string, string> = { ...cfg.headers };
    const baseURL = keycloakConnectOptions.authServerUrl;

    if (cfg.adminAuth !== false) {
      const token = await this.getAdminToken();
      headers.Authorization = `Bearer ${token}`;
    }

    try {
      const res = await firstValueFrom(
        this.http.request<T>({
          method,
          url,
          baseURL,
          params: cfg.params,
          data: cfg.data,
          headers,
        }),
      );
      return res.data;
    } catch (err: any) {
      const status = err.response?.status ?? 500;

      if (behavior.mapTo === 'null-on-401' && (status === 400 || status === 401)) {
        void this.logger.warn(
          '%s %s -> %s %o',
          method.toUpperCase(),
          url,
          status,
          err.response?.data,
        );
        return null as T;
      }

      const body = err.response?.data;
      const msg =
        typeof body === 'string'
          ? body
          : body && typeof body === 'object'
            ? JSON.stringify(body)
            : err.message;

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
   * Verifies a JWT using the cached JWKS for the given issuer.
   *
   * @param token - The access token to verify.
   * @param issuer - The expected issuer URL.
   * @returns The decoded JWT payload.
   */
  protected async verifyJwt<T extends object>(token: string, issuer: string): Promise<T> {
    const JWKS = this.getJwks(issuer);
    const { payload } = await jose.jwtVerify(token, JWKS, { issuer });
    return payload as T;
  }

  /**
   * Retrieves and caches an admin access token.
   * Includes a 30-second pre-expiration buffer.
   *
   * @returns The valid admin access token.
   */
  protected async getAdminToken(): Promise<string> {
    const now = Date.now();
    if (this.#adminToken && this.#adminToken.expiresAt > now) {
      return this.#adminToken.token;
    }

    const params = new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: KC_ADMIN_USERNAME,
      password: KC_ADMIN_PASSWORD,
    });

    const res = await firstValueFrom(
      this.http.post<{ access_token: string; expires_in: number }>(
        `/realms/master/protocol/openid-connect/token`,
        params.toString(),
        {
          baseURL: keycloakConnectOptions.authServerUrl,
          headers: this.loginHeaders,
        },
      ),
    );

    const token = res.data.access_token;
    const expiresIn = Number(res.data.expires_in ?? 60);
    this.#adminToken = {
      token,
      expiresAt: Date.now() + Math.max(1, expiresIn - 30) * 1000,
    };
    return token;
  }

  /**
   * Builds headers for JSON-based admin requests.
   *
   * @returns Authorization and Content-Type headers.
   */
  protected async adminJsonHeaders(): Promise<Record<string, string>> {
    return {
      Authorization: `Bearer ${await this.getAdminToken()}`,
      'Content-Type': 'application/json',
    };
  }

  /**
   * Loads and validates a realm role by name.
   *
   * @param roleName - The role to load.
   * @returns The corresponding Keycloak role data.
   * @throws {NotFoundException} If the role does not exist.
   */
  protected async getRealmRole(roleName: Role | string): Promise<RoleData> {
    const effective = this.mapRoleInput(roleName);
    try {
      const role = await this.kcRequest<RoleData>(
        'get',
        `${paths.roles}/${encodeURIComponent(effective)}`,
      );
      if (!role?.id || !role?.name) {
        throw new Error(`Incomplete role object (name='${effective}')`);
      }
      return { id: role.id, name: role.name };
    } catch {
      throw new NotFoundException(`Realm role '${effective}' not found.`);
    }
  }

  /**
   * Loads all realm roles assigned to a given user.
   *
   * @param userId - The Keycloak user ID.
   * @returns A list of assigned realm roles.
   */
  protected async getUserRealmRoles(userId: string): Promise<RoleData[]> {
    return this.kcRequest<RoleData[]>(
      'get',
      `${paths.users}/${encodeURIComponent(userId)}/role-mappings/realm`,
    );
  }

  /**
   * Resolves a user ID from a given username.
   *
   * @param username - The username to search for.
   * @returns The user ID or null if not found.
   */
  protected async findUserIdByUsername(username: string): Promise<string | null> {
    const data = await this.kcRequest<Array<{ id?: string }>>('get', paths.users, {
      params: { username, exact: true },
    });
    return data?.[0]?.id ?? null;
  }

  /**
   * Maps a role enum or string to its actual Keycloak role name.
   *
   * @param input - The role enum or string.
   * @returns The mapped role name.
   */
  protected mapRoleInput(input: Role | string): string {
    const key = String(input).toUpperCase() as Role;
    return ROLE_NAME_MAP[key] ?? String(input);
  }

  /**
   * Executes an async function inside an OpenTelemetry span.
   *
   * @param name - The span name.
   * @param fn - The async function to execute.
   * @returns The result of the async function.
   */
  protected async withSpan<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const span = this.tracer.startSpan(name);
    try {
      return await otelContext.with(trace.setSpan(otelContext.active(), span), fn);
    } catch (err) {
      void this.logger.error('%s failed: %s', name, (err as Error).message);
      throw err;
    } finally {
      span.end();
    }
  }

  /**
   * Builds a Keycloak-compatible attribute map from phone data.
   *
   * @param phones - The list of phone entries.
   * @returns A Keycloak attribute map.
   */
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

  /**
   * Converts a domain user entity into a Keycloak attribute map.
   *
   * @param u - The user entity.
   * @returns The mapped Keycloak attributes.
   */
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
    if (u.roles?.length) {
      out.roles = u.roles.map((r) => String(r));
    }

    return out;
  }

  /**
   * Retrieves or caches a remote JWKS instance for a given issuer.
   *
   * @param issuer - The issuer URL.
   * @returns The JWKS retrieval function.
   */
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
