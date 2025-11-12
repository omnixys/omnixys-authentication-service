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

import { paths } from '../../config/keycloak.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import {
  isKcAttributeKey,
  KcAttributeInput,
  KcAttributeKey,
  normalizeAttributeValue,
} from '../models/attributes/user.attributes.js';
import { KeycloakRawOutput, KeycloakUserPatch } from '../models/dtos/keycloak.dto.js';
import { User } from '../models/entitys/user.entity.js';
import { PhoneKind } from '../models/enums/phone-kind.enum.js';
import { Role } from '../models/enums/role.enum.js';
import type { SignUpInput0 } from '../models/inputs/sign-up.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import type { TokenPayload } from '../models/payloads/token.payload.js';
import { AuthWriteService } from './authentication-write.service.js';
import { KeycloakBaseService } from './keycloak-base.service.js';
import { KeycloakReadService } from './read.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';

/**
 * @file Mutierende Operationen gegen Keycloak (Authentication-Flows & User-Mutationen).
 *  - login/refresh/logout
 *  - signUp / update / password / delete
 *  - Attribute & Rollen
 *  - Kafka-Events bei signUp
 */
@Injectable()
export class AdminWriteService extends KeycloakBaseService {
  constructor(
    logger: LoggerPlusService,
    trace: TraceContextProvider,
    private authService: AuthWriteService,
    private readonly readService: KeycloakReadService,
    http: HttpService,
  ) {
    super(logger, trace, http);
  }

  async signUp(input: SignUpInput0): Promise<TokenPayload> {
    return this.withSpan('authentication.signUp', async () => {
      const { firstName, lastName, email, invitationIds, phoneNumbers, username, password } = input;
      void this.logger.debug('signUp: input=%o', input);

      // 1) User anlegen
      const baseAttrs: Record<string, string[] | undefined> = {
        ...this.buildAttributesFromPhones(phoneNumbers),
      };

      if (input.ticketIds?.length) {
        baseAttrs.ticketIds = input.ticketIds;
      }
      if (invitationIds?.length) {
        baseAttrs.invitationIds = input.invitationIds;
      }
      baseAttrs.roles = ['ADMIN'];

      void this.logger.debug('signUp: baseAttr=%o', baseAttrs);

      const credentials: Array<Record<string, string | undefined | boolean>> = [
        { type: 'password', value: password, temporary: false },
      ];

      const body = {
        username,
        enabled: true,
        firstName,
        lastName,
        email,
        credentials,
        emailVerified: true,
        requiredActions: [],
        attributes: baseAttrs,
      };

      await this.kcRequest('post', paths.users, {
        data: body,
        headers: await this.adminJsonHeaders(),
      });

      const token = await this.authService.login({ username, password });

      return token;
    });
  }

  /**
   * Benutzer löschen.
   */
  async deleteUser(id: string): Promise<void> {
    await this.kcRequest('delete', `${paths.users}/${encodeURIComponent(id)}`);
  }

  /**
   * Passwort setzen (nicht temporär).
   */
  async setUserPassword(id: string, newPassword: string): Promise<void> {
    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(id)}/reset-password`, {
      data: { type: 'password', value: newPassword, temporary: false },
      headers: await this.adminJsonHeaders(),
    });
  }

  // Typesichere Signatur: nur erlaubte Keys
  async addAttributes(input: {
    userId: string;
    attributes: KcAttributeInput; // { roles?: string[], ticketIds?: string[], ... }
    mode?: 'set' | 'append' | 'remove';
  }): Promise<void> {
    void this.logger.debug('addAttributes: input=%o', input);

    const { userId, attributes } = input;
    const mode = input.mode ?? 'set';

    // 1) Aktuellen KC-User (RAW) laden
    const kcRaw = await this.kcRequest<KeycloakRawOutput>(
      'get',
      `${paths.users}/${encodeURIComponent(userId)}`,
      {
        headers: await this.adminJsonHeaders(),
      },
    );

    // 2) Aktuelle Attribute normalisieren (string[])
    const current: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(kcRaw?.attributes ?? {})) {
      current[k] = Array.isArray(v) ? [...v] : v == null ? [] : [String(v)];
    }

    // 3) Nur die übergebenen Keys mergen
    const updated: Record<string, string[]> = { ...current };
    const keys = Object.keys(attributes) as KcAttributeKey[];

    for (const key of keys) {
      if (!isKcAttributeKey(key)) {
        throw new Error(`Unsupported attribute key: ${String(key)}`);
      }
      const next = normalizeAttributeValue(key, attributes[key], mode); // → string[]

      if (mode === 'set') {
        if (next.length) {
          updated[key] = next;
        } else {
          delete updated[key];
        }
      } else if (mode === 'append') {
        if (!next.length) {
          continue;
        }
        const merged = new Set([...(updated[key] ?? []), ...next]);
        updated[key] = Array.from(merged);
      } else {
        // remove
        if (!next.length) {
          delete updated[key];
          continue;
        }
        const rm = new Set(next);
        const keep = (updated[key] ?? []).filter((s) => !rm.has(s));
        if (keep.length) {
          updated[key] = keep;
        } else {
          delete updated[key];
        }
      }
    }

    const changed = this.diffKeys(current, updated);
    void this.logger.debug('addAttributes: changedKeys=%o', changed);
    if (changed.length === 0) {
      void this.logger.debug('addAttributes: no-op (skip PUT)');
      return;
    }

    void this.logger.debug('addAttributes: changedKeys=%o', changed);

    // 4) Profilfelder aus KC übernehmen (verhindert Nulling)
    const keepProfileProps = {
      username: kcRaw.username,
      firstName: kcRaw.firstName,
      lastName: kcRaw.lastName,
      email: kcRaw.email,
    };

    // 5) PUT: vollständige (aktuell⊕patch) Attribute zurückschreiben
    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(userId)}`, {
      headers: await this.adminJsonHeaders(),
      data: {
        ...keepProfileProps,
        attributes: updated,
      },
    });
  }

  async updateUser(id: string, input: UpdateMyProfileInput): Promise<void> {
    // 1) Bestehenden User laden (für Merge)
    const kcUser = await this.readService.findById(id);

    // 2) Ausgangsbasis: bisherige Attribute aus Domain-User rekonstruieren
    const attributes: Record<string, string[] | undefined> = this.buildAttrsFromDomainUser(kcUser);

    // 2) Phones aus strukturiertem Input mappen → KC-Attribute
    if (input.phoneNumbers) {
      const priv = input.phoneNumbers.find((p) => p.kind === PhoneKind.PRIVATE)?.value;
      const work = input.phoneNumbers.find((p) => p.kind === PhoneKind.WORK)?.value;
      const wa = input.phoneNumbers.find((p) => p.kind === PhoneKind.WHATSAPP)?.value;
      const others = input.phoneNumbers
        .filter((p) => p.kind === PhoneKind.OTHER)
        .map((p) => p.value);
      attributes.privatePhone = priv ? [priv] : undefined;
      attributes.workPhone = work ? [work] : undefined;
      attributes.whatsappPhone = wa ? [wa] : undefined;
      attributes.phoneNumbers = others.length ? others : undefined;
    }

    // 4) Single-Overrides (wenn Felder explizit gesetzt wurden -> auch leeren erlauben)
    this.setOrClear(attributes, 'privatePhone', input.privatePhone);
    this.setOrClear(attributes, 'workPhone', input.workPhone);
    this.setOrClear(attributes, 'whatsappPhone', input.whatsappPhone);

    // 5) Tickets/Invitations inkrementell auf Basis der bestehenden Werte
    const currTickets = new Set<string>(attributes.ticketIds ?? kcUser.ticketIds ?? []);
    const currInvs = new Set<string>(attributes.invitationIds ?? kcUser.invitationIds ?? []);

    for (const t of input.addTicketIds ?? []) {
      currTickets.add(t);
    }
    for (const t of input.removeTicketIds ?? []) {
      currTickets.delete(t);
    }

    for (const i of input.addInvitationIds ?? []) {
      currInvs.add(i);
    }
    for (const i of input.removeInvitationIds ?? []) {
      currInvs.delete(i);
    }

    attributes.ticketIds = Array.from(currTickets);
    attributes.invitationIds = Array.from(currInvs);

    // 6) KC-User Patch – nur attributes setzen, wenn wir wirklich was schreiben wollen
    const patch: KeycloakUserPatch = {
      username: input.username ?? kcUser.username,
      firstName: input.firstName ?? kcUser.firstName,
      lastName: input.lastName ?? kcUser.lastName,
      email: input.email ?? kcUser.email,
    };

    // Wenn du nichts an attributes geändert hast, kannst du sie weglassen:
    const hasAttrKey = Object.keys(attributes).some((k) => attributes[k] !== undefined);
    if (hasAttrKey) {
      patch.attributes = attributes;
    }

    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(id)}`, {
      data: patch,
      headers: await this.adminJsonHeaders(),
    });
  }

  /**
   * Realm-Rolle einem User zuweisen.
   */
  async assignRealmRoleToUser(userId: string, roleName: Role): Promise<void> {
    const current = await this.getUserRealmRoles(userId);

    if (current.some((r) => r.name === this.mapRoleInput(roleName))) {
      return;
    }
    const role = await this.getRealmRole(roleName);
    await this.kcRequest(
      'post',
      `${paths.users}/${encodeURIComponent(userId)}/role-mappings/realm`,
      { data: [role] },
    );

    void this.logger.debug('assignRealmRoleToUser: roleName=%s', roleName);
    await this.addAttributes({
      userId,
      mode: 'append',
      attributes: { roles: roleName },
    });
  }

  /**
   * Realm-Rolle von User entfernen.
   */
  async removeRealmRoleFromUser(userId: string, roleName: Role | string): Promise<void> {
    const role = await this.getRealmRole(roleName);
    await this.kcRequest(
      'delete',
      `${paths.users}/${encodeURIComponent(userId)}/role-mappings/realm`,
      { data: [role] },
    );

    await this.addAttributes({
      userId,
      mode: 'remove',
      attributes: { roles: roleName },
    });
  }

  private setOrClear(
    attrs: Record<string, string[] | undefined>,
    key: string,
    value: string | null | undefined,
  ): void {
    if (value === undefined) {
      return;
    } // nicht angefasst
    const v = (value ?? '').trim();
    attrs[key] = v ? [v] : []; // leer/ null => Attribut leeren
  }

  private buildAttrsFromDomainUser(u: User): Record<string, string[] | undefined> {
    const priv = u.phoneNumbers?.find((p) => p.kind === PhoneKind.PRIVATE)?.value;
    const work = u.phoneNumbers?.find((p) => p.kind === PhoneKind.WORK)?.value;
    const wa = u.phoneNumbers?.find((p) => p.kind === PhoneKind.WHATSAPP)?.value;
    const others = (u.phoneNumbers ?? [])
      .filter((p) => p.kind === PhoneKind.OTHER)
      .map((p) => p.value);

    return {
      privatePhone: priv ? [priv] : undefined,
      workPhone: work ? [work] : undefined,
      whatsappPhone: wa ? [wa] : undefined,
      phoneNumbers: others.length ? others : undefined,
      ticketIds: u.ticketIds ?? undefined,
      invitationIds: u.invitationIds ?? undefined,
    };
  }

  private sameArr(a?: string[], b?: string[]): boolean {
    const A = Array.isArray(a) ? [...a].sort() : [];
    const B = Array.isArray(b) ? [...b].sort() : [];
    if (A.length !== B.length) {
      return false;
    }
    return A.every((v, i) => v === B[i]);
  }

  private diffKeys(before: Record<string, string[]>, after: Record<string, string[]>): string[] {
    const keys = Array.from(new Set([...Object.keys(before), ...Object.keys(after)]));
    return keys.filter((k) => !this.sameArr(before[k], after[k]));
  }
}
