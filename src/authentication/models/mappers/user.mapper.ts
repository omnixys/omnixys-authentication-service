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

import type { KeycloakTokenPayload } from '../dtos/kc-token.dto.js';
import type { KeycloakUser } from '../dtos/kc-user.dto.js';
import type { PhoneNumber } from '../entitys/phone-number.entity.js';
import type { User } from '../entitys/user.entity.js';
import { PhoneKind } from '../enums/phone-kind.enum.js';
import type { Role } from '../enums/role.enum.js';
import { toEnumRoles } from '../enums/role.enum.js';

/**
 * Utility: normiert string|string[]|undefined -> string[]|undefined
 */
function toStringArray(
  v: string | string[] | undefined | null,
): string[] | undefined {
  if (v == null) {
    return undefined;
  }
  return Array.isArray(v) ? v.filter(Boolean) : v ? [v] : undefined;
}

/**
 * Utility: holt erstes Element aus attributes[key]
 */
function firstAttr(
  attrs: Record<string, string[] | undefined> | undefined,
  key: string,
): string | undefined {
  const arr = attrs?.[key];
  return Array.isArray(arr) && arr.length > 0 ? arr[0] : undefined;
}

/**
 * Ist es ein Admin-API-User?
 */
function isKeycloakUser(
  v: KeycloakUser | KeycloakTokenPayload,
): v is KeycloakUser {
  return (
    typeof (v as KeycloakUser)?.id === 'string' &&
    typeof (v as KeycloakUser)?.username === 'string' &&
    typeof (v as KeycloakUser)?.email === 'string'
  );
}

/**
 * Aus KC-Admin-API → Domain
 * - attributes: phoneNumbers[] (frei), privatePhone/workPhone/whatsappPhone (single)
 * - ticketIds[]/invitationIds[]
 */
function fromKeycloakUser(u: KeycloakUser): User {
  const attrs: Record<string, string[] | undefined> = u.attributes ?? {};

  // Single Phones (first value)
  const privatePhone = firstAttr(attrs, 'privatePhone');
  const workPhone = firstAttr(attrs, 'workPhone');
  const whatsappPhone = firstAttr(attrs, 'whatsappPhone');

  // Multi phones (OTHER)
  const phoneNumbersRaw = attrs['phoneNumbers'] ?? [];
  const phoneOthers =
    toStringArray(phoneNumbersRaw)?.map<PhoneNumber>((v, i) => ({
      kind: PhoneKind.OTHER,
      value: v,
      label: `phone_${i + 1}`,
    })) ?? [];

  const phones: PhoneNumber[] = [
    ...(privatePhone ? [{ kind: PhoneKind.PRIVATE, value: privatePhone }] : []),
    ...(workPhone ? [{ kind: PhoneKind.WORK, value: workPhone }] : []),
    ...(whatsappPhone
      ? [{ kind: PhoneKind.WHATSAPP, value: whatsappPhone }]
      : []),
    ...phoneOthers,
  ];

  const ticketIds = toStringArray(attrs['ticketIds']);
  const invitationIds = toStringArray(attrs['invitationIds']) ?? [];

  const rolesAttr = toStringArray(attrs['roles']) ?? [];
  const roles: Role[] = toEnumRoles(rolesAttr);

  return {
    id: u.id ?? 'N/A',
    username: u.username,
    firstName: u.firstName ?? 'N/A',
    lastName: u.lastName ?? 'N/A',
    email: u.email,
    phoneNumbers: phones.length ? phones : undefined,
    ticketIds,
    invitationIds,
    roles,
    eventIds: u.attributes?.eventIds,
  };
}

/**
 * Aus Access-Token → Domain
 * - nutzt camelCase Claims aus deinem ClientScope („checkpoint-main-extra“)
 */
function fromTokenPayload(p: KeycloakTokenPayload): User {
  // Phones: baue strukturierte Liste aus den Singletons + Liste
  const phoneList: PhoneNumber[] = [];

  if (p.private_phone) {
    phoneList.push({ kind: PhoneKind.PRIVATE, value: p.private_phone });
  }
  if (p.work_phone) {
    phoneList.push({ kind: PhoneKind.WORK, value: p.work_phone });
  }
  if (p.whatsapp_phone) {
    phoneList.push({ kind: PhoneKind.WHATSAPP, value: p.whatsapp_phone });
  }

  if (Array.isArray(p.phoneNumbers)) {
    p.phoneNumbers.filter(Boolean).forEach((v: string, i) =>
      phoneList.push({
        kind: PhoneKind.OTHER,
        value: v,
        label: `phone_${i + 1}`,
      }),
    );
  }

  const realmRolesStr: string[] = Array.isArray(p.realm_access?.roles)
    ? p.realm_access.roles
    : [];
  const attrRolesStr: string[] = Array.isArray(p.roles) ? p.roles : [];

  // Merge + Enum-Normalisierung
  const roles: Role[] = toEnumRoles([...realmRolesStr, ...attrRolesStr]);

  return {
    id: p.sub ?? 'N/A',
    username: p.username ?? 'N/A',
    firstName: p.first_name ?? 'N/A',
    lastName: p.last_name ?? 'N/A',
    email: p.email ?? 'N/A',
    roles,
    invitationIds: Array.isArray(p.invitationIds)
      ? (p.invitationIds as string[])
      : [],
    ticketIds: Array.isArray(p.ticketIds) ? p.ticketIds : undefined,
    phoneNumbers: phoneList.length ? phoneList : undefined,
    eventIds: p.event_ids,
  };
}

/** Liste von Admin-API-Usern → Domain */
export function toUsers(usersRaw: readonly KeycloakUser[]): User[] {
  return usersRaw.map(fromKeycloakUser);
}

/** Overloads */
export function toUser(src: KeycloakUser): User;
export function toUser(src: KeycloakTokenPayload): User;
export function toUser(src: KeycloakUser | KeycloakTokenPayload): User {
  return isKeycloakUser(src) ? fromKeycloakUser(src) : fromTokenPayload(src);
}

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

/** Optionaler Wrapper (falls du es so in DI/Docs magst) */
export class UserMappers {
  static toUsers(usersRaw: readonly KeycloakUser[]): User[] {
    return toUsers(usersRaw);
  }
  static toUser(src: KeycloakUser | KeycloakTokenPayload): User {
    return toUser(src);
  }
}
