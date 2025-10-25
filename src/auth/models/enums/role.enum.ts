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

// TODO eslint kommentare lösen
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/consistent-type-definitions */
import { registerEnumType } from '@nestjs/graphql';

export type RoleData = { id: string; name: string };

export enum Role {
  ADMIN = 'ADMIN',
  SECURITY = 'SECURITY',
  GUEST = 'GUEST',
  EVENT_ADMIN = 'EVENT_ADMIN',
}
registerEnumType(Role, { name: 'Role' });

/** Enum → tatsächlicher Keycloak-Rollenname (meist lowercase in KC) */
export const ENUM_TO_KC: Record<Role, string> = {
  [Role.ADMIN]: 'ADMIN',
  [Role.SECURITY]: 'SECURITY',
  [Role.GUEST]: 'GUEST',
  [Role.EVENT_ADMIN]: 'EVENT_ADMIN',
};

/** Keycloak-Name/String → Enum (robust & case-insensitive) */
export const KC_TO_ENUM: Record<string, Role> = {
  admin: Role.ADMIN,
  ADMIN: Role.ADMIN,
  security: Role.SECURITY,
  SECURITY: Role.SECURITY,
  guest: Role.GUEST,
  GUEST: Role.GUEST,
  EVENT_ADMIN: Role.EVENT_ADMIN,
  // hier ggf. Synonyme ergänzen, falls ihr andere Bezeichnungen nutzt
};

/** Ein String → Enum (oder null bei unbekannt) */
export function roleStrToEnum(s: string | undefined | null): Role | null {
  if (!s) {
    return null;
  }
  const hit = KC_TO_ENUM[s] || KC_TO_ENUM[String(s).toLowerCase()];
  return hit ?? null;
}

/** Strings → dedupliziertes Enum-Array */
export function toEnumRoles(list: Array<string | null | undefined>): Role[] {
  const out: Role[] = [];
  const seen = new Set<Role>();
  for (const raw of list) {
    const r = roleStrToEnum(raw ?? undefined);
    if (r && !seen.has(r)) {
      seen.add(r);
      out.push(r);
    }
  }
  return out;
}

/** Enum → Keycloak-String */
export function enumToKcName(r: Role): string {
  return ENUM_TO_KC[r] ?? String(r).toLowerCase();
}

/** Mapping deines internen Role-Typs → tatsächlicher Rollenname in Keycloak */
export const ROLE_NAME_MAP: Record<Role, string> = {
  ADMIN: Role.ADMIN,
  SECURITY: Role.SECURITY,
  GUEST: Role.GUEST,
  EVENT_ADMIN: Role.EVENT_ADMIN,
};
