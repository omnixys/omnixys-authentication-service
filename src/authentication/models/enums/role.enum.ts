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

import { registerEnumType } from '@nestjs/graphql';

export interface RoleData {
  id: string;
  name: string;
}

export enum RealmRole {
  ADMIN = 'ADMIN',
  USER = 'USER',
}
registerEnumType(RealmRole, { name: 'RealmRole' });

/** Enum → tatsächlicher Keycloak-Rollenname (meist lowercase in KC) */
export const ENUM_TO_KC: Record<RealmRole, string> = {
  [RealmRole.ADMIN]: 'ADMIN',
  [RealmRole.USER]: 'USER',
};

/** Keycloak-Name/String → Enum (robust & case-insensitive) */
export const KC_TO_ENUM: Record<string, RealmRole> = {
  admin: RealmRole.ADMIN,
  ADMIN: RealmRole.ADMIN,
  user: RealmRole.USER,
  USER: RealmRole.USER,

  // hier ggf. Synonyme ergänzen, falls ihr andere Bezeichnungen nutzt
};

/** Ein String → Enum (oder null bei unbekannt) */
export function roleStrToEnum(s: string | undefined | null): RealmRole | null {
  if (!s) {
    return null;
  }
  const hit = KC_TO_ENUM[s] ?? KC_TO_ENUM[String(s).toLowerCase()];
  return hit ?? null;
}

/** Strings → dedupliziertes Enum-Array */
export function toEnumRoles(
  list: Array<string | null | undefined>,
): RealmRole[] {
  const out: RealmRole[] = [];
  const seen = new Set<RealmRole>();
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
export function enumToKcName(r: RealmRole): string {
  return ENUM_TO_KC[r] ?? String(r).toLowerCase();
}

/** Mapping deines internen Role-Typs → tatsächlicher Rollenname in Keycloak */
export const ROLE_NAME_MAP: Record<RealmRole, string> = {
  ADMIN: RealmRole.ADMIN,
  USER: RealmRole.USER,
};
