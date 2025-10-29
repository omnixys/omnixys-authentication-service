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

// src/service/pending-contact.service.ts
import { PendingContact } from '../auth/models/dtos/pending-contact.dto.js';
import { env } from '../config/env.js';
import { RedisService } from './redis.service.js';
import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import * as jose from 'jose';

const { REDIS_PC_JWE_KEY, REDIS_PC_TTL_SEC } = env;
@Injectable()
export class PendingContactService {
  constructor(private readonly redis: RedisService) {} // ← statt Inject('REDIS')

  private keyFor(id: string): string {
    return `pc:${id}`;
  }

  private getKeyMaterial(): Uint8Array {
    const raw = REDIS_PC_JWE_KEY;
    if (!raw || raw === '') {
      throw new Error('REDIS_PC_JWE_KEY missing (32 bytes base64 recommended)');
    }
    // base64 oder utf8 zulassen
    try {
      const buf = Buffer.from(raw, 'base64');
      if (buf.length) {
        return buf;
      }
    } catch {
      /* ignore */
    }
    return new TextEncoder().encode(raw);
  }

  async put(
    input: Omit<PendingContact, 'id' | 'createdAt'>,
    ttlSec = REDIS_PC_TTL_SEC,
  ): Promise<string> {
    const id = randomUUID();
    const payload: PendingContact = { ...input, id, createdAt: Date.now() };
    const key = this.getKeyMaterial();

    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(key);

    // ioredis API via dein RedisService
    await this.redis.raw.set(this.keyFor(id), jwe, 'EX', ttlSec);
    return id;
  }

  async get(id: string): Promise<PendingContact | null> {
    const jwe = await this.redis.raw.get(this.keyFor(id));
    if (!jwe) {
      return null;
    }
    const key = this.getKeyMaterial();
    const { plaintext } = await jose.compactDecrypt(jwe, key);
    return JSON.parse(new TextDecoder().decode(plaintext)) as PendingContact;
  }

  async del(id: string): Promise<void> {
    await this.redis.raw.del(this.keyFor(id));
  }
}
