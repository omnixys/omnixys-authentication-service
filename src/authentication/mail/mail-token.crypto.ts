import { env } from '../../config/env.js';
import type { Provider } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { JweService, KeyringProvider, type JweKey } from '@omnixys/security-ts';

export const MAIL_TOKEN_JWE = Symbol('MAIL_TOKEN_JWE');

function configuredKeys(): JweKey[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(env.MAIL_TOKEN_CACHE_JWE_KEYS);
  } catch (cause) {
    throw new Error('MAIL_TOKEN_CACHE_JWE_KEYS must be valid JSON', { cause });
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('MAIL_TOKEN_CACHE_JWE_KEYS must be a JSON object');
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  const activeKid = env.MAIL_TOKEN_CACHE_JWE_ACTIVE_KID;
  const active = entries.find(([kid]) => kid === activeKid);
  if (!active) {
    throw new Error(
      `MAIL_TOKEN_CACHE_JWE_ACTIVE_KID ${activeKid} is not configured`,
    );
  }
  return [active, ...entries.filter(([kid]) => kid !== activeKid)].map(
    ([kid, value]) => {
      if (typeof value !== 'string') {
        throw new Error(`JWE key ${kid} must be a base64 string`);
      }
      const material = Buffer.from(value, 'base64');
      if (material.length !== 32) {
        throw new Error(`JWE key ${kid} must decode to 32 bytes`);
      }
      return { kid, material };
    },
  );
}

export const mailTokenJweProvider: Provider = {
  provide: MAIL_TOKEN_JWE,
  inject: [OmnixysLogger],
  useFactory: (logger: OmnixysLogger) =>
    new JweService(new KeyringProvider(configuredKeys(), logger), logger),
};
