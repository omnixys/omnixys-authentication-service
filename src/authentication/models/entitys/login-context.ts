import { TokenPayload } from '../payloads/token.payload.js';

export interface LoginContext {
  userId?: string;
  email?: string;
  ip: string;
  userAgent?: string;
  isPasswordless: boolean;
  isResetFlow: boolean;
  deviceId?: string;
  failedAttempts: number;
}

export type RiskDecision = 'NONE' | 'TOTP' | 'WEBAUTHN' | 'BLOCK';

export interface RiskResult {
  score: number;
  decision: RiskDecision;
  reasons: string[];
}

export interface AuthContext {
  ip?: string;
  userAgent?: string;
  fingerprint?: string;
  acceptLanguage?: string;
  clientDeviceId?: string; // from header e.g. x-device-id
}

export interface AuthResult {
  tokens?: TokenPayload;
  stepUpRequired?: boolean;
  stepUpMethod?: 'TOTP' | 'WEBAUTHN';
}

import { Injectable } from '@nestjs/common';
import geoip from 'geoip-lite';

@Injectable()
export class GeoIpService {
  lookup(ip: string) {
    const geo = geoip.lookup(ip);

    if (!geo) {
      return null;
    }

    return {
      country: geo.country,
      region: geo.region,
      city: geo.city,
    };
  }
}
