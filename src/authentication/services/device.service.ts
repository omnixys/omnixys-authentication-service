/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi
 */

import { Injectable } from '@nestjs/common';
import { createHmac } from 'crypto';

export type DeviceFingerprintInput = {
  ip?: string;
  userAgent?: string;
  acceptLanguage?: string;
  /**
   * Optional stable client fingerprint (recommended).
   * Example: a random UUID stored in localStorage and sent as header "x-device-id".
   */
  clientDeviceId?: string;
  /**
   * Optional platform hints (from Client Hints headers if you use them).
   */
  secChUa?: string;
  secChUaPlatform?: string;
  secChUaMobile?: string;
};

export type DeviceFingerprintResult = {
  deviceId: string; // stable derived hash
  strength: 'WEAK' | 'MEDIUM' | 'STRONG';
};

@Injectable()
export class DeviceService {
  private readonly hmacKey: string;

  constructor() {
    // English comment tailored for VS:
    // Use a dedicated secret to avoid correlating device IDs with other HMAC purposes.
    this.hmacKey = process.env.DEVICE_FINGERPRINT_KEY ?? '';
    if (!this.hmacKey) {
      // Do NOT throw in dev by default, but warn: you'll get weak fingerprints.
      // In production, you should enforce this.
      // eslint-disable-next-line no-console
      console.warn(
        '[DeviceService] DEVICE_FINGERPRINT_KEY is missing. Device fingerprints will be weaker.',
      );
    }
  }

  computeFingerprint(input: DeviceFingerprintInput): DeviceFingerprintResult {
    const ua = (input.userAgent ?? '').trim();
    const al = (input.acceptLanguage ?? '').trim();
    const ip = (input.ip ?? '').trim();
    const cdid = (input.clientDeviceId ?? '').trim();

    const ch = [
      (input.secChUa ?? '').trim(),
      (input.secChUaPlatform ?? '').trim(),
      (input.secChUaMobile ?? '').trim(),
    ].join('|');

    // English comment tailored for VS:
    // Prefer stable clientDeviceId if present; other signals can be volatile.
    const base = [
      `cdid=${cdid}`,
      `ua=${ua}`,
      `al=${al}`,
      `ch=${ch}`,
      // Include IP only as a weak signal; NAT/VPN makes this unstable.
      `ip=${ip}`,
    ].join('||');

    const deviceId = this.hmacKey
      ? createHmac('sha256', this.hmacKey).update(base).digest('hex')
      : createHmac('sha256', 'dev-weak-key').update(base).digest('hex');

    const strength: DeviceFingerprintResult['strength'] =
      cdid.length >= 12 ? 'STRONG' : ua.length > 20 ? 'MEDIUM' : 'WEAK';

    return { deviceId, strength };
  }
}
