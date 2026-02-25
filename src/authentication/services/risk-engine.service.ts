/**
 * @license GPL-3.0-or-later
 */

import { DeviceService, type DeviceFingerprintResult } from './device.service.js';
import { GeoIpService, type GeoIpResult } from './geoip.service.js';
import { Injectable } from '@nestjs/common';

export type RiskDecision = 'NONE' | 'TOTP' | 'WEBAUTHN' | 'BLOCK';

export interface RiskEvaluateInput {
  userId: string;
  ip?: string;
  userAgent?: string;
  acceptLanguage?: string;
  clientDeviceId?: string;

  // flow context
  isPasswordless: boolean;
  isResetFlow: boolean;

  // signals
  failedAttempts: number;
}

export interface RiskEvaluateResult {
  score: number; // 0..100
  decision: RiskDecision;
  reasons: string[];
  geo?: GeoIpResult | null;
  device?: DeviceFingerprintResult;
}

@Injectable()
export class RiskEngineService {
  constructor(
    private readonly geoIp: GeoIpService,
    private readonly deviceService: DeviceService,
  ) {}

  async evaluate(input: RiskEvaluateInput): Promise<RiskEvaluateResult> {
    const reasons: string[] = [];

    const geo = await this.geoIp.lookup(input.ip);
    const device = this.deviceService.computeFingerprint({
      ip: input.ip,
      userAgent: input.userAgent,
      acceptLanguage: input.acceptLanguage,
      clientDeviceId: input.clientDeviceId,
    });

    let score = 0;

    // --- Baseline rules ---
    if (input.failedAttempts >= 3) {
      score += 20;
      reasons.push('failed_attempts>=3');
    }
    if (input.failedAttempts >= 6) {
      score += 35;
      reasons.push('failed_attempts>=6');
    }

    if (!input.userAgent || input.userAgent.length < 10) {
      score += 10;
      reasons.push('missing_or_short_user_agent');
    }

    if (device.strength === 'WEAK') {
      score += 10;
      reasons.push('weak_device_fingerprint');
    }

    // Passwordless should be stricter than password login.
    if (input.isPasswordless) {
      score += 10;
      reasons.push('passwordless_flow');
    }

    // Reset flow is a high-risk operation.
    if (input.isResetFlow) {
      score += 15;
      reasons.push('reset_flow');
    }

    // Optional: GeoIP heuristics
    if (geo?.countryCode) {
      // Example heuristics:
      // English comment tailored for VS:
      // Add rules like "blocked countries", "new country vs last known", "impossible travel".
      // score += ...
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    // --- Decisioning ---
    let decision: RiskDecision = 'NONE';

    // Block very high risk
    if (score >= 85) {
      decision = 'BLOCK';
    } else if (score >= 60) {
      // Strong step-up for high risk
      decision = 'WEBAUTHN';
    } else if (score >= 35) {
      // Medium risk
      decision = 'TOTP';
    }

    return { score, decision, reasons, geo, device };
  }
}
