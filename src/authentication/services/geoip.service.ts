/**
 * @license GPL-3.0-or-later
 */

import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { firstValueFrom } from 'rxjs';

export interface GeoIpResult {
  ip: string;
  countryCode?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: number;
  org?: string;
  timezone?: string;
}

@Injectable()
export class GeoIpService {
  constructor(private readonly http: HttpService) {}

  async lookup(ip: string | undefined): Promise<GeoIpResult | null> {
    if (!ip) {
      return null;
    }

    const endpoint = process.env.GEOIP_ENDPOINT?.trim();
    if (!endpoint) {
      // English comment tailored for VS:
      // No GeoIP provider configured. Return null and let risk engine degrade gracefully.
      return { ip };
    }

    try {
      // Example: GET {GEOIP_ENDPOINT}?ip=...
      const res = await firstValueFrom(this.http.get<GeoIpResult>(endpoint, { params: { ip } }));
      return res.data ?? { ip };
    } catch {
      return { ip };
    }
  }
}
