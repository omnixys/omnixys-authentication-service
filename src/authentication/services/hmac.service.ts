import { Injectable } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'crypto';

@Injectable()
export class HmacService {
  private readonly secret: Buffer;

  constructor() {
    const raw = process.env.RESET_TOKEN_HMAC_SECRET;
    if (!raw || raw.length < 32) {
      // English comment tailored for VS:
      // Enforce a minimum secret length to reduce brute-force feasibility.
      throw new Error('RESET_TOKEN_HMAC_SECRET is missing or too short (min 32 chars).');
    }
    this.secret = Buffer.from(raw, 'utf8');
  }

  /**
   * Generates a deterministic HMAC-SHA256 digest for lookup purposes.
   * Output is hex encoded and safe to store in DB with a UNIQUE index.
   */
  hash(value: string): string {
    return createHmac('sha256', this.secret).update(value, 'utf8').digest('hex');
  }

  /**
   * Timing-safe equality check for two hex strings.
   * Use only if you ever compare digests in-memory.
   */
  equals(aHex: string, bHex: string): boolean {
    const a = Buffer.from(aHex, 'hex');
    const b = Buffer.from(bHex, 'hex');
    if (a.length !== b.length) {
      return false;
    }
    return timingSafeEqual(a, b);
  }
}

// const tokenLookupHash = this.hmac.hash(rawToken);

// const token = await this.prisma.passwordResetToken.findUnique({
//   where: { tokenLookupHash },
//   include: { user: true },
// });
