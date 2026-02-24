/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-return */
import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';

@Injectable()
export class Argon2Service {
  private readonly memoryCost = Number(process.env.ARGON2_MEMORY ?? 65536);
  private readonly timeCost = Number(process.env.ARGON2_TIME ?? 3);
  private readonly parallelism = Number(process.env.ARGON2_PARALLELISM ?? 1);
  private readonly pepper = process.env.ARGON2_PEPPER ?? '';

  /* -------------------------------------------------- */
  /* HASH                                               */
  /* -------------------------------------------------- */

  async hash(value: string): Promise<string> {
    return argon2.hash(this.applyPepper(value), {
      type: argon2.argon2id,
      memoryCost: this.memoryCost,
      timeCost: this.timeCost,
      parallelism: this.parallelism,
    });
  }

  /* -------------------------------------------------- */
  /* VERIFY                                             */
  /* -------------------------------------------------- */

  async verify(hash: string, plain: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, this.applyPepper(plain));
    } catch {
      return false;
    }
  }

  /* -------------------------------------------------- */
  /* DUMMY VERIFY (Timing Attack Mitigation)           */
  /* -------------------------------------------------- */

  async dummyVerify(): Promise<void> {
    const dummyHash =
      '$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$9sZfE6xY7nM7gqX8zSxjXxjYxjYxjYxjYxjYxjYxjY';
    try {
      await argon2.verify(dummyHash, 'dummy');
    } catch {
      // intentionally ignored
    }
  }

  /* -------------------------------------------------- */
  /* INTERNAL                                           */
  /* -------------------------------------------------- */

  private applyPepper(value: string): string {
    return value + this.pepper;
  }
}

// const valid = await this.argon.verify(token.tokenHash, rawToken);

// if (!valid) {
//   await this.argon.dummyVerify();
//   throw new UnauthorizedException();
// }
