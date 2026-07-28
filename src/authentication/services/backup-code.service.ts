import { PrismaService } from '../../prisma/prisma.service.js';
import { Injectable } from '@nestjs/common';
import { HashService } from '@omnixys/security';
import { randomBytes } from 'crypto';
import { getLogger } from '@omnixys/logger';

@Injectable()
export class BackupCodeService {
  readonly #logger = getLogger(BackupCodeService.name);
  constructor(
    private readonly prisma: PrismaService,
    private readonly argon: HashService,
  ) {}

  async generate(userId: string): Promise<string[]> {
    const codes = Array.from({ length: 10 }).map(() => randomBytes(4).toString('hex'));

    await this.prisma.backupCode.deleteMany({ where: { userId } });

    for (const code of codes) {
      await this.prisma.backupCode.create({
        data: {
          userId,
          codeHash: await this.argon.hash(code),
        },
      });
    }

    return codes;
  }

  async consume(userId: string, code: string): Promise<boolean> {
    const records = await this.prisma.backupCode.findMany({
      where: { userId, usedAt: null },
    });

    for (const record of records) {
      const valid = await this.argon.verify(record.codeHash, code);

      if (valid) {
        this.#logger.debug('backup_code_consumed', { userId, recordId: record.id });
        await this.prisma.backupCode.update({
          where: { id: record.id },
          data: { usedAt: new Date() },
        });
        return true;
      }
    }

    this.#logger.warn('backup_code_invalid', { userId });
    return false;
  }
}
