/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { PrismaService } from '../../prisma/prisma.service.js';
import { Argon2Service } from './argon2.service.js';
import { Injectable } from '@nestjs/common';

@Injectable()
export class SecurityQuestionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly argon: Argon2Service,
  ) {}

  async verifyAnswers(userId: string, answers: any[]): Promise<boolean> {
    const records = await this.prisma.securityQuestion.findMany({
      where: { userId },
    });

    for (const answer of answers) {
      const record = records.find((r) => r.id === answer.questionId);
      if (!record) {
        return false;
      }

      const valid = await this.argon.verify(record.answerHash, answer.answer);
      if (!valid) {
        return false;
      }
    }

    return true;
  }
}
