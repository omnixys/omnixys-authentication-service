/* eslint-disable @typescript-eslint/explicit-function-return-type */

import { SecurityQuestion } from '../../prisma/generated/client.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import {
  AuthenticationInputException,
  AuthenticationStateException,
} from '../errors/authentication.error.js';
import { SecurityQuestionInput } from '../models/inputs/security-question.input.js';
import { Injectable } from '@nestjs/common';
import { getLogger } from '@omnixys/logger-ts';
import { HashService } from '@omnixys/security-ts';

export interface AddSecurityQuestionAnswerInput {
  questionId: string;
  answer: string;
}

export interface VerifySecurityAnswerInput {
  questionId: string;
  answer: string;
}

@Injectable()
export class SecurityQuestionService {
  readonly #logger = getLogger(SecurityQuestionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly argon: HashService,
  ) {}

  // --------------------------------------------------
  // Admin: create controlled question
  // --------------------------------------------------
  async addSecurityQuestion(question: SecurityQuestionInput) {
    return this.prisma.securityQuestion.create({
      data: { question: question.question.trim(), key: question.key },
    });
  }

  async removeSecurityQuestion(questionId: string) {
    return this.prisma.securityQuestion.delete({
      where: { id: questionId },
    });
  }

  // --------------------------------------------------
  // User: add answer to predefined question
  // --------------------------------------------------
  async addSecurityQuestionAnswer(userId: string, input: AddSecurityQuestionAnswerInput) {
    const question = await this.prisma.securityQuestion.findUnique({
      where: { id: input.questionId },
    });

    if (!question) {
      throw new AuthenticationInputException('security-question-invalid');
    }

    const existing = await this.prisma.userSecurityQuestion.findUnique({
      where: {
        userId_questionId: {
          userId,
          questionId: input.questionId,
        },
      },
    });

    if (existing) {
      this.#logger.warn(
        {
          userId,
          questionId: input.questionId,
        },
        'security_question_already_configured',
      );
      throw new AuthenticationStateException('security-question-already-configured');
    }

    const answerHash = await this.argon.hash(input.answer);

    return this.prisma.userSecurityQuestion.create({
      data: {
        userId,
        questionId: input.questionId,
        answerHash,
      },
    });
  }

  async removeSecurityQuestionAnswer(userId: string, questionId: string) {
    return this.prisma.userSecurityQuestion.delete({
      where: {
        userId_questionId: {
          userId,
          questionId,
        },
      },
    });
  }

  // --------------------------------------------------
  // Verify answers
  // --------------------------------------------------
  async verifyAnswers(userId: string, answers: VerifySecurityAnswerInput[]): Promise<boolean> {
    if (!answers?.length) {
      return false;
    }

    const records = await this.prisma.userSecurityQuestion.findMany({
      where: { userId },
    });

    if (records.length === 0) {
      return false;
    }

    for (const answer of answers) {
      const record = records.find((r) => r.questionId === answer.questionId);

      if (!record) {
        this.#logger.warn({ userId, questionId: answer.questionId }, 'security_question_not_found');
        return false;
      }

      const valid = await this.argon.verify(record.answerHash, answer.answer);

      if (!valid) {
        this.#logger.warn(
          {
            userId,
            questionId: answer.questionId,
          },
          'security_question_answer_invalid',
        );
        return false;
      }
    }

    this.#logger.debug({ userId, count: answers.length }, 'security_questions_verified');
    return true;
  }

  async getAllQuestions(): Promise<SecurityQuestion[]> {
    return this.prisma.securityQuestion.findMany({});
  }
}
