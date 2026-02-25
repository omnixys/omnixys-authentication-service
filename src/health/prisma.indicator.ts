/**
 * PostgreSQL Health via Prisma
 */

import { PrismaService } from '../prisma/prisma.service.js';
import { Injectable } from '@nestjs/common';
import { HealthIndicatorResult } from '@nestjs/terminus';

@Injectable()
export class PrismaIndicator {
  constructor(private readonly prisma: PrismaService) {}

  async isHealthy(): Promise<HealthIndicatorResult> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;

      return {
        postgres: {
          status: 'up',
        },
      };
    } catch {
      return {
        postgres: {
          status: 'down',
          message: 'Database unreachable',
        },
      };
    }
  }
}
