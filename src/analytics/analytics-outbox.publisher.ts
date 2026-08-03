import { PrismaService } from '../prisma/prisma.service.js';
import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import { KafkaProducerService } from '@omnixys/kafka-ts';
import { randomUUID } from 'node:crypto';

@Injectable()
export class AnalyticsOutboxPublisher implements OnModuleDestroy {
  private readonly instanceId = randomUUID();
  private running = true;

  constructor(
    private readonly prisma: PrismaService,
    private readonly kafka: KafkaProducerService,
  ) {}

  @Interval(1_000)
  async publishReady(): Promise<void> {
    if (!this.running) {
      return;
    }
    const candidates = await this.prisma.analyticsOutbox.findMany({
      where: {
        publishedAt: null,
        deadLetteredAt: null,
        nextAttemptAt: { lte: new Date() },
        OR: [
          { lockedAt: null },
          { lockedAt: { lt: new Date(Date.now() - 60_000) } },
        ],
      },
      orderBy: { createdAt: 'asc' },
      take: 50,
    });
    for (const candidate of candidates) {
      const claimed = await this.prisma.analyticsOutbox.updateMany({
        where: {
          id: candidate.id,
          publishedAt: null,
          deadLetteredAt: null,
          OR: [
            { lockedAt: null },
            { lockedAt: { lt: new Date(Date.now() - 60_000) } },
          ],
        },
        data: { lockedAt: new Date(), lockedBy: this.instanceId },
      });
      if (claimed.count !== 1) {
        continue;
      }
      await this.publish(candidate.id);
    }
  }

  onModuleDestroy(): void {
    this.running = false;
  }

  private async publish(id: string): Promise<void> {
    const record = await this.prisma.analyticsOutbox.findUniqueOrThrow({
      where: { id },
    });
    try {
      await this.kafka.rawSend(
        record.topic,
        JSON.stringify({
          eventId: record.id,
          eventName: record.topic,
          eventType: 'EVENT',
          eventVersion: '1',
          service: 'authentication',
          timestamp: record.createdAt.toISOString(),
          payload: record.payload,
        }),
        {
          'x-tenant-id': record.tenantId,
          'x-correlation-id': record.correlationId ?? undefined,
          'x-actor-id': record.actorId ?? undefined,
        },
      );
      await this.prisma.analyticsOutbox.update({
        where: { id },
        data: {
          publishedAt: new Date(),
          lockedAt: null,
          lockedBy: null,
          lastError: null,
        },
      });
    } catch (error) {
      const attempts = record.attempts + 1;
      await this.prisma.analyticsOutbox.update({
        where: { id },
        data: {
          attempts,
          lockedAt: null,
          lockedBy: null,
          lastError: error instanceof Error ? error.message : String(error),
          ...(attempts >= 10
            ? { deadLetteredAt: new Date() }
            : {
                nextAttemptAt: new Date(
                  Date.now() + Math.min(300_000, 2 ** attempts * 1_000),
                ),
              }),
        },
      });
    }
  }
}
