import { AnalyticsOutboxPublisher } from './analytics-outbox.publisher.js';
import { AnalyticsOutboxService } from './analytics-outbox.service.js';
import { Module } from '@nestjs/common';

@Module({
  providers: [AnalyticsOutboxService, AnalyticsOutboxPublisher],
  exports: [AnalyticsOutboxService],
})
export class AnalyticsModule {}
