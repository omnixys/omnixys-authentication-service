/* eslint-disable @typescript-eslint/explicit-function-return-type */
import { KCSignUpDTO } from '../authentication/models/dtos/kc-sign-up.dto.js';
import { RegisterService } from '../authentication/services/register.service.js';
import {
  KafkaHandler,
  KafkaEvent,
} from '../kafka/decorators/kafka-event.decorator.js';
import {
  KafkaEventHandler,
  KafkaEventContext,
} from '../kafka/interface/kafka-event.interface.js';
import { getTopic, getTopics } from '../kafka/kafka-topic.properties.js';
import { LoggerPlusService } from '../logger/logger-plus.service.js';
import { Injectable } from '@nestjs/common';

@KafkaHandler('user')
@Injectable()
export class UserHandler implements KafkaEventHandler {
  private readonly logger;

  constructor(
    private readonly userService: RegisterService,
    private readonly loggerService: LoggerPlusService,
  ) {
    this.logger = this.loggerService.getLogger(UserHandler.name);
  }

  @KafkaEvent(...getTopics('create', 'createUser'))
  async handle(
    topic: string,
    data: { payload: KCSignUpDTO },
    context: KafkaEventContext,
  ): Promise<void> {
    this.logger.debug(`Person-Kommando empfangen: ${topic}`);
    this.logger.debug('Kontext: %o', context);

    switch (topic) {
      case getTopic('create'):
        await this.create(data);
        break;

      case getTopic('createUser'):
        await this.createUser(data);
        break;

      default:
        this.logger.warn(`Unknown authentication topic: ${topic}`);
    }
  }

  private async create(data: { payload: KCSignUpDTO }) {
    const input = data.payload;

    await this.userService.signUp(input);
  }

  private async createUser(data: { payload: KCSignUpDTO }) {
    const input = data.payload;

    await this.userService.signUp(input);
  }
}
