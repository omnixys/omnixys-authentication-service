// /* eslint-disable @typescript-eslint/explicit-function-return-type */
// import { KCSignUpDTO } from '../authentication/models/dtos/sign-up.dto.js';
// import { UserWriteService } from '../authentication/services/user-write.service.js';
// // import { getLogger } from '../logger/get-logger.js';
// import {
//   KafkaHandler,
//   KafkaEvent,
// } from '../messaging/decorators/kafka-event.decorator.js';
// import {
//   KafkaEventHandler,
//   KafkaEventContext,
// } from '../messaging/interface/kafka-event.interface.js';
// import { getTopic } from '../messaging/kafka-topic.properties.js';
// import { Injectable } from '@nestjs/common';

// @KafkaHandler('user')
// @Injectable()
// export class UserHandler implements KafkaEventHandler {
//   // private readonly logger = getLogger(UserHandler.name);

//   constructor(private readonly userService: UserWriteService) {}

//   @KafkaEvent(getTopic('create'))
//   async handle(
//     topic: string,
//     data: { payload: KCSignUpDTO },
//     context: KafkaEventContext,
//   ): Promise<void> {
//     console.debug(`Person-Kommando empfangen: ${topic}`);
//     console.debug('Kontext: %o', context);

//     switch (topic) {
//       case getTopic('create'):
//         await this.create(data);
//         break;
//     }
//   }

//   private async create(data: { payload: KCSignUpDTO }) {
//     const input = data.payload;

//     await this.userService.u(input);
//   }
// }
