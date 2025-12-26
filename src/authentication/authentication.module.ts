/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

import { AuthModule } from '../auth/auth.module.js';
import { CoreHttpModule } from '../http.module.js';
import { LoggerModule } from '../logger/logger.module.js';
import { KafkaModule } from '../messaging/kafka.module.js';
import { TraceModule } from '../trace/trace.module.js';
import { ValkeyModule } from '../valkey/valkey.module.js';
import { AdminMutationResolver } from './resolvers/admin-mutation.resolver.js';
import { AuthMutationResolver } from './resolvers/authentication-mutation.resolver.js';
import { AuthQueryResolver } from './resolvers/authentication-query.resolver.js';
import { UserMutationResolver } from './resolvers/user-mutation.resolver.js';
import { AdminWriteService } from './services/admin-write.service.js';
import { AuthWriteService } from './services/authentication-write.service.js';
import { PendingContactService } from './services/pending-contact.service.js';
import { AuthenticateReadService } from './services/read.service.js';
import { UserWriteService } from './services/user-write.service.js';
import { Module } from '@nestjs/common';

@Module({
  imports: [KafkaModule, LoggerModule, TraceModule, CoreHttpModule, AuthModule, ValkeyModule],
  providers: [
    AuthenticateReadService,
    UserWriteService,
    AdminWriteService,
    AuthWriteService,
    AuthQueryResolver,
    AuthMutationResolver,
    UserMutationResolver,
    AdminMutationResolver,
    PendingContactService,
  ],
  exports: [
    AuthenticateReadService,
    UserWriteService,
    AdminWriteService,
    AuthWriteService,
    PendingContactService,
  ],
})
export class AuthenticationModule {}
