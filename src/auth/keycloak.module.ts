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

// TODO eslint kommentare lösen
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { KafkaModule } from '../messaging/kafka.module.js';
import { AdminMutationResolver } from './resolvers/admin-mutation.resolver.js';
import { AuthMutationResolver } from './resolvers/auth-mutation.resolver.js';
import { AuthQueryResolver } from './resolvers/auth-query.resolver.js';
import { UserMutationResolver } from './resolvers/user-mutation.resolver.js';
import { AdminWriteService } from './services/admin-write.service.js';
import { AuthWriteService } from './services/auth-write.service.js';
import { KeycloakReadService } from './services/read.service.js';
import { UserWriteService } from './services/user-write.service.js';
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard, KeycloakConnectModule, RoleGuard } from 'nest-keycloak-connect';

@Module({
  imports: [KafkaModule],
  providers: [KeycloakReadService, UserWriteService, AdminWriteService, AuthWriteService],
  exports: [KeycloakReadService, UserWriteService, AdminWriteService, AuthWriteService],
})
class ConfigModule {}

@Module({
  imports: [
    KafkaModule,
    KeycloakConnectModule.registerAsync({
      useExisting: KeycloakReadService,
      imports: [ConfigModule],
    }),
  ],
  providers: [
    KeycloakReadService,
    UserWriteService,
    AdminWriteService,
    AuthWriteService,
    AuthQueryResolver,
    AuthMutationResolver,
    UserMutationResolver,
    AdminMutationResolver,
    {
      // fuer @UseGuards(AuthGuard)
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    {
      // fuer @Roles({ roles: ['admin'] }) einschl. @Public() und @AllowAnyRole()
      provide: APP_GUARD,
      useClass: RoleGuard,
    },
  ],
  exports: [
    KeycloakConnectModule,
    KeycloakReadService,
    UserWriteService,
    AdminWriteService,
    AuthWriteService,
  ],
})
export class KeycloakModule {}
