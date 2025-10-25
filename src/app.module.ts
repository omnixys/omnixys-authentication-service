// TODO eslint kommentare lösen
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
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

// import { graphQlModuleOptions } from './config/graphql.js';
import { KeycloakModule } from './auth/keycloak.module.js';
import { HandlerModule } from './handlers/handler.module.js';
import { HealthModule } from './health/health.module.js';
import { LoggerModule } from './logger/logger.module.js';
import { RequestLoggerMiddleware } from './logger/request-logger.middleware.js';
import { KafkaModule } from './messaging/kafka.module.js';
import { RedisModule } from './redis/redis.module.js';
import { ApolloFederationDriver, ApolloFederationDriverConfig } from '@nestjs/apollo';
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';

@Module({
  imports: [
    HealthModule,
    KeycloakModule,
    LoggerModule,
    KafkaModule,
    HandlerModule,
    RedisModule,
    // GraphQLModule.forRoot<ApolloDriverConfig>(graphQlModuleOptions),
    ConfigModule.forRoot({ isGlobal: true }),
    GraphQLModule.forRootAsync<ApolloFederationDriverConfig>({
      driver: ApolloFederationDriver,

      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => ({
        // autoSchemaFile: join(process.cwd(), 'dist/schema.gql'),
        autoSchemaFile:
          process.env.SCHEMA_TARGET === 'tmp'
            ? { path: '/tmp/schema.gql', federation: 2 }
            : process.env.SCHEMA_TARGET === 'false'
              ? false
              : { path: 'dist/schema.gql', federation: 2 },
        sortSchema: true,
        playground: cfg.get('GRAPHQL_PLAYGROUND') === 'true',
        csrfPrevention: false,
        introspection: true,
        context: ({ req, res }: { req: Request; res: Response }) => ({
          req,
          res,
        }),
      }),
    }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(RequestLoggerMiddleware).forRoutes('*');
  }
}
