import { paths } from '../../config/keycloak.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { KafkaProducerService } from '../../messaging/kafka-producer.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import { KCSignUpDTO } from '../models/dtos/kc-sign-up.dto.js';
import { RealmRole } from '../models/enums/role.enum.js';
import { TokenPayload } from '../models/payloads/token.payload.js';
import { AdminWriteService } from './admin-write.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, NotFoundException } from '@nestjs/common';

@Injectable()
export class RegisterService extends AuthenticateBaseService {
  constructor(
    logger: LoggerPlusService,
    trace: TraceContextProvider,
    http: HttpService,
    private readonly kafka: KafkaProducerService,
    private authService: AuthWriteService,
    private adminService: AdminWriteService,
  ) {
    super(logger, trace, http);
  }

  async signUp(input: KCSignUpDTO): Promise<TokenPayload> {
    return this.withSpan('authentication.signUp', async (span) => {
      void this.logger.debug('signUp: input=%o', input);

      const { firstName, lastName, email, username, password } = input;

      const credentials: Array<Record<string, string | undefined | boolean>> = [
        { type: 'password', value: password, temporary: false },
      ];

      const body = {
        username,
        enabled: true,
        firstName,
        lastName,
        email,
        credentials,
      };

      await this.kcRequest('post', paths.users, {
        data: body,
        headers: await this.adminJsonHeaders(),
      });

      // id ermitteln
      const userId = await this.findUserIdByUsername(username);
      if (!userId) {
        throw new NotFoundException('User id could not be resolved after signUp');
      }

      // Rolle zuweisen
      await this.adminService.assignRealmRoleToUser(userId, RealmRole.USER);

      const sc = span.spanContext();

      void this.kafka.addUserId({ newId: userId, oldId: input.id }, 'authentication.userSignUp', {
        traceId: sc.traceId,
        spanId: sc.spanId,
      });

      const token = await this.authService.login({ username, password });
      return token;
    });
  }
}
