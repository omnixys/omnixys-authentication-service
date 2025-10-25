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
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
// src/messaging/handlers/user.handler.ts
import { AddTicketDTO } from '../auth/models/dtos/add-ticket.dto.js';
import { SignUpDTO } from '../auth/models/dtos/sign-up.dto.js';
import { PhoneKind } from '../auth/models/enums/phone-kind.enum.js';
import { PhoneNumberInput } from '../auth/models/inputs/phone-number.input.js';
import { AdminWriteService } from '../auth/services/admin-write.service.js';
import { UserWriteService } from '../auth/services/user-write.service.js';
import { getLogger } from '../logger/logger.js';
import {
  KafkaEvent,
  KafkaHandler,
} from '../messaging/decorators/kafka-event.decorator.js';
import {
  KafkaEventContext,
  KafkaEventHandler,
} from '../messaging/interface/kafka-event.interface.js';
import { KafkaTopics } from '../messaging/kafka-topic.properties.js';
import { PendingContactService } from '../redis/pending-contact.service.js';
import { Injectable } from '@nestjs/common';

@KafkaHandler('user')
@Injectable()
export class UserHandler implements KafkaEventHandler {
  private readonly logger = getLogger(UserHandler.name);

  constructor(
    private readonly userService: UserWriteService,
    private readonly adminService: AdminWriteService,
    private readonly pending: PendingContactService,
  ) {}

  @KafkaEvent(
    KafkaTopics.auth.create,
    KafkaTopics.auth.delete,
    KafkaTopics.auth.addAttribute,
  )
  async handle(
    topic: string,
    data: any,
    context: KafkaEventContext,
  ): Promise<void> {
    console.debug(`Person-Kommando empfangen: ${topic}`);
    console.debug('Kontext: %o', context);

    switch (topic) {
      case KafkaTopics.auth.create:
        await this.create(data);
        break;
      case KafkaTopics.auth.addAttribute:
        await this.addTicket(data);
        break;
    }
  }

  private async create(data: { payload: SignUpDTO }) {
    this.logger.debug('CreateUserHandler: data=%o', data);
    let email: string | undefined;
    let phoneNumbers: PhoneNumberInput[] | undefined;

    const { pendingContactId, invitationId } = data.payload;
    if (pendingContactId) {
      const pc = await this.pending.get(pendingContactId);
      if (pc) {
        email = pc.email;
        // PendingContactService speichert `phones`
        phoneNumbers = await this.normalizePhones(pc?.phoneNumbers);
        await this.pending.del(pendingContactId).catch(() => void 0);
      } else {
        this.logger.warn(
          'pending contact missing for invitation=%s (TTL abgelaufen?)',
          invitationId,
        );
      }
    } else {
      this.logger.warn('no pendingContactId for invitation=%s', invitationId);
    }

    this.logger.debug(
      '[Handler] create: email=%s, phoneNumbers=%o',
      email ?? '',
      phoneNumbers ?? [],
    );
    const input = data.payload;
    input.email = email;
    input.phoneNumbers = phoneNumbers;
    await this.userService.signUp(input);
  }

  private async addTicket(data: { payload: AddTicketDTO }) {
    this.logger.debug('[Handler]addTicket: payload=%o', data.payload);
    const { userId, mode, ticketId } = data.payload;
    await this.adminService.addAttributes({
      userId,
      mode,
      attributes: { ticketIds: ticketId },
    });
  }

  private async normalizePhones(
    arr?: Array<{ kind: string | PhoneKind; value: string }>,
  ): Promise<PhoneNumberInput[]> {
    const ALLOWED = new Set(Object.values(PhoneKind));
    const out: PhoneNumberInput[] = [];
    for (const p of arr ?? []) {
      const kind = String(p.kind ?? '')
        .toUpperCase()
        .trim();
      const value = String(p.value ?? '').trim();
      if (!ALLOWED.has(kind as PhoneKind)) {
        continue;
      }
      if (!value) {
        continue;
      }
      out.push({ kind: kind as PhoneKind, value });
    }
    return out;
  }
}
