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

import { getLogger } from '../../logger/get-logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { RegisterService } from '../services/register.service.js';
import { UseInterceptors } from '@nestjs/common';
import { Args, Mutation, Resolver } from '@nestjs/graphql';

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class RegisterResolver {
  private readonly logger = getLogger(RegisterResolver.name);

  constructor(private readonly registerService: RegisterService) {}

  @Mutation(() => String)
  async verifySignUp(@Args('token') token: string): Promise<string> {
    this.logger.debug('Verify Registration');
    const { status } = await this.registerService.verifySignup(token);
    return status;
  }
}
