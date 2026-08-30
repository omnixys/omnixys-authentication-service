import { env } from '../../config/env.js';
import { MailTokenService, type MailTokenResponse } from './mail-token.service.js';
import {
  BadRequestException,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { HeaderAuthGuard } from '@omnixys/security-ts';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { timingSafeEqual } from 'node:crypto';

@Controller('internal/mail')
export class MailTokenController {
  constructor(private readonly mailTokens: MailTokenService) {}

  @Post('token')
  @HttpCode(HttpStatus.OK)
  @UseGuards(HeaderAuthGuard)
  async issue(
    @Headers('authorization') authorization: string | undefined,
    @Headers('x-internal-token') internalToken: string | undefined,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<MailTokenResponse> {
    reply.header('cache-control', 'no-store').header('pragma', 'no-cache');
    if (!secureEqual(internalToken, env.INTERNAL_GATEWAY_TOKEN)) {
      throw new UnauthorizedException({
        code: 'INTERNAL_AUTHENTICATION_FAILED',
        message: 'Internal authentication failed',
      });
    }
    if (request.body !== undefined && request.body !== null) {
      throw new BadRequestException({
        code: 'MAIL_TOKEN_BODY_NOT_ALLOWED',
        message: 'Request body must be empty',
      });
    }
    const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) {
      throw new UnauthorizedException({
        code: 'UNAUTHENTICATED',
        message: 'Bearer token is required',
      });
    }
    return this.mailTokens.issue(token);
  }
}

function secureEqual(value: string | undefined, expected: string): boolean {
  if (!value || !expected) {
    return false;
  }
  const actualHash = Buffer.from(value);
  const expectedHash = Buffer.from(expected);
  return actualHash.length === expectedHash.length && timingSafeEqual(actualHash, expectedHash);
}
