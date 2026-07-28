/* eslint-disable @typescript-eslint/explicit-function-return-type */
import { AuthenticationInputException } from '../errors/authentication.error.js';
import { OAuthService } from '../services/o-auth.service.js';
import { Controller, Get, Param, Query, Res } from '@nestjs/common';
import { ClientInfo, type ClientContext } from '@omnixys/context';
import { FastifyReply } from 'fastify';
import { getLogger } from '@omnixys/logger';

const isProd = process.env.NODE_ENV === 'production';
const logger = getLogger('OAuthController');

@Controller('auth/oauth')
export class OAuthController {
  constructor(private readonly oauthService: OAuthService) {}

  /* =====================================================
     STEP 1 – Redirect to Provider
  ===================================================== */
  @Get(':provider')
  async redirect(@Param('provider') provider: string, @Res() reply: FastifyReply) {
    if (!['github', 'google'].includes(provider)) {
      logger.warn('oauth_unsupported_provider', { provider });
      throw new AuthenticationInputException('oauth-provider-unsupported');
    }

    logger.debug('oauth_redirect', { provider });
    const { url } = await this.oauthService.getAuthUrl(provider);

    reply.status(302).redirect(url);
  }

  /* =====================================================
     STEP 2 – Callback
  ===================================================== */
  @Get(':provider/callback')
  async callback(
    @ClientInfo() client: ClientContext,
    @Param('provider') provider: string,
    @Res() reply: FastifyReply,
    @Query('code') code?: string,
    @Query('state') state?: string,
    @Query('error') error?: string,
  ) {
    if (error) {
      logger.warn('oauth_callback_error', { provider, error });
      return reply.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
    }

    if (!code || !state) {
      logger.warn('oauth_parameters_missing', { provider, hasCode: !!code, hasState: !!state });
      throw new AuthenticationInputException('oauth-parameters-missing');
    }

    logger.debug('oauth_callback_success', { provider, userId: client.userId });
    const token = await this.oauthService.handleCallback(provider, code, state, client);
    /* -----------------------------
       Cookie setzen (Fastify!)
    ----------------------------- */
    reply.setCookie('access_token', token.accessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'lax' : 'lax',
      path: '/',
      maxAge: token.expiresIn,
    });

    reply.setCookie('refresh_token', token.refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'lax' : 'lax',
      path: '/',
      maxAge: token.refreshExpiresIn,
    });

    reply.status(302).redirect(`http://localhost:3000/home`);
  }
}
