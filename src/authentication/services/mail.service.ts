/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { LoggerPlus } from '../../logger/logger-plus.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { Injectable } from '@nestjs/common';
import { Resend } from 'resend';

@Injectable()
export class MailService {
  private readonly logger: LoggerPlus;
  private readonly resend: Resend;
  private readonly from: string;
  private readonly appBaseUrl: string;
  private readonly resetPath: string;

  constructor(private readonly loggerService: LoggerPlusService) {
    this.logger = this.loggerService.getLogger(this.constructor.name);
    this.resend = new Resend(process.env.RESEND_API_KEY);
    this.from = process.env.MAIL_FROM ?? 'no-reply@example.com';
    this.appBaseUrl = process.env.APP_BASE_URL ?? '';
    this.resetPath = process.env.RESET_PATH ?? '/reset-password';
  }

  /* -------------------------------------------------- */
  /* PASSWORD RESET                                    */
  /* -------------------------------------------------- */

  async sendResetEmail(email: string, rawToken: string): Promise<void> {
    const resetUrl = `${this.appBaseUrl}${this.resetPath}?token=${encodeURIComponent(rawToken)}`;

    try {
      await this.resend.emails.send({
        from: this.from,
        to: email,
        subject: 'Reset your password',
        html: this.buildResetHtml(resetUrl),
        text: this.buildResetText(resetUrl),
      });
    } catch (error: any) {
      this.logger.error('Failed to send reset email', {
        email,
        error: error?.message,
      });
      throw error;
    }
  }

  /* -------------------------------------------------- */
  /* TEMPLATE BUILDERS                                 */
  /* -------------------------------------------------- */

  private buildResetHtml(resetUrl: string): string {
    return `
      <div style="font-family: Arial, sans-serif;">
        <h2>Password Reset</h2>
        <p>You requested to reset your password.</p>
        <p>This link expires in 15 minutes.</p>
        <a href="${resetUrl}" 
           style="display:inline-block;padding:10px 16px;background:#111;color:#fff;text-decoration:none;border-radius:6px;">
           Reset Password
        </a>
        <p>If you did not request this, ignore this email.</p>
      </div>
    `;
  }

  private buildResetText(resetUrl: string): string {
    return `
Password Reset

You requested to reset your password.
This link expires in 15 minutes.

Reset here:
${resetUrl}

If you did not request this, ignore this email.
`;
  }
}
