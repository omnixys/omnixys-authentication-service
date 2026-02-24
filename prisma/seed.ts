import { PrismaClient, MfaPreference } from '../src/prisma/generated/client.js';
import { PrismaPg } from '@prisma/adapter-pg';
import 'dotenv/config';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter });
/**
 * Generates random backup codes and hashes them.
 */
async function generateBackupCodes(userId: string, amount = 5) {
  const codes: { codeHash: string; userId: string }[] = [];

  for (let i = 0; i < amount; i++) {
    const raw = randomBytes(4).toString('hex'); // 8 hex chars
    const hash = await argon2.hash(raw, {
      type: argon2.argon2id,
    });

    console.log(`Backup code for ${userId}:`, raw); // Only for initial seed visibility

    codes.push({
      codeHash: hash,
      userId,
    });
  }

  return codes;
}

async function main() {
  console.log('🌱 Seeding authentication schema...');

  /* =====================================================
     ADMIN
  ===================================================== */

  const admin = await prisma.authUser.upsert({
    where: { email: 'admin@omnixys.com' },
    update: {},
    create: {
      id: 'dde8114c-2637-462a-90b9-413924fa3f55',
      email: 'admin@omnixys.com',
      mfaPreference: MfaPreference.NONE,
    },
  });

  /* =====================================================
     CALEB (Full MFA example)
  ===================================================== */

  const caleb = await prisma.authUser.upsert({
    where: { email: 'caleb-script@outlook.de' },
    update: {},
    create: {
      id: '694d2e8e-0932-4c8f-a1c4-e300dc235be4',
      email: 'caleb-script@outlook.de',
      mfaPreference: MfaPreference.TOTP,
    },
  });

  /* =====================================================
     TOTP (disabled initially)
  ===================================================== */

  await prisma.totpCredential.upsert({
    where: { userId: caleb.id },
    update: {},
    create: {
      userId: caleb.id,
      encryptedSecret: 'SEED_PLACEHOLDER_ENCRYPTED_SECRET',
      enabled: false,
    },
  });

  /* =====================================================
     Backup Codes
  ===================================================== */

  const backupCodes = await generateBackupCodes(caleb.id);

  for (const code of backupCodes) {
    await prisma.backupCode.create({ data: code });
  }

  /* =====================================================
     Security Questions
  ===================================================== */

  const answerHash = await argon2.hash('omnixys', {
    type: argon2.argon2id,
  });

  await prisma.securityQuestion.createMany({
    data: [
      {
        userId: caleb.id,
        question: 'What is your favorite company?',
        answerHash,
      },
      {
        userId: caleb.id,
        question: 'Where were you born?',
        answerHash,
      },
    ],
  });

  console.log('✅ Authentication seed completed');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
