import { PrismaClient } from '../src/prisma/generated/client.js';
import { PrismaPg } from '@prisma/adapter-pg';
import 'dotenv/config';

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter });

async function main() {
  const authUserCount = await prisma.authUser.count();

  const result = {
    service: 'authentication',
    checks: [
      { name: 'Authentication Users', ok: authUserCount > 0, count: authUserCount },
    ],
  };

  console.log('VALIDATE_JSON:' + JSON.stringify(result));
}

main()
  .catch((e) => {
    console.error('❌ Validate failed', e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
