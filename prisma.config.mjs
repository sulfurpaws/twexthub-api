import { defineConfig } from '@prisma/config';
import { PrismaPg } from '@prisma/adapter-pg';

const url = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/twexthub';

export default defineConfig({
  schema: './prisma/schema.prisma',
  migrations: { path: './prisma/migrations' },
  datasource: { url },
});
