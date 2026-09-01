-- Phase 3: canonical identity switch (U/K)
-- AuthUser.id becomes the internal Omnixys UUIDv7 (U), generated once by PostgreSQL 18.
-- keycloak_sub (K) is now mandated: every identity is Keycloak-backed (U != K).

-- AlterTable
ALTER TABLE "auth_user" ALTER COLUMN "id" SET DEFAULT uuidv7();

-- AlterTable
ALTER TABLE "auth_user" ALTER COLUMN "keycloak_sub" SET NOT NULL;