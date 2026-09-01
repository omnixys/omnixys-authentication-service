-- AlterTable
ALTER TABLE "auth_user" ADD COLUMN     "keycloak_sub" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "auth_user_keycloak_sub_key" ON "auth_user"("keycloak_sub");

