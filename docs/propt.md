You are a Senior Security Architect and Backend Engineer.

Generate a production-ready NestJS microservice called "AuthService" written in TypeScript using Prisma and PostgreSQL.

The service must:

1. Integrate with Keycloak via Admin REST API.
2. Implement a full password reset orchestration flow.
3. Support multiple MFA mechanisms:

   * Email reset link
   * TOTP (Google Authenticator)
   * WebAuthn / Passkeys
   * Backup codes
   * Security questions
4. Allow users to choose their preferred MFA method.
5. Implement rate limiting and lockout protection.
6. Use Prisma with a relational PostgreSQL schema.
7. Follow clean architecture principles.
8. Be modular and extensible.
9. Include:

   * Folder structure
   * Prisma schema
   * DTOs
   * Controllers
   * Services
   * Keycloak integration service
   * MFA modules
   * Validation
   * Example environment config
   * Example Docker setup
10. Ensure:

* Secure hashing (Argon2id)
* No plaintext secrets
* Single-use reset tokens
* Token expiry (15 minutes)
* Attempt tracking
* Session invalidation in Keycloak

The output should include:

* Project structure
* Complete Prisma schema
* Example service implementations
* API routes
* Security considerations
* Deployment guidance

Write the solution at enterprise production standard.