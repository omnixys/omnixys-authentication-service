# 📘 Projektbeschreibung – AuthService (Omnixys / Nexys Ecosystem)

## 🎯 Projektname

**Omnixys AuthService**

---

## 🏗 Ziel

Es soll ein eigenständiger, produktionsreifer **AuthService Microservice** entwickelt werden, der:

* Keycloak als Identity Provider nutzt
* Eine eigene PostgreSQL-Datenbank (via Prisma) verwaltet
* Erweiterte Authentifizierungs- und Recovery-Mechanismen implementiert
* MFA-Methoden verwaltet
* Passwort-Reset orchestration übernimmt
* Audit- und Security-Events unterstützt
* In eine Microservice-Architektur integrierbar ist

Der Service soll in **TypeScript** entwickelt werden und Prisma als ORM verwenden.

---

## 🧠 Architektur-Konzept

### 🔐 Verantwortlichkeiten

### Keycloak übernimmt:

* Benutzer-Credentials
* OAuth2 / OIDC Flows
* Access & Refresh Tokens
* Session Management
* Login

### AuthService übernimmt:

* Password Reset Flow
* Step-Up Authentication
* MFA Enrollment & Verification
* TOTP
* WebAuthn / Passkeys
* Backup Codes
* Sicherheitsfragen
* Lockout & Attempt Tracking
* Audit Logging
* MFA Preference Management
* Integration mit Keycloak Admin API

---

## 🛠 Technologie-Stack

* Sprache: TypeScript
* Framework: NestJS (empfohlen)
* ORM: Prisma
* Datenbank: PostgreSQL
* WebAuthn: @simplewebauthn/server
* TOTP: otplib
* Email: nodemailer oder SES
* Optional: Redis (Rate Limiting / Temporary Tokens)
* Optional: Kafka (Audit Events)

---

## 🗄 Datenbankmodell (High-Level)

### AuthUser

* id (UUID)
* keycloakUserId (unique)
* email (unique)
* mfaPreference (enum)
* createdAt
* updatedAt

### TotpCredential

* id
* secret
* enabled
* userId (unique)

### WebAuthnCredential

* id
* publicKey
* counter
* transports
* userId

### BackupCode

* id
* codeHash
* used
* userId

### SecurityQuestion

* id
* question
* answerHash
* userId

### PasswordResetToken

* id
* token
* expiresAt
* verified
* attempts
* userId

---

## 🔄 Funktionale Anforderungen

### 1️⃣ Passwort Reset

Flow:

1. User fordert Reset an
2. AuthService validiert Benutzer via Keycloak
3. Reset-Token wird generiert und gespeichert
4. Email mit Link wird versendet
5. Token-Verifikation
6. Step-Up MFA-Verifikation (abhängig von Benutzerpräferenz)
7. Passwort wird via Keycloak Admin API gesetzt
8. Alle Sessions werden invalidiert

---

### 2️⃣ Unterstützte MFA-Methoden

Der Benutzer kann später selbst wählen:

* NONE
* TOTP
* WebAuthn
* Backup Codes
* Security Questions

---

### 3️⃣ TOTP

* Secret generieren
* QR Code bereitstellen
* Erst nach erfolgreicher Verifikation aktivieren
* RFC 6238 kompatibel

---

### 4️⃣ WebAuthn / Passkeys

* Registration Challenge
* Verification
* Credential Speicherung
* Counter Validation
* Unterstützt:

  * FaceID
  * TouchID
  * Windows Hello
  * Passkeys

---

### 5️⃣ Backup Codes

* 10 Codes generieren
* Gehasht speichern
* Nach Nutzung invalidieren
* Regeneration möglich

---

### 6️⃣ Sicherheitsfragen

* Mindestens 3
* Antworten werden normalisiert + gehasht gespeichert
* Max 5 Fehlversuche pro Reset Token
* Token wird bei Überschreitung invalidiert

---

### 7️⃣ Lockout & Security

* 5 Versuche pro Reset-Token
* 10 Versuche pro Stunde pro User
* IP Rate Limiting
* Optional Redis Throttling
* Token max. 15 Minuten gültig
* Single-use Token

---

### 8️⃣ Keycloak Integration

Muss implementieren:

* Passwort setzen:
  PUT /admin/realms/{realm}/users/{id}/reset-password

* Logout All Sessions:
  POST /admin/realms/{realm}/users/{id}/logout

---

### 9️⃣ Audit Events

Optional Kafka Topics:

* auth.password.reset.requested
* auth.password.reset.completed
* auth.mfa.enabled
* auth.mfa.failed
* auth.account.locked

---

## 🔐 Sicherheitsanforderungen

* Niemals Klartext speichern
* Argon2id oder bcrypt verwenden
* Timing-safe Vergleiche
* CSRF Schutz
* Secure Cookies
* CORS Restriktionen
* Input Validation (Zod oder class-validator)
* Structured Logging
* Kein User Enumeration Leak