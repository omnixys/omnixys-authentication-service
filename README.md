# 🛡️ Omnixys Auth Service

<p align="center">
  <img src="https://omnixys.com/assets/logo.png" width="150" alt="Omnixys Logo" />
</p>

---

## 📖 Table of Contents

- [🇬🇧 English Version](#-english-version)
  - [Overview](#overview)
  - [Features](#features)
  - [Tech Stack](#tech-stack)
  - [Folder Structure](#folder-structure)
  - [Environment Variables](#environment-variables)
  - [Setup & Installation](#setup--installation)
  - [Running the Server](#running-the-server)
  - [GraphQL Example](#graphql-example)
  - [Troubleshooting](#troubleshooting)
  - [Development Commands](#development-commands)
  - [Contributing](#contributing)a
  - [License & Contact](#license--contact)
- [🇩🇪 Deutsche Version](#-deutsche-version)
  - [Übersicht](#übersicht)
  - [Funktionen](#funktionen)
  - [Technologie-Stack](#technologie-stack)
  - [Projektstruktur](#projektstruktur)
  - [Umgebungsvariablen](#umgebungsvariablen)
  - [Installation & Setup](#installation--setup)
  - [Server Starten](#server-starten)
  - [GraphQL Beispiel](#graphql-beispiel)
  - [Fehlerbehebung](#fehlerbehebung)
  - [Entwicklungsbefehle](#entwicklungsbefehle)
  - [Mitwirken](#mitwirken)
  - [Lizenz & Kontakt](#lizenz--kontakt)

---

## 🇬🇧 English Version

### Overview
The **Omnixys Auth Service** is a secure authentication and authorization microservice built with **NestJS** and integrated with **Keycloak**, **Kafka**, **Redis**, and **Apollo Federation**.  
It manages user identities, token validation, and inter-service authentication across the Omnixys ecosystem.

---

### ✨ Features
- 🔑 Keycloak-based user management (OAuth2 / OpenID Connect)
- 🧩 GraphQL Federation (Apollo v4)
- ⚙️ Kafka Event Dispatcher integration
- 💾 Redis caching and token storage
- 📦 Modular architecture with NestJS
- 🧠 Strong type safety (TypeScript 5+)
- 🧾 Pino-based structured logging
- 🐳 Docker & Docker Compose ready

---

### 🧩 Tech Stack

| Layer | Technology |
|-------|-------------|
| Runtime | Node.js 22+ |
| Framework | NestJS 11 |
| Authentication | Keycloak 25+ |
| Message Broker | KafkaJS |
| Cache / Session | Redis |
| API Layer | Apollo Federation (GraphQL) |
| Logger | Pino |
| Package Manager | pnpm |
| Containerization | Docker |

---

### 📂 Folder Structure

```
auth/
├── src/
│   ├── auth/              # Keycloak integration, guards, and strategies
│   ├── config/            # Environment and Keycloak configuration
│   ├── handlers/          # Domain event handlers
│   ├── health/            # Health check endpoint
│   ├── kafka/             # Kafka event modules
│   ├── logger/            # Logger setup and middleware
│   ├── redis/             # Redis connection module
│   ├── main.ts            # Application bootstrap
│   └── app.module.ts      # Root module
├── .env.example           # Example environment file
├── docker-compose.yml     # Docker services
├── package.json
└── tsconfig.json
```

---

### ⚙️ Environment Variables

| Variable | Description | Default |
|-----------|-------------|----------|
| `NODE_ENV` | Environment mode (`development`, `production`) | `development` |
| `PORT` | Server port | `7501` |
| `KC_URL` | Keycloak base URL | `http://localhost:18080/auth` |
| `KC_REALM` | Keycloak realm | `camunda-platform` |
| `KC_CLIENT_ID` | Client ID | `camunda-identity` |
| `KC_CLIENT_SECRET` | Client secret | – |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |

---

### 🚀 Setup & Installation

```bash
# 1. Clone repository
git clone https://github.com/omnixys/auth-service.git
cd auth

# 2. Copy environment file
cp .env.example .env

# 3. Install dependencies
pnpm install
```

---

### 🏃 Running the Server

**Development:**
```bash
pnpm run start:dev
```

**Production:**
```bash
pnpm run build
pnpm run start:prod
```

Access GraphQL playground: [http://localhost:7501/graphql](http://localhost:7501/graphql)

---

### 🧠 GraphQL Example

```graphql
mutation Login {
  login(input: { username: "admin", password: "p" }) {
    accessToken
    refreshToken
    expiresIn
  }
}
```

---

### 🧩 Troubleshooting

| Problem | Solution |
|----------|-----------|
| Keycloak not reachable | Ensure `docker compose up` started and port `18080` is open |
| `.env` not loaded | Add `import dotenv from 'dotenv'; dotenv.config();` in `env.ts` |
| Input object empty `{}` | Add `@IsString()` and `@IsNotEmpty()` decorators to GraphQL InputType |
| `.tsbuildinfo` created | Use `rm -f tsconfig.build.tsbuildinfo && nest start --watch` |

---

### 🧰 Development Commands

```bash
# Run linter
pnpm run lint

# Format code
pnpm run format

# Run tests
pnpm run test
```

---

### 🤝 Contributing

1. Fork the repository  
2. Create a branch (`git checkout -b feature/my-feature`)  
3. Commit (`pnpm run lint && git commit -m "feat: add feature"`)  
4. Push & open a Pull Request  

---

### 🧾 License & Contact

Licensed under **GPL-3.0-or-later**  
© 2025 Caleb Gyamfi – Omnixys Technologies  
🌍 [omnixys.com](https://omnixys.com)  
📧 contact@omnixys.tech

---

## 🇩🇪 Deutsche Version

### Übersicht
Der **Omnixys Auth Service** ist ein sicherer Authentifizierungs- und Autorisierungs-Mikroservice auf Basis von **NestJS**, integriert mit **Keycloak**, **Kafka**, **Redis** und **Apollo Federation**.  
Er verwaltet Benutzeridentitäten, Token und Kommunikationssicherheit im gesamten Omnixys-Ökosystem.

---

### ✨ Funktionen
- 🔑 Keycloak-basierte Authentifizierung (OAuth2 / OIDC)
- 🧩 GraphQL Federation Unterstützung
- ⚙️ Kafka Event Dispatcher
- 💾 Redis für Cache & Tokens
- 📦 Modularer Aufbau mit NestJS
- 🧠 TypeScript 5+ für Typensicherheit
- 🧾 Pino-Logging
- 🐳 Docker-Unterstützung

---

### 🧩 Technologie-Stack
(siehe englische Version)

---

### 📁 Projektstruktur
(siehe Struktur oben)

---

### ⚙️ Umgebungsvariablen
(siehe Tabelle oben)

---

### 🚀 Installation & Setup

```bash
git clone https://github.com/omnixys/auth-service.git
cd auth
cp .env.example .env
pnpm install
```

---

### 🏃 Server Starten

**Entwicklung:**
```bash
pnpm run start:dev
```

**Produktion:**
```bash
pnpm run build
pnpm run start:prod
```

GraphQL Playground: [http://localhost:7501/graphql](http://localhost:7501/graphql)

---

### 🧠 GraphQL Beispiel

```graphql
mutation Login {
  login(input: { username: "admin", password: "p" }) {
    accessToken
    refreshToken
    expiresIn
  }
}
```

---

### 🧩 Fehlerbehebung

| Problem | Lösung |
|----------|---------|
| Keycloak nicht erreichbar | `docker compose up` starten und Port `18080` prüfen |
| `.env` wird nicht geladen | `dotenv.config()` in `env.ts` einfügen |
| Input bleibt leer `{}` | `@IsString()` und `@IsNotEmpty()` in InputType setzen |
| `.tsbuildinfo` Datei entsteht | `rm -f tsconfig.build.tsbuildinfo && nest start --watch` verwenden |

---

### 🧰 Entwicklungsbefehle

```bash
pnpm run lint
pnpm run format
pnpm run test
```

---

### 🤝 Mitwirken

1. Repository forken  
2. Branch erstellen (`git checkout -b feature/mein-feature`)  
3. Commit durchführen (`pnpm run lint && git commit -m "feat: neues feature"`)  
4. Pull Request öffnen  

---

### 🧾 Lizenz & Kontakt

Lizensiert unter **GPL-3.0-or-later**  
© 2025 Caleb Gyamfi – Omnixys Technologies  
🌍 [omnixys.com](https://omnixys.com)  
📧 contact@omnixys.tech
