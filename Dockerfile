# syntax=docker/dockerfile:1.14.0
ARG NODE_VERSION=24.10.0

# ---------------------------------------------------------------------------------------
# Stage 0: base
# ---------------------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS base
WORKDIR /home/node

# Aktiviert Corepack (für pnpm)
RUN corepack enable pnpm

USER node

# ---------------------------------------------------------------------------------------
# Stage 1: dist (Build)
# ---------------------------------------------------------------------------------------
FROM base AS dist

COPY --chown=node:node package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts

COPY --chown=node:node . .
RUN pnpm run build


# ---------------------------------------------------------------------------------------
# Stage 2: dependencies (Production Only)
# ---------------------------------------------------------------------------------------
FROM base AS dependencies

COPY --chown=node:node package.json pnpm-lock.yaml ./
RUN pnpm install --prod --frozen-lockfile --ignore-scripts

# ---------------------------------------------------------------------------------------
# Stage 3: final
# ---------------------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS final

ARG NODE_VERSION
ARG APP_NAME
ARG APP_VERSION
ARG CREATED
ARG REVISION

LABEL org.opencontainers.image.title="omnixys-${APP_NAME}-service" \
      org.opencontainers.image.description="Omnixys ${APP_NAME}-service – Node.js ${NODE_VERSION}, gebaut mit TypeScript, Version ${APP_VERSION}, basiert auf Debian Bookworm." \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.vendor="omnixys" \
      org.opencontainers.image.authors="caleb.gyamfi@omnixys.com" \
      org.opencontainers.image.base.name="node:${NODE_VERSION}-bookworm-slim" \
      org.opencontainers.image.url="https://github.com/omnixys/omnixys-${APP_NAME}-service" \
      org.opencontainers.image.source="https://github.com/omnixys/omnixys-${APP_NAME}-service" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.documentation="https://github.com/omnixys/omnixys-${APP_NAME}-service/blob/main/README.md"

WORKDIR /opt/app
RUN apt-get update && \
    apt-get install -y --no-install-recommends dumb-init wget && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/*


RUN corepack enable pnpm

# Node-User
USER node

# Node modules + dist aus vorherigen Builds übernehmen
COPY --from=dependencies --chown=node:node /home/node/node_modules ./node_modules
COPY --from=dist --chown=node:node /home/node/dist ./dist
COPY --chown=node:node package.json ./

EXPOSE 3000
ENTRYPOINT ["dumb-init", "pnpm", "start"]
