# ---------------------------------------------------------------------------------------
# 🧱 docker-bake.hcl – Omnixys Bake Setup
# ---------------------------------------------------------------------------------------
# Build orchestration for Omnixys Node-based microservices using HashiCorp Docker Bake.
# Aufruf mit docker buildx bake
# ---------------------------------------------------------------------------------------

variable "APP_NAME" {
  default = "authentication"
}

variable "APP_VERSION" {
  default = "1.0.0"
}

variable "NODE_VERSION" {
  default = "24.10.0"
}

variable "CREATED" {
  default = timestamp()
}

variable "REVISION" {
  default = "local-dev"
}

# ---------------------------------------------------------------------------------------
# Target Group
# ---------------------------------------------------------------------------------------

group "default" {
  targets = ["build"]
}

target "build" {
  dockerfile = "./Dockerfile"
  context = "."

  args = {
    NODE_VERSION = "${NODE_VERSION}"
    APP_NAME     = "${APP_NAME}"
    APP_VERSION  = "${APP_VERSION}"
    CREATED      = "${CREATED}"
    REVISION     = "${REVISION}"
  }

  labels = {
    "org.opencontainers.image.title"         = "omnixys-${APP_NAME}-service"
    "org.opencontainers.image.version"       = "${APP_VERSION}"
    "org.opencontainers.image.created"       = "${CREATED}"
    "org.opencontainers.image.revision"      = "${REVISION}"
    "org.opencontainers.image.source"        = "https://github.com/omnixys/omnixys-${APP_NAME}-service"
    "org.opencontainers.image.licenses"      = "GPL-3.0-or-later"
    "org.opencontainers.image.vendor"        = "omnixys"
    "org.opencontainers.image.authors"       = "caleb.gyamfi@omnixys.com"
  }

  tags = [
    "omnixys/${APP_NAME}-service:latest",
    "omnixys/${APP_NAME}-service:${APP_VERSION}"
  ]

platforms = ["linux/arm64"]
output = ["type=docker"]

}
