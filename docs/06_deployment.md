# Gatekeeper - Deployment Guide

## 1. Purpose

This document describes the deployment process, environment requirements, and configuration needed to run the Gatekeeper API Gateway.  

It ensures developers and testers can reliably start, configure, and operate the system in a reproducible manner.

---

## 2. Deployment Environments

| Environment | Purpose | Notes |
|------------|---------|-------|
| Local | Development and testing | Uses Docker Compose |
| Staging | Pre-production testing | Optional, mirrors production configuration |
| Production | Public-facing API gateway | Not implemented in this POC, would require load balancing, TLS certs, monitoring |

---

## 3. System Requirements

### Hardware
- CPU: 2 cores minimum
- RAM: 4GB minimum
- Disk: 10GB free space

### Software
- Docker 24+  
- Docker Compose 2+  
- PostgreSQL 15+ (or Docker container)  
- Redis 7+ (or Docker container)  
- Git (for cloning repo)  

---

## 4. Directory Structure

├─ docs/ # Project documentation
├─ diagrams/ # Architecture and sequence diagrams
├─ src/ # Source code
│ ├─ gateway/ # Gateway service
│ └─ admin/ # Admin endpoints (API key management, analytics)
├─ docker-compose.yml # Local container setup
├─ Dockerfile # Gateway Docker image
└─ README.md

---

## 5. Configuration

Gatekeeper supports environment variables for configuration:

| Variable | Purpose | Example |
|----------|---------|---------|
| `POSTGRES_HOST` | Host for Postgres DB | `localhost` |
| `POSTGRES_PORT` | Port for Postgres | `5432` |
| `POSTGRES_USER` | DB username | `gatekeeper_user` |
| `POSTGRES_PASSWORD` | DB password | `securepass` |
| `REDIS_HOST` | Host for Redis | `localhost` |
| `REDIS_PORT` | Port for Redis | `6379` |
| `RATE_LIMIT_MAX` | Maximum requests per window | `100` |
| `RATE_LIMIT_WINDOW` | Window duration in seconds | `60` |

---

## 6. Deployment Steps

### 6.1 Local Deployment (Docker Compose)

1. Clone the repository:

    ```bash
    git clone https://github.com/PassionateProgrammers/Gatekeeper.git
    cd Gatekeeper

2. Build and start containers:
    docker-compose up --build

3. Verify services:
    - Gateway: http://localhost:8080/health

    - Redis: Check logs in docker-compose

    - Postgres: Connect using a DB client

    - Run sample requests

### 6.2 Manual Deployment (Optional)

1. Install dependencies (Python/Node/etc. depending on implementation)

2. Configure environment variables

3. Start gateway service:
python3 src/gateway/main.py

---

## 7. Upgrades & Maintenance

- Update Docker image:
    docker-compose build
    docker-compose up -d

- Database migrations: Use included migration scripts (if any)

- Rotate API keys regularly

- Monitor logs for errors or unusual activity

---

## 8. Rollback Plan

- Keep previous Docker image tags

- Restore Postgres snapshot if required

- Stop new container and restart old container:
docker-compose down
docker-compose up -d --no-build

---

## 9. Monitoring

- Health endpoint: /health

- Logs: Stdout captured by Docker

- Metrics (optional): Expose /metrics endpoint for Prometheus or similar

---

## 10. Notes

- For production deployment, TLS, authentication proxies, and load balancers are required.

- The current deployment is intended for development and proof-of-concept testing only.
