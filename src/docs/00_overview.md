# Gatekeeper – Project Overview

## Purpose

Gatekeeper is a backend, server-based, multi-tenant API gateway that authenticates requests using API keys, enforces per-key rate limits, and records detailed usage metrics for analytics and operational insight.

Gatekeeper operates as a long-running HTTP service and exposes both:

- **Data plane APIs** for protected request handling  
- **Control plane APIs** for administration, configuration, and analytics  

---

## Problem Statement

Public-facing APIs must protect backend services from abuse, excessive load, and unauthorized access while also providing visibility into client behavior.

Without a gateway layer enforcing authentication, rate limiting, and observability:

- Backend services are vulnerable to denial-of-service scenarios  
- Malfunctioning or abusive clients can exhaust resources  
- Operators lack insight into usage patterns and errors  

Gatekeeper addresses these issues by providing a centralized authentication, rate-limiting, logging, and analytics layer.

---

## Goals

- Provide API key–based authentication for multi-tenant clients  
- Enforce per-key rate limits using Redis  
- Record structured usage events in Postgres  
- Expose admin endpoints for analytics and operational visibility  
- Support manual IP blocking and abuse mitigation  
- Be containerized and runnable locally via Docker Compose  
- Be testable and easy to evaluate through a demo script  

---

## Non-Goals

Gatekeeper does **not** aim to provide:

- Load balancing or TLS offloading  
- Web application firewall (WAF) functionality  
- OAuth or third-party identity providers  
- Service mesh features  
- Billing or payment processing  
- Multi-region or high-availability deployments  
- Enterprise-scale performance guarantees  

---

## Target Users

- Developers exposing public-facing APIs that require:
  - API key authentication  
  - Rate limiting  
  - Usage tracking  
  - Basic abuse mitigation  

- Administrators who need visibility into API consumption and client behavior  

---

## Scope

### In Scope

- Multi-tenant API key management  
- API key authentication via `Authorization: Bearer` header  
- Per-key rate limiting stored in Redis  
- Structured request logging with request IDs  
- Usage analytics endpoints (counts, error rates, top endpoints, rate-limited requests)  
- IP blocking with configurable TTL  
- Health endpoint for service monitoring  
- Docker-based local deployment  

### Out of Scope

- OAuth2 / OpenID Connect  
- Role-based access control (RBAC)  
- Streaming analytics  
- Immutable audit logs or compliance-grade audit guarantees  
- Enterprise-grade scaling architecture  

---

## Assumptions

- Deployment scale is moderate and suitable for proof-of-concept or small-to-mid APIs  
- Redis is available for rate limiting and IP block state  
- Postgres is available for durable storage  
- The system operates as a single gateway service  

---

## Success Criteria

The project is considered successful if:

- Requests with missing or invalid API keys are rejected with HTTP 401  
- Requests exceeding rate limits are rejected with HTTP 429  
- Revoked API keys immediately stop authorizing requests  
- Usage analytics endpoints return accurate metrics for a specified time window  
- IP block and unblock functionality works correctly  
- The system runs via Docker Compose without errors  
- Automated tests validate core authentication and rate limiting behavior  
- A demo script demonstrates authentication, rate limiting, analytics, and IP blocking  

---

## Deliverables

- Source code for the Gatekeeper service  
- Markdown documentation (requirements, overview, architecture)  
- Docker Compose configuration  
- Automated tests for core behaviors  
- Demo script showcasing system functionality  
- Video demonstration of the project  