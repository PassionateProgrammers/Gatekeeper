# Gatekeeper – Software Design Document

## 1. Design Overview

Gatekeeper is designed as a single, long-running backend service that acts as an API gateway in front of application endpoints. Its primary responsibility is to validate incoming HTTP requests before they reach backend business logic.

The design prioritizes:
- Clear separation of concerns
- Deterministic request handling order
- Simplicity over enterprise-scale complexity
- Testability and local reproducibility

This document describes the internal structure of the system, how components interact, and the rationale behind major design decisions.

## 2. High-Level Architecture

### 2.1 Architectural Style

Gatekeeper follows a modular monolithic architecture:
- A single deployable service
- Internally decomposed into well-defined modules

This approach avoids unnecessary operational complexity while preserving clean boundaries between responsibilities.

### 2.2 Core Components

At a high level, the system consists of:
- HTTP Server
- Authentication Module
- Rate Limiting Module
- Request Handler
- Usage Logging Module
- Admin API
- External dependencies (Redis and Postgres)

## 3. Component Design

### 3.1 HTTP Server & Routing

The HTTP server is responsible for:
- Accepting incoming HTTP connections
- Assigning a unique request ID
- Routing requests to either:
  - Gateway (data plane) endpoints
  - Admin (control plane) endpoints

Routing rules clearly separate public gateway traffic from administrative operations.

### 3.2 Authentication Module

Responsibilities:
- Extract API key from `Authorization: Bearer <key>` header
- Hash and compare the API key against stored values
- Resolve the API key to a tenant
- Reject invalid or revoked API keys

Design notes:
- API keys are stored in hashed form
- Key comparison uses constant-time operations
- Authentication occurs before any other request processing

### 3.3 Rate Limiting Module

Responsibilities:
- Enforce per-API-key request limits
- Support burst traffic above steady-state limits
- Reject excess requests with HTTP 429

Implementation approach:
- Token bucket or sliding window algorithm
- Redis used as a centralized state store
- Rate-limit checks occur after authentication but before request handling

Failure behavior:
- Redis failure behavior (fail-open or fail-closed) is configurable

### 3.4 Request Handling

Responsibilities:
- Forward authenticated and permitted requests to downstream handlers
- Measure request latency
- Attach request ID to logs and responses

This module represents the execution path for requests that pass all gateway checks.

### 3.5 Usage Logging & Analytics

Responsibilities:
- Record request metadata including:
  - API key identifier
  - Tenant
  - Endpoint
  - Timestamp
  - HTTP status code
  - Request latency
- Persist usage data to Postgres
- Support aggregation queries for analytics

Design notes:
- Logging is synchronous but lightweight
- Analytics are computed at query time

### 3.6 Admin & Metrics API

Responsibilities:
- Create and revoke API keys
- Query usage metrics by tenant and time window
- Expose health and diagnostics endpoints

Admin APIs are logically separated from gateway traffic.

## 4. Request Lifecycle

A typical request flows through the system as follows:
- HTTP request is received
- A unique request ID is generated
- API key is extracted from headers
- Authentication module validates the key
- Rate limiting module checks allowance
- Request is forwarded to the handler
- Response is returned to the client
- Usage metadata is recorded

If any step fails, the request is immediately rejected with the appropriate HTTP status code.

## 5. API Design

### 5.1 Authentication Model

- API keys are passed using `Authorization: Bearer <key>`
- Each API key maps to exactly one tenant
- API keys can be revoked at any time

### 5.2 Gateway Endpoints (Data Plane)

These endpoints represent requests subject to authentication and rate limiting.

Common characteristics:
- Require a valid API key
- Enforced rate limits
- Usage logging enabled

Exact endpoint definitions are implementation-defined and documented alongside the code.

### 5.3 Admin Endpoints (Control Plane)

Examples include:
- Create API key
- Revoke API key
- Query usage statistics
- Health checks

Admin endpoints are not accessible to standard API clients.

### 5.4 Error Model

All error responses return structured JSON containing:
- HTTP status code
- Error type
- Human-readable message
- Request ID

## 6. Data Flow & Storage

### 6.1 Redis

Used for:
- Rate limiting counters
- Short-lived, mutable state

Data stored in Redis is considered ephemeral.

### 6.2 Postgres

Used for:
- API key metadata
- Tenant records
- Usage logs

Postgres provides durable storage and supports analytical queries.

## 7. Key Design Decisions & Tradeoffs

### 7.1 API Keys vs OAuth

API keys were chosen for simplicity, clarity, and suitability for machine-to-machine communication.

### 7.2 Single Service Design

A single service simplifies deployment and debugging while remaining sufficient for the project scope.

### 7.3 Query-Time Analytics

Analytics are computed at query time to avoid the complexity of streaming pipelines.

## 8. Traceability

This design document supports:
- Functional requirements defined in the SRS
- Non-functional requirements for performance, security, and maintainability

Each major design component maps to one or more functional requirements.
