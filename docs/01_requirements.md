# Gatekeeper - Software Requirements Specification

## 1. Introduction

### 1.1 Purpose
The SRS document defines the functional and non-functional requirements for Gatekeeper.

### 1.2 Intended Audience
- Developers using gatekeeper.

### 1.3 Definitions
- **API**: Application Programming Interface allows applications to communicate and exchange data with each other. 
- **Tenant**: An owner of one or more API keys.
- **API Key**: A secret token used to authenticate requests made to an API.
- **Rate Limit**: A limit as to how many request can be made to an API per key over a period of time.
- **Gateway**: The service thats responsible for validating requests before processing.

## Overall Description

### 2.1 System Context
Gatekeeper is located in the backend and serves as middleware between the API and the front end. Requests are authenticated, rate limited, logged, and either accepted or denied using the appropriate HTTP code.

### 2.2 User Classes

- **Admin**: Can create/revoke API keys and query usage analytics.
- **Client**: Uses an API key to make requests through the gateway.

### 2.3 Assumptions

- Requests are HTTP based.
- Clients include API key with each request.
- Redis and Postgres are available and can be accessed by the gateway.

## 3. Functional Requirements

### 3.1 Authentication
- **FR-1**: The system shall authenticate requests using an API key provided by the "Authorization: Bearer <key>" header.
- **FR-2**: The system shall reject requests that are missing an API key with HTTP 401.
- **FR-3**: The system shall reject requests invalid keys with HTTP 401
- **FR-4**: API keys should be associate with exactly one tenant.

### 3.2 API Key Management
- **FR-5**: The system shall allow admins to create new API keys for tenants.
- **FR-6**: The system shall allow admins to revoke API keys.
- **FR-7**: Revoked API keys shall immediately stop authorizing requests.
- **FR-8**: API keys must be stored in a hashed form.

### 3.3 Rate Limiting
- **FR-9**: The system shall enforce per-API-key rate limits.
- **FR-10**: Rate limits shall support burst traffic up to a configured maximum.
- **FR-11**: Requests exceeding the configured rate limit shall be rejected with HTTP 429.
- **FR-12**: Rate limit checks shall occur before request handling logic.
- **FR-13**: Rate limit state shall be stored in Redis.

### 3.4 Request Handling
- **FR-14**: Authenticated and permitted requests shall be forwarded to the request handler.
- **FR-15**: Each request shall be assigned a unique request ID for traceability.
- **FR-16**: The system shall return structured JSON error responses.

### 3.5 Usage Logging & Analytics
- **FR-17**: The system shall record request metadata including:
  - API key identifier
  - Timestamp
  - Endpoint
  - HTTP status code
  - Request latency
- **FR-18**: The system shall expose admin endpoints to retrieve usage statistics by tenant and time window.
- **FR-19**: Usage data shall support aggregation (counts, error rates).

### 3.6 Health & Observability
- **FR-20**: The system shall expose a health endpoint for liveness checks.
- **FR-21**: The system shall log authentication failures and rate-limit violations.

## 4. Non-Functional Requirements

### 4.1 Performance
- **NFR-1**: Authentication and rate-limit checks shall complete within 10ms at p95 under local load testing.
- **NFR-2**: The gateway shall support burst traffic of up to 1,000 requests per second in test scenarios.

### 4.2 Reliability
- **NFR-3**: If Redis is unavailable, the system shall fail closed (reject requests) or fail open (allow requests) according to a documented configuration setting.
- **NFR-4**: Revoked keys shall take effect without requiring service restarts.

### 4.3 Security
- **NFR-5**: API keys shall never be logged in plaintext.
- **NFR-6**: Key comparisons shall be resistant to timing attacks.
- **NFR-7**: Input data shall be validated to prevent injection attacks.

### 4.4 Maintainability
- **NFR-8**: The system shall follow a modular architecture with clear separation of concerns.
- **NFR-9**: Core logic shall be covered by automated tests.

### 4.5 Portability
- **NFR-10**: The system shall be runnable locally using Docker Compose.

## 5. Constraints
- The system shall be implemented using a single gateway service.
- Redis shall be used for rate limiting state.
- Postgres shall be used for durable data storage.

## 6. Out of Scope
- OAuth or third-party identity providers
- Billing or payment processing
- Web-based dashboards or UI clients
- Multi-region or high-availability deployment

## 7. Traceability
Each functional requirement (FR) shall be traceable to:
- Architecture components
- API endpoints
- Test cases defined in `docs/06_test_plan.md`