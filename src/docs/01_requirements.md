# Gatekeeper – Software Requirements Specification (Revised)

## 1. Introduction

### 1.1 Purpose  
This Software Requirements Specification (SRS) defines the functional and non-functional requirements for Gatekeeper, an API key–based gateway service.

### 1.2 Intended Audience  
- Developers integrating applications behind Gatekeeper  
- Administrators managing tenants, API keys, and usage analytics  

### 1.3 Definitions  

- **API**: Application Programming Interface allowing applications to communicate and exchange data.  
- **Tenant**: An owner of one or more API keys.  
- **API Key**: A secret token used to authenticate requests made to the API.  
- **Rate Limit**: A maximum number of requests allowed per API key within a configured time window.  
- **Gateway**: The service responsible for validating and regulating incoming requests before they reach application endpoints.

---

## 2. Overall Description

### 2.1 System Context  

Gatekeeper runs as a standalone backend server positioned in front of protected application endpoints.

Incoming requests pass through:
- Authentication  
- Rate limiting  
- Request logging  

Requests are then either:
- Accepted and processed by the application endpoint  
- Rejected with an appropriate HTTP response  

Gatekeeper exposes:

- **Gateway APIs** for client request handling  
- **Admin APIs** for configuration and analytics  

---

### 2.2 User Classes  

- **Admin**
  - Can create and revoke API keys  
  - Can configure rate limits  
  - Can query usage analytics  
  - Can manage IP blocking  

- **Client**
  - Uses an API key to make requests through the gateway  

---

### 2.3 Assumptions  

- Requests are HTTP-based.  
- Clients include an API key in the `Authorization: Bearer <key>` header.  
- Redis and Postgres are available to the gateway service.  

---

# 3. Functional Requirements

## 3.1 Authentication

- **FR-1**: The system shall authenticate requests using an API key provided in the `Authorization: Bearer <key>` header.  
- **FR-2**: The system shall reject requests missing an API key with HTTP 401.  
- **FR-3**: The system shall reject requests with invalid or revoked API keys with HTTP 401.  
- **FR-4**: Each API key shall be associated with exactly one tenant.  

---

## 3.2 API Key Management

- **FR-5**: The system shall allow admins to create new API keys for tenants.  
- **FR-6**: The system shall allow admins to revoke API keys.  
- **FR-7**: Revoked API keys shall immediately stop authorizing requests.  
- **FR-8**: API keys shall be stored in hashed form in the database.  
- **FR-9**: The system shall allow admins to configure per-key rate limits.  

---

## 3.3 Rate Limiting

- **FR-10**: The system shall enforce per-API-key rate limits.  
- **FR-11**: Requests exceeding the configured rate limit shall be rejected with HTTP 429.  
- **FR-12**: Rate limit checks shall occur before request handler logic is executed.  
- **FR-13**: Rate limit state shall be stored in Redis.  

---

## 3.4 Request Handling

- **FR-14**: Authenticated and permitted requests shall be processed by the protected endpoint handler.  
- **FR-15**: Each request shall be assigned a unique request ID for traceability.  
- **FR-16**: The system shall return structured JSON error responses.  

---

## 3.5 Usage Logging & Analytics

- **FR-17**: The system shall record request metadata including:
  - Tenant identifier  
  - API key identifier  
  - Timestamp  
  - HTTP method  
  - Endpoint path  
  - HTTP status code  
  - Request latency  
  - Client IP address  
  - Request ID  

- **FR-18**: The system shall expose admin endpoints to retrieve usage statistics by tenant and time window.  
- **FR-19**: Usage data shall support aggregation including:
  - Request counts  
  - Error counts  
  - Error rates  
  - Status code breakdowns  
  - Top endpoints  
  - Rate-limited request counts  

---

## 3.6 Abuse & IP Blocking

- **FR-20**: The system shall allow admins to manually block client IP addresses.  
- **FR-21**: Blocked IPs shall be stored in Redis with a configurable expiration (TTL).  
- **FR-22**: The system shall allow admins to unblock IP addresses.  
- **FR-23**: The system shall provide endpoints to list active blocked IPs.  
- **FR-24**: The system shall record block and unblock events for audit purposes.  

---

## 3.7 Health & Observability

- **FR-25**: The system shall expose a health endpoint for liveness checks.  
- **FR-26**: The system shall record authentication failures and rate-limit violations in usage logs.  

---

# 4. Non-Functional Requirements

## 4.1 Reliability

- **NFR-1**: Revoked API keys shall take effect without requiring service restarts.  
- **NFR-2**: Rate limiting and IP blocking state shall be maintained in Redis.  
- **NFR-3**: Durable data (tenants, API keys, usage logs) shall be stored in Postgres.  

---

## 4.2 Security

- **NFR-4**: API keys shall not be stored in plaintext in the database.  
- **NFR-5**: API keys shall not be logged in plaintext in server logs.  
- **NFR-6**: Input data shall be validated using structured request models.  

---

## 4.3 Maintainability

- **NFR-7**: The system shall follow a modular architecture with separation of:
  - Routing  
  - Dependencies  
  - Middleware  
  - Data models  
  - Configuration  

- **NFR-8**: The system shall include automated tests for core authentication and rate limiting behavior.  

---

## 4.4 Portability

- **NFR-9**: The system shall be runnable locally using Docker Compose.  

---

# 5. Constraints

- The system shall be implemented as a single gateway service.  
- Redis shall be used for rate limiting and block state.  
- Postgres shall be used for durable data storage.  

---

# 6. Out of Scope

- OAuth or third-party identity providers  
- Billing or payment processing  
- Multi-region or high-availability deployment  
- Guaranteed performance thresholds  

---

# 7. Traceability

Each functional requirement (FR) shall be traceable to:
- Architecture components  
- API endpoints  