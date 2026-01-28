# Test Plan: API Gateway

## 1. Purpose

This test plan defines the strategy and test cases used to validate the API Gateway’s:
- Authentication (API key validation)
- Rate limiting enforcement
- Security controls
- Reliability and availability

The goal is to ensure correct behavior under normal, edge, and adversarial conditions.

---

## 2. Scope

### In Scope
- API key validation
- Invalid and missing API key handling
- Rate limiting (per-key and per-IP)
- Error handling and status codes
- Request rejection behavior
- Logging and monitoring verification

### Out of Scope
- Backend service business logic
- UI or client-side behavior
- Third-party integrations beyond the gateway

---

## 3. Test Environment

- **Gateway**: API Gateway (local / cloud-based)
- **Protocol**: HTTPS
- **Test Tools**:
  - cURL / HTTPie
  - Postman
  - Load testing tool (e.g., k6, Locust)
- **Data Stores**:
  - API key store
  - Rate limit counters
- **Logging**:
  - Centralized logging enabled

---

## 4. Test Data

| Data Type | Description |
|---------|------------|
| Valid API Key | Active, non-expired key |
| Invalid API Key | Random or revoked key |
| Missing API Key | No key provided |
| Rate Limit Threshold | Configured max requests per window |
| Test IPs | Single IP and multiple IPs |

---

## 5. Test Scenarios & Cases

### 5.1 API Key Validation

#### TC-01: Valid API Key
- **Input**: Request with valid API key
- **Expected Result**:
  - Request is authenticated
  - Forwarded to backend
  - HTTP `200 OK`

#### TC-02: Missing API Key
- **Input**: Request without API key
- **Expected Result**:
  - Request rejected
  - HTTP `401 Unauthorized`
  - Generic error message

#### TC-03: Invalid API Key
- **Input**: Request with invalid API key
- **Expected Result**:
  - Request rejected early
  - HTTP `403 Forbidden`
  - No backend call made

---

### 5.2 Rate Limiting

#### TC-04: Below Rate Limit
- **Input**: Requests under configured limit
- **Expected Result**:
  - All requests succeed
  - HTTP `200 OK`

#### TC-05: Rate Limit Exceeded
- **Input**: Requests exceeding limit within time window
- **Expected Result**:
  - Request rejected
  - HTTP `429 Too Many Requests`
  - `Retry-After` header present

#### TC-06: Rate Limit Reset
- **Input**: Requests after window expiration
- **Expected Result**:
  - Requests succeed again
  - Rate counter resets

---

### 5.3 Abuse & Security Testing

#### TC-07: Invalid API Key Flood
- **Input**: High volume of requests with invalid keys
- **Expected Result**:
  - Early rejection
  - No backend saturation
  - Logs show spike in invalid keys

#### TC-08: Distributed Rate Limit Bypass Attempt
- **Input**: Requests from multiple IPs using same API key
- **Expected Result**:
  - Per-key limit enforced
  - Requests blocked when threshold reached

---

### 5.4 Error Handling

#### TC-09: Malformed Request
- **Input**: Invalid headers or malformed JSON
- **Expected Result**:
  - HTTP `400 Bad Request`
  - No internal error details exposed

#### TC-10: Backend Timeout
- **Input**: Backend service unavailable or slow
- **Expected Result**:
  - HTTP `502` or `504`
  - Request logged with correlation ID

---

## 6. Non-Functional Testing

### 6.1 Performance
- Validate gateway latency under normal load
- Measure response time during rate limit enforcement

### 6.2 Reliability
- Ensure gateway remains responsive under abusive traffic
- Verify backend isolation during DoS attempts

### 6.3 Security
- Confirm no sensitive data in logs
- Validate HTTPS enforcement
- Ensure consistent error responses

---

## 7. Logging & Monitoring Validation

- API key usage logged
- Rate limit violations logged
- Alert triggers on abuse thresholds
- Correlation IDs propagated

---

## 8. Exit Criteria

The test plan is considered complete when:
- All critical test cases pass
- No high or critical severity defects remain
- Security and rate limiting controls function as designed

---

## 9. Risks & Assumptions

### Risks
- Load testing may not fully simulate real-world attacks
- Misconfigured limits may impact legitimate users

### Assumptions
- API keys are securely generated and stored
- Gateway configuration matches production settings

---