# Threat Model: API Gateway

## 1. Overview

This document describes the threat model for an API Gateway responsible for:
- Authenticating requests via API keys
- Enforcing rate limits
- Routing requests to backend services
- Protecting backend systems from abuse and misuse

The goal is to identify threats, assess risk, and define mitigations.

---

## 2. System Description

### Components
- **Client**: External consumer making HTTP requests
- **API Gateway**
  - API key validation
  - Rate limiting
  - Request routing
  - Logging & monitoring
- **Backend Services**: Internal services behind the gateway
- **Data Store**: Stores API keys, rate limit counters, logs

### Trust Boundaries
- Internet → API Gateway
- API Gateway → Backend Services
- API Gateway → Data Store

---

## 3. Assets

| Asset | Description |
|-----|------------|
| API Keys | Credentials used to authenticate clients |
| Backend Services | Internal business logic and data |
| Rate Limit Counters | Controls usage and abuse |
| Logs | Security and audit data |
| Availability | Uptime of the API |

---

## 4. Threat Actors

- Anonymous attackers
- Authenticated but malicious users
- Automated bots
- Competitors attempting data scraping
- Misconfigured or compromised clients

---

## 5. Threats & Mitigations (STRIDE)

### 5.1 Spoofing Identity

**Threat**
- Use of stolen or guessed API keys

**Impact**
- Unauthorized access to protected endpoints

**Mitigations**
- High-entropy API keys
- Key rotation
- Optional IP allowlists
- HMAC or signed requests (advanced)

---

### 5.2 Tampering

**Threat**
- Modification of request parameters
- Replay attacks

**Impact**
- Data corruption or unintended operations

**Mitigations**
- HTTPS only (TLS)
- Request signing
- Nonce or timestamp validation

---

### 5.3 Repudiation

**Threat**
- Client denies making malicious or excessive requests

**Impact**
- Lack of accountability

**Mitigations**
- Structured request logging
- Correlation/request IDs
- Log retention policies

---

### 5.4 Information Disclosure

**Threat**
- Error messages revealing system internals
- Leaked API keys

**Impact**
- Easier exploitation of the system

**Mitigations**
- Generic error responses
- No stack traces in production
- Secure storage of API keys (hashed or encrypted)

---

### 5.5 Denial of Service (DoS)

**Threat**
- Excessive requests (flooding)
- Credential stuffing with invalid API keys

**Impact**
- Service degradation or outage

**Mitigations**
- Global and per-key rate limiting
- IP-based throttling
- Early rejection of invalid API keys
- WAF or CDN protections

---

### 5.6 Elevation of Privilege

**Threat**
- Abuse of misconfigured roles or scopes

**Impact**
- Access to unauthorized endpoints

**Mitigations**
- Scoped API keys
- Least-privilege access
- Explicit authorization checks per route

---

## 6. Rate Limiting Threat Scenario

### Scenario: Rate Limited Request

**Flow**
1. Client sends request
2. API key is validated
3. Rate limit counter is checked
4. Limit exceeded → `429 Too Many Requests`
5. Request is rejected without hitting backend

**Threats**
- Distributed attacks bypassing per-IP limits
- Legitimate clients being starved by abusive users

**Mitigations**
- Per-key + per-IP limits
- Sliding window or token bucket algorithms
- Separate limits for authenticated vs unauthenticated traffic

---

## 7. Residual Risks

- Stolen API keys before rotation
- Sophisticated distributed attacks
- Insider misuse

Residual risks are accepted with monitoring and alerting in place.

---

## 8. Monitoring & Detection

- Rate limit violation alerts
- Invalid API key spikes
- Backend latency monitoring
- Anomaly detection on request patterns

---

## 9. Summary

The API Gateway significantly reduces risk by:
- Enforcing authentication early
- Limiting abusive traffic
- Preventing direct backend exposure

Remaining risks are mitigated through layered defenses, monitoring, and operational controls.

---