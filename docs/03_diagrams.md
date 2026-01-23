# Gatekeeper – Architecture Diagrams

## 1. System Context Diagram

![System Context](../diagrams/system-context.png)

This diagram shows Gatekeeper’s position between API clients and backend services,
as well as its dependencies on Redis and Postgres.

## 2. Component Architecture Diagram

![Component Architecture](../diagrams/component-architecture.png)

This diagram illustrates the internal modules of the Gatekeeper service and the
data flow between authentication, rate limiting, request handling, and logging.

## 3. Request Lifecycle – Valid Request

![Valid Request Sequence](../diagrams/sequence-valid-request.png)

This sequence diagram shows the successful path for an authenticated and
rate-limited request.

## 4. Request Lifecycle – Invalid API Key

![Invalid Key Sequence](../diagrams/sequence-invalid-key.png)

This diagram demonstrates how requests with missing or invalid API keys are
rejected early in the pipeline.

## 5. Request Lifecycle – Rate Limited

![Rate Limited Sequence](../diagrams/sequence-rate-limited.png)

This sequence diagram shows how the gateway responds when a request exceeds the
configured rate limit.
