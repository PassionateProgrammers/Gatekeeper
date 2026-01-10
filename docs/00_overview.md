# Gatekeeper - Project Overview

## Purpose
Gatekeeper is designed to be a multi-tenant API gateway that authenticates requests using API keys, enforces per client rate limits, and records usage metrics for analytics.

## Problem Statement
A public facing API needs to protect backend services from being exploited or overloaded. It must also provide some usage details to the client. Without oversight, the backend system is susceptible to issues such as denial of service, runaway clients, and mismanagement of resources.

## Goals
- Provide API key authentication for multi-tenant clients.
- Enforce per-key rate limits
- Record and query usage analytics
- Be containerized for local execution. (Docker)
- Testable and easy to evaluate

## Non Goals
- Load Balancing features such as TLS offloading
- Web application firewalls
- OAuth providers
- Service mesh
- Front end dashboard UI
- Multi-region deployment

## Target Users
- Developers exposing a public facing API that require auth, rate limiting, and usage tracking.

## Scope
### In Scope
- API key management
- Request authentication
- Rate limiting per key
- Usage logging
- Admin analytics endpoints
- Health endpoints and structured logging with request IDs

### Out of Scope
- OAuth2 open ID
- Role based access control
- streaming analytics
- immutable guarentees, signed logs, and other audit compliance features.

## Assumptions
- Scale is smaller than enterprise level
- Redis for rate limiting
- Postgres for data storage
- Proof of concept

## Success Criteria
- Code has descriptive and accurate function, variable, and class names.
- Code runs without logical or syntax errors
- Request with invalid keys are rejected with HTTP 401 signal
- Request exceeding rate limit are rejected with HTTP 429 signal
- Rate limiting behavior is tested through a load test script.
- Usage analytics endpoints returns correct metrics for a specific window
- Documentation for requirements, architecture, API design, and data model are used for planning.
- Demo script shows a sample of all project features tested.
- Video to demonstrate the project.

## Deliverables
- Source code for the project
- Markdown documents and/or diagrams for project planning
- Load test script
- Video demonstration
