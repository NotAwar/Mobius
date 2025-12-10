# Mobius Architecture and Design (API-first)

This repository contains the backend/services for Mobius — a self-hosted,
cross-OS device management platform. The React frontend will live in a separate
repository and will use the public API exclusively.

## High-level goals

- API-first everything: all functionality is exposed via HTTP APIs; the UI is a
  consumer of the same internal API used by all components.
- Cross-OS device management: Windows, macOS, Linux; Android/iOS via MDM where
  supported.
- First-class MDM: Apple, Windows, and Android MDM are core. We aim for full
  parity with established MDMs and to exceed them via performance, simplicity,
  self-hosting, and extensibility.
- Small, portable containers for all components; easy self-hosting on any OS.
- Data sovereignty: admins own and host the full stack.
- Licensable product: enforce tiers and device limits on the API layer.

## Core components

- Mobius Server
  - Central API and orchestration for enrollment, policy, software distribution,
    osquery results, MDM protocols, and Cocoon.
  - Exposes API endpoints consumed by CLI, Cocoon, agents, and the admin GUI.
  - Implements licensing checks (tiers, device-limits) and multi-tenant-safe
    boundaries.

- Mobius Client (agent)
  - Lightweight background service that enrolls, auto-starts, and periodically
    heartbeats.
  - Runs osquery (or integrates with it) to collect telemetry; posts to the
    server.
  - Supports pluggable "workloads" for platform-specific management (e.g.,
    Windows/Mac profiles, policies, app distribution).

- Mobius CLI
  - Admin tool for scripting and direct API interactions.
  - Mirrors server capabilities via commands that call the public API.

- Mobius Cocoon (self-service portal)
  - Optional end-user portal for installing approved software and viewing
    device status.
  - Provided as its own small service that reads/writes only via the API.

- Admin GUI (centralized administration)
  - A React SPA (separate repo) that integrates with the internal API for all
    administrative actions.
  - Typically served by the central server (as static assets) and communicates
    with the same versioned API surface as other clients.

## API-first contract (selected flows)

- Enrollment: POST /api/osquery/enroll → node_key
- Config fetch: POST /api/osquery/config → config payload
- Heartbeat: HEAD/POST /api/mobius/device/ping
- Software catalog/installers: /api/_version_/mobius/software/*
- Policies: /api/_version_/mobius/policies/*
- MDM (Apple/Windows/Android): dedicated protocol endpoints, gated by license
  tier.

- Licensing:
  - GET /api/_version_/mobius/license/status → current license info
  - PUT /api/_version_/mobius/license → apply/update license (in OSS builds,
    this returns a clear “configure license.key and restart” message)

## Licensing model (skeleton)

- License is presented to the server (configuration/env) as a signed token.
- Fields include: tier (basic/premium/enterprise), device_count (limit), exp,
  org.
- Middleware in server validates license and enforces feature flags and limits.
- Non-licensed features respond with ErrMissingLicense and clear error
  messages.

## Containers and deployment

- Each component has a multi-stage Dockerfile using a pinned Go toolchain.
- Images are slim Alpine-based, with only required runtime artifacts.
- docker-compose and Kubernetes manifests are provided under deployments/.

## Data model and storage

- MySQL-compatible datastore with Redis for caching and live-querying.
- Object storage (S3 or compatible) for carves, installers, artifacts.

## Security and observability

- TLS everywhere; configurable secrets for enroll and API auth.
- Structured logging; Prometheus metrics; optional tracing.

## Non-goals (here)

- Frontend code (lives in a separate repo).
- On-host EDR-like features beyond osquery and MDM policies.

## Notes for contributors

- Keep features behind API flags and license gates.
- Prefer additive migrations and backward-compatible API changes.
