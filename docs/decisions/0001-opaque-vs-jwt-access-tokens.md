# 0001 — Opaque access tokens (not JWT); introspection for resource servers

**Status:** Accepted · **Date:** 2026-07-19

## Decision

Clinch issues **opaque** access and refresh tokens — random strings stored server-side
as SHA-256 HMACs (`OidcAccessToken` / `OidcRefreshToken`), not self-contained JWTs. The
**ID token stays a JWT** (RS256), because it is meant to be read by the client. Resource
servers that need to validate an access token call the **RFC 7662 introspection endpoint**
(`POST /oauth/introspect`), which also returns the user's `groups` for authorization.

## Context

There is no universal winner between opaque and JWT access tokens; it is an architecture
call:

| | Opaque (reference) | JWT (self-contained) |
|---|---|---|
| Validation | Resource server calls back (introspect/userinfo) | Offline signature check against JWKS |
| **Revocation** | **Instant** — the AS holds the state | Valid until expiry unless a blocklist is added (which re-adds state) |
| Best when | One central IdP, few resource servers, revocation matters | Many resource servers, high throughput, offline verification needed |
| Token contents | Nothing leaks (just a handle) | Claims readable by any holder |

Clinch is a single self-hosted IdP with a handful of relying parties. It already has
instant revocation, including refresh-token **family revocation** on reuse. That
revocation guarantee is a real security property for an IdP, and the introspection
callback cost is negligible at this scale (and cacheable by the resource server).

## Consequences

- Resource servers (e.g. c2a2) cannot verify tokens offline; they must call
  `/oauth/introspect` (authenticated as a confidential client) and should briefly cache
  positive results.
- Tokens can be revoked immediately (logout, admin action, reuse detection) and stop
  working at the next introspection — a property JWT access tokens can't offer without
  reintroducing server state.
- If we ever need many resource servers with zero-latency offline verification, revisit
  with RFC 9068 (JWT access token profile) — accepting the loss of instant revocation.
