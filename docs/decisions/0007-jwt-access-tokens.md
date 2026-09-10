# 0007 — Per-client access token format; RFC 9068 JWTs as an opt-in

**Status:** Accepted · **Date:** 2026-09-10

## Decision

An `Application` chooses how its access tokens are formatted, via
`access_token_format`:

- **`opaque`** (default, unchanged) — a random handle. The resource server calls
  `/oauth/introspect` to validate it. Revocation is instant.
- **`jwt`** — an **RFC 9068** (`typ: at+jwt`) token signed with the same RS256 key
  as ID tokens. The resource server verifies it offline against
  `/.well-known/jwks.json` and never calls clinch on the request path. Revocation
  takes effect when the token expires.

A JWT access token still has its `oidc_access_tokens` row; its `jti` is that row's
`token_hmac`, so a JWT presented to `/oauth/introspect`, `/oauth/userinfo` or
`/oauth/revoke` resolves to the same record an opaque token would. Clients that do
not opt in are unaffected in every respect.

## Context

[0001](0001-opaque-vs-jwt-access-tokens.md) chose opaque tokens and named the
condition for revisiting: *"if we ever need many resource servers with zero-latency
offline verification."* c2a2 and shopo will serve many requests per second, and under
the opaque design every one of those requests depends on clinch being reachable.

That dependency is worse than it first looks. The resource server caches introspection
results, but the cache key is the token string, and a refresh mints a new token string
— so the cache cannot span a refresh, and clinch is on the critical path at least once
per access-token lifetime per client no matter how the TTL is tuned. Raising
`access_token_ttl` widens the window but does not remove the dependency: it just makes
the outage that eventually hits a cold cache less frequent, not less total.

The trade is therefore not "cache more" but "stop calling back at all", and that is a
per-client decision, because the two clients that need it have very different
requirements from a browser SSO client where instant revocation is the whole point.

## Why per-client rather than global

This is the mainstream shape. Auth0 issues a JWT when a token is requested for a
registered API's audience and an opaque token otherwise; Okta splits the same way
between a custom authorization server and the org one; Ory Hydra exposes
`access_token_strategy` per client. Nobody makes it a global switch, because the
answer genuinely differs per relying party.

So: browser SSO clients, MCP connectors, and anything where an admin expects "revoke"
to mean *now* keep opaque tokens and instant revocation. The two high-throughput APIs
opt into JWTs and accept a bounded revocation lag.

## Consequences

- **c2a2/shopo/gr stop depending on clinch for API traffic.** Verification is a local
  RSA check (~50µs, no I/O) instead of an HTTP round trip. A clinch outage is invisible
  to their request path until tokens expire.
- **They no longer need a client secret on the API path** — JWKS is public. One fewer
  secret deployed in one more place.
- **`resource_identifiers` registration ([0005](0005-introspection-authorization.md))
  becomes unnecessary for JWT clients.** The `aud` claim carries the RFC 8707 resource
  self-containedly, so the confused-deputy protection survives without clinch having to
  gate disclosure — and the `{"active": false}` misconfiguration trap disappears with it.
- **Revocation lag equals `access_token_ttl`.** This is the whole cost, and it inverts
  how the TTL should be set: under opaque, a long TTL is harmless because introspection
  still catches revocation immediately; under JWT, the TTL *is* the revocation window.
  Pair `jwt` with a short access-token TTL and rely on refresh, rather than a long one.
- **Claims are readable by any holder.** A JWT carries the user's `email` and `groups`
  in base64, so an over-broad scope leaks further than it does with a handle. Scope
  gating is identical to introspection's; the consequence of getting it wrong is larger.
- **Key rotation becomes a coordination problem.** With offline verification, resource
  servers cache the JWKS. Every token names its key in the `kid` header; clients must
  refetch the JWKS on an unknown `kid` (rate-limited) rather than trusting a fixed TTL,
  or a rotation blackholes every request until their cache expires. clinch publishes a
  single key today and has no rotation mechanism — worth building before the first
  rotation, not during it.
- **`at_hash` now hashes the delivered token.** OIDC Core §3.1.3.6 hashes the access
  token *as given to the client*; for a JWT client that is the JWT, not the internal
  handle. Both issuance paths compute the wire value once and hash that.

## Implementation notes

- `OidcJwtService.generate_access_token` mints; `.decode_access_token` verifies
  (signature, `typ: at+jwt`, issuer, expiry) and returns nil on anything else.
- `OidcAccessToken#wire_value` produces what goes on the wire;
  `.find_by_presented_token` accepts either format and is used by userinfo,
  introspection and revocation.
- `jti` is the record's `token_hmac` — a one-way digest of a random string, so naming
  it in the token discloses nothing to a holder who already has the token, and it gives
  introspection an indexed lookup with no new column.
- Claims: `iss`, `sub` (pairwise sid, matching the ID token and introspection), `aud`
  (the RFC 8707 resource, falling back to `client_id`), `exp`, `iat`, `jti`,
  `client_id`, `scope`, plus scope-gated `email` and `groups`.
