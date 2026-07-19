# 0002 — CLI/agent auth via the Device Authorization Grant (RFC 8628)

**Status:** Accepted · **Date:** 2026-07-19

## Decision

CLIs and terminal agents (e.g. Claude) authenticate to Clinch-protected services as a
real user via the **OAuth 2.0 Device Authorization Grant (RFC 8628)** instead of static
API keys. The tool prints a short code and a URL; the user approves at `/device` with
their passkey; the tool polls the token endpoint and receives the standard
access + refresh + ID token triple.

## Context

We wanted CLIs — and especially headless agents — to authenticate as a real user rather
than carry a long-lived API key. The two mainstream options:

- **Device flow (RFC 8628):** tool prints a code, human approves on any device, tool
  polls. Needs only "print text" + "poll HTTP".
- **Auth code + PKCE with a loopback (`127.0.0.1`) redirect (RFC 8252):** tool opens a
  browser and catches a local redirect.

Agents are often sandboxed or run on a remote box where opening a browser and receiving a
loopback redirect is unreliable. Device flow needs neither, which is exactly why it fits
CLIs and agents. The human approves wherever their passkey lives.

## Implementation notes

- `OidcDeviceCode` mirrors `OidcAuthorizationCode`: opaque `device_code` stored as an
  HMAC, short plaintext `user_code`, nullable `user` until approval, `status`
  (pending/approved/denied), PKCE columns, and `interval`/`last_polled_at` for
  `slow_down` enforcement.
- Endpoints: `POST /oauth/device_authorization`, the
  `urn:ietf:params:oauth:grant-type:device_code` branch of `POST /oauth/token`, and the
  authenticated verification page `GET/POST /device`.
- Token issuance reuses the authorization-code path (`OidcAccessToken` +
  `OidcRefreshToken` + `OidcJwtService`). Access control reuses
  `Application#user_allowed?`, so approval is gated by group membership.
- PKCE is **optional** for device flow (RFC 8628 §5.5): enforced only when the device
  authorization request supplied a `code_challenge`. The `device_code` itself is a
  high-entropy secret delivered directly to the client over TLS.
- A well-known public client `clinch-cli` (no secret, PKCE) is seeded for tools to use.

## Consequences

- No static API keys for user-context CLI/agent access; tokens are revocable and expire.
- Resource servers validate the resulting opaque access tokens via introspection — see
  [0001](0001-opaque-vs-jwt-access-tokens.md).
- Same foundation (public clients + PKCE + introspection) supports future MCP connector
  support, whose main additional piece would be Dynamic Client Registration (RFC 7591).
