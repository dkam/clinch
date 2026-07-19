# 0003 — Dynamic Client Registration (RFC 7591), runtime-gated

**Status:** Accepted · **Date:** 2026-07-19

## Decision

Clinch supports **OAuth 2.0 Dynamic Client Registration (RFC 7591)** at
`POST /oauth/register`, so clients (notably MCP connectors like Claude) can register
themselves instead of being hand-created. It is **off by default** and toggled at runtime
by an admin from the Applications page. A newly registered client is **default-deny**: it
has no `allowed_groups` until an admin attaches one.

We also serve the **RFC 8414** metadata alias at
`/.well-known/oauth-authorization-server` (the OIDC discovery document is a superset), and
advertise `registration_endpoint` only while registration is enabled.

## Context

MCP connectors expect to self-register via anonymous DCR rather than being pre-provisioned.
But open registration is a real risk: anyone could register a legitimate-looking client and
attempt **consent phishing** — luring a user to approve it, then holding a token that acts
as that user against any resource server that trusts clinch tokens (via introspection, see
[0001](0001-opaque-vs-jwt-access-tokens.md)).

Two controls make this safe:

1. **Runtime window, not always-on.** DCR is a toggle (persisted `Setting`, admin UI), so
   the operator opens it briefly, lets the client register, attaches a group, and closes it
   again. The `CLINCH_DCR_ENABLED` env var is only a bootstrap default when the setting is
   unset. Default is off.
2. **Default-deny for new clients.** Clinch's authorize flow already gates on
   `Application#user_allowed?` (group membership), evaluated *before* the consent screen
   renders. A group-less registered client therefore can't show any user an approve button —
   the consent-phishing path dead-ends until an admin explicitly grants a group. ForwardAuth
   services are gated by the user's session cookie, not client tokens, so DCR doesn't widen
   that surface at all.

## Implementation notes

- `OidcRegistrationController#create`: validates `token_endpoint_auth_method`
  (none/client_secret_basic/client_secret_post), `grant_types`
  (authorization_code/refresh_token), `response_types` (code), and `redirect_uris`
  (https anywhere; http only for loopback). Creates a public or confidential `Application`
  with `require_pkce: true`, returns the RFC 7591 response (client_secret once, for
  confidential clients).
- `Setting` is a small key/value store; `Application.dynamic_registration_enabled?` reads it
  with the env var as fallback. Admin toggle: `Admin::DynamicClientRegistrationController`.

## Consequences

- MCP connectors can self-register when the window is open, then operate normally once an
  admin grants a group.
- No always-on anonymous registration surface; the risky window is short and operator-driven.
- Remaining MCP pieces (resource indicators RFC 8707, protected-resource metadata RFC 9728 on
  the resource server) are separate, smaller follow-ups.
