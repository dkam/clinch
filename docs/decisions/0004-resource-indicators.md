# 0004 — Resource Indicators (RFC 8707), pass-through binding

**Status:** Accepted · **Date:** 2026-07-19

## Decision

Clinch accepts the RFC 8707 `resource` parameter at `/oauth/authorize` and
`/oauth/device_authorization`, binds it to the issued token as its audience, and
reports it at introspection as `aud`. Validation is **syntax-only (pass-through)**:
the value must be an absolute URI without a fragment; clinch does not maintain a
registry of resource servers. The **resource server enforces** the audience when it
introspects the token.

## Context

Without an audience, an access token minted for one API could be replayed against
another API that also trusts clinch (the confused-deputy problem). RFC 8707 lets the
client name the target (`resource=https://c2a2.example.com`); the token is then bound
to that audience and is useless elsewhere.

Two ways to handle the value:

- **Pass-through (chosen):** validate the URI syntax, store it, report it as `aud`.
  Enforcement is at the resource server, which already validates tokens via
  introspection ([0001](0001-opaque-vs-jwt-access-tokens.md)) and simply checks
  `aud == <its own identifier>`. A token bound to an arbitrary audience is worthless
  anywhere that isn't that audience, so no clinch-side registry is needed.
- **Registry-gated (not chosen):** reject unknown resources with `invalid_target`.
  Catches typos early but requires clinch to model and maintain resource-server
  identities, which it does not have today.

## Implementation notes

- `resource` is threaded from the authorize / device_authorization request onto the
  authorization/device code, then onto the access and refresh tokens, and is carried
  across refresh rotation so re-issued tokens keep the audience.
- Invalid resources are rejected with `error=invalid_target` (redirect for authorize,
  JSON 400 for device_authorization). Validation lives in
  `OidcController#valid_resource_indicator?` (absolute URI, no fragment).
- Introspection returns `aud = access_token.resource` when bound, falling back to the
  client_id when no resource indicator was used.
- Binding happens at authorization time and is carried through; token-time `resource`
  narrowing is not implemented (not needed for the MCP / device flows).

## Consequences

- Tokens can be scoped to a single resource server, closing the cross-service replay
  path — enforced where it belongs, at the resource server.
- Completes the clinch-side OAuth surface MCP connectors rely on (with DCR
  [0003](0003-dynamic-client-registration.md) and introspection). The remaining MCP
  piece, Protected Resource Metadata (RFC 9728), lives on the resource server.
