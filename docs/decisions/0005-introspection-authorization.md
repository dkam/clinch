# 0005 — Introspection authorization & claim scope-gating

**Status:** Accepted · **Date:** 2026-07-19

## Decision

The RFC 7662 introspection endpoint restricts *which* tokens a caller may see and
*which* claims it returns:

1. **Authorization to introspect.** A caller may introspect a token only if it was
   issued to that caller, or the token is bound (RFC 8707 `resource`) to a resource
   the caller is registered to serve (`Application#serves_resource?`, backed by a new
   `resource_identifiers` column). Unauthorized callers get the same `{active:false}`
   as an unknown token — disclosing nothing.
2. **Claim scope-gating.** `username` (email) is returned only when the token carries
   the `email` scope; `groups` only with the `groups` scope — mirroring the userinfo
   endpoint. `sub` is a pairwise pseudonym and is always safe to return.

## Context

The first cut authenticated the caller (any confidential client) but then returned
`active:true` plus the user's email and **all** group names for **any** token — even
tokens issued to a different client and regardless of the token's scopes. A
low-privilege second client could therefore harvest every user's email and group
memberships by replaying tokens it observed. RFC 7662 §4 explicitly calls for the AS
to verify the resource server is authorized to introspect the particular token,
typically via audience restriction.

## How it fits together

This is the enforcement half of the RFC 8707 resource indicators
([0004](0004-resource-indicators.md)): the CLI/agent requests a token with
`resource=<resource server>`, the resource server is registered with that same
identifier, and only it can introspect (and thereby read the user's groups to
authorize). A token minted for one resource server cannot be introspected by another.

## Consequences

- **c2a2 setup:** the `c2a2-introspection` client must declare its
  `resource_identifiers` (seeded from `C2A2_RESOURCE`), and the CLI must request its
  token with `resource=<that URL>`. A token with no bound resource can only be
  introspected by the client it was issued to.
- Resource servers see only the identity claims the token was actually granted, so an
  over-broad token (or a misconfigured scope) can't leak email/groups.
- Unauthorized introspection is indistinguishable from an unknown token, preventing
  token-scanning and cross-client identity harvesting.
