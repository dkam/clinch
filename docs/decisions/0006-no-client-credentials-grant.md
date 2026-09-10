# 0006 — No `client_credentials` grant; machine access is user-delegated

**Status:** Accepted · **Date:** 2026-09-10

## Decision

Clinch does not implement the OAuth 2.0 `client_credentials` grant, and will not add
it to serve CLIs, agents, or scripts. Every access token clinch issues represents a
**person**. A machine that needs to call a clinch-protected API obtains that person's
token through the Device Authorization Grant ([0002](0002-device-authorization-grant.md)),
bound to the target resource ([0004](0004-resource-indicators.md)).

`SUPPORTED_GRANT_TYPES` (`app/controllers/oidc_controller.rb`) therefore stays at
`authorization_code`, `refresh_token`, and `urn:ietf:params:oauth:grant-type:device_code`.

## Context

The recurring suggestion, when an agent or a script needs API access, is "give it its
own client_credentials grant" — it is the textbook answer for machine-to-machine, and
it is the wrong answer for the thing we are actually doing. Four reasons:

**1. A client_credentials token has no identity, and our resource servers authorize on
identity.** The grant produces a token with no `sub`, no user, no groups. c2a2 decides
access with `ClinchAuthorization.authorized_identity?(email:, groups:)` — email/domain
allow-list OR clinch group membership. A userless token discloses neither, so every
resource server would need a *second*, parallel authorization path keyed on `client_id`:
new ACL surface to build, maintain, and get wrong, in each app.

**2. The data model is user-shaped on purpose.** `oidc_access_tokens.user_id` is
`null: false` and `OidcAccessToken belongs_to :user` is required. Introspection reads
`access_token.user` to produce `sub`, `username`, and `groups`. Access control at every
grant runs through `Application#user_allowed?`. Userless tokens mean a nullable FK plus
a "what if there is no user" branch in every consumer of a token — including the
introspection response, whose shape resource servers already depend on.

**3. It reintroduces the long-lived shared secret the design exists to avoid.** The
point of [0002](0002-device-authorization-grant.md) is that a human authenticates once
and the tool gets a scoped, expiring, revocable token — no password, no static key in
an agent's environment. A client secret sitting in `ENV` for an agent to use is a static
key with extra steps: it does not expire, it is not scoped to a person, and it grants
the same access to anyone who reads the environment. Where a service genuinely needs
that trade-off it already has simpler options (a resource server's own admin token, or
clinch's `ApiKey`); dressing it up as OAuth buys nothing and obscures what it is.

**4. It destroys the audit trail and per-person revocation.** Today a request log names
a human, one person's grant can be revoked without affecting anyone else, and an
offboarded user loses access everywhere at once. With a shared client identity, "who
ran this" is unanswerable and revocation is all-or-nothing.

## What to do instead

- **A CLI, an agent, a developer's script** — device flow. `c2a2 login` (see
  `c2a2/cli/`, which is app-agnostic and stdlib-only) prints a code and a URL, the human
  approves at `/device` with a passkey, tokens land in `$XDG_CONFIG_HOME/clinch-cli/`
  at mode 0600 and refresh transparently. Access tokens live 1h, refresh tokens 30d
  and rotate on use, so an agent in regular use never re-authenticates.
- **Re-login is too frequent** — raise `refresh_token_ttl` on that one `Application`
  (`Application#refresh_token_expiry`, default 2592000s). Do not change grant type to
  dodge an expiry knob.
- **A truly unattended service calling another service**, with no human to delegate
  from (a nightly job in app A hitting app B's API) — this is the one case
  client_credentials is *for*, and we still do not have it. Revisit then, and prefer
  `private_key_jwt` (RFC 7523) over a shared secret so no credential crosses the wire.
  Until such a caller actually exists, adding the grant is speculative surface.

## Consequences

- Every token in the system answers "who authorized this?" with a person, which is what
  makes introspection's `username`/`groups` disclosure ([0005](0005-introspection-authorization.md))
  meaningful to a resource server.
- Onboarding a machine costs one browser approval by a human, once per machine.
- Genuinely unattended service-to-service calls are not supported by clinch today. That
  is a deliberate gap, not an oversight — see above for what would fill it.
