# Security Review — September 2026

**Reviewed:** 2 September 2026
**Revision:** `bf10995` (v0.17.2)
**Stack:** Rails 8.1.3, Ruby 4.0.6, SQLite
**Tooling:** Brakeman clean (3 informational warnings), bundler-audit clean

A code-level review of Clinch covering sign-in, sessions, two-factor and passkeys,
the OIDC / OAuth 2.0 endpoints, forward auth, admin surfaces, and deployment
configuration. Twenty findings, seven confirmed by test, ordered so they can be
worked top to bottom.

Severity reflects impact on an identity provider specifically: a flaw that would
be minor in an ordinary web app can be serious here because every relying party
inherits it. **Verified** means the behaviour was reproduced with an integration
test against the current code. That test is in the appendix so the failing runs
can become regression tests as each item is fixed (see the testing rule in
`~/.claude/CLAUDE.md`: write the test, watch it fail, then fix).

Related: [security-todo.md](security-todo.md) tracks earlier audit items;
CLN-03 below overlaps with its "Per-Account Rate Limiting" entry.

---

## Findings register

| ID | Finding | Severity | Status | Effort |
|----|---------|----------|--------|--------|
| **Fix soon** | | | | |
| [CLN-01](#cln-01-disabled-users-oidc-tokens-stay-valid-until-expiry) | Disabled users' OIDC tokens stay valid until expiry | High | **Fixed** | Small |
| [CLN-02](#cln-02-passkey-sign-in-counted-as-two-factor-without-user-verification) | Passkey sign-in counted as two-factor without user verification | High | **Partly fixed** | Small |
| [CLN-03](#cln-03-sign-in-throttles-are-per-ip-only-pending-2fa-state-never-expires) | Sign-in throttles are per IP only; pending 2FA state never expires | High | **Fixed** | Medium |
| [CLN-04](#cln-04-refresh-grant-runs-without-a-row-lock-and-mints-before-checking-consent) | Refresh grant runs without a row lock and mints before checking consent | Medium | **Fixed** | Small |
| [CLN-05](#cln-05-revoke-all-leaves-tokens-alive-and-the-pairwise-subject-is-not-stable) | "Revoke all" leaves tokens alive and the pairwise subject is not stable | Medium | **Fixed** | Medium |
| [CLN-06](#cln-06-rp-initiated-logout-is-triggerable-by-any-site-id_token_hint-ignored) | RP-initiated logout is triggerable by any site; `id_token_hint` ignored | Medium | Verified | Medium |
| [CLN-07](#cln-07-email_verified-is-always-true-email-changes-are-never-confirmed) | `email_verified` is always true; email changes are never confirmed | Medium | **Fixed** | Medium |
| **Worth fixing** | | | | |
| [CLN-08](#cln-08-consent-page-is-served-without-a-form-action-csp-directive) | Consent page is served without a form-action CSP directive | Medium | **Fixed** | Small |
| [CLN-09](#cln-09-internal-ip-host-authorisation-patterns-are-unanchored) | Internal-IP host authorisation patterns are unanchored | Low | **Fixed** | Small |
| [CLN-10](#cln-10-session-cookie-is-scoped-to-the-registrable-domain-and-never-fully-cleared) | Session cookie is scoped to the registrable domain and never fully cleared | Medium | By inspection | Small |
| [CLN-11](#cln-11-changing-a-password-from-the-profile-keeps-other-sessions-alive) | Changing a password from the profile keeps other sessions alive | Low | **Fixed** | Small |
| [CLN-12](#cln-12-revocation-endpoint-does-not-check-token-ownership) | Revocation endpoint does not check token ownership | Low | **Fixed** | Small |
| **Lower priority** | | | | |
| [CLN-13](#cln-13-actioncable-connection-skips-session-expiry-and-active-user-checks) | ActionCable connection skips session expiry and active-user checks | Low | **Fixed** | Small |
| [CLN-14](#cln-14-userinfo-accepts-the-access-token-in-the-query-string) | Userinfo accepts the access token in the query string | Low | **Fixed** | Small |
| [CLN-15](#cln-15-encryption-still-accepts-unencrypted-totp-secrets) | Encryption still accepts unencrypted TOTP secrets | Low | By inspection | Small |
| [CLN-16](#cln-16-single-signing-key-with-no-rotation-path) | Single signing key with no rotation path | Low | By inspection | Medium |
| [CLN-17](#cln-17-forward-auth-api-key-path-allows-requests-with-no-host-header) | Forward-auth API key path allows requests with no host header | Low | **Fixed** | Small |
| [CLN-18](#cln-18-backchannel-logout-leaves-a-dns-rebinding-window-after-the-ssrf-check) | Backchannel logout leaves a DNS rebinding window after the SSRF check | Low | By inspection | Small |
| [CLN-19](#cln-19-webauthn-failures-echo-library-exception-text-to-the-client) | WebAuthn failures echo library exception text to the client | Low | **Fixed** | Small |
| [CLN-20](#cln-20-no-audit-log-of-admin-actions-or-authentication-events) | No audit log of admin actions or authentication events | Low | Gap | Large |

---

## Progress

**3 September 2026** — first batch shipped. Fixed and covered by regression
tests: CLN-01, CLN-04, CLN-08, CLN-09, CLN-11, CLN-12, CLN-13, CLN-14, CLN-17,
CLN-19. CLN-02 is partly done (see its section for the remaining step).

The four small "lower priority" items (CLN-12, 13, 14, 17, 19) were pulled
forward into this batch rather than left to maintenance, because each is a few
lines in a file the batch was already touching.

Tests live in:

- `test/integration/security_review_probe_test.rb` — the appendix probes, with
  every assertion now inverted to assert the *secure* behaviour.
- `test/integration/security_review_phase1_test.rb` — CLN-12, 14, 17, 19.
- `test/integration/webauthn_user_verification_test.rb` — CLN-02 steps 1 and 2.
- `test/lib/internal_host_patterns_test.rb` — CLN-09.
- `test/integration/csp_test.rb` — extended with the consent page (CLN-08).

Suite: 644 runs, 0 failures (627 before). Brakeman still reports the same three
informational warnings; standardrb reports the same four pre-existing offences.

**Known gap in coverage:** the login-side recording of the WebAuthn UV flag
(`sessions#webauthn_verify`) is not covered by a test — reaching the code after
`verify` needs a genuinely signed assertion, which the suite has no fixture for.
The model and registration sides are tested. Worth revisiting if a WebAuthn test
harness is ever added.

**23 September 2026** — CLN-05 and CLN-07, the two findings Silo's OIDC
binding depends on, since it links accounts by verified address and keys
identities on `(iss, sub)`.

- CLN-07: `users.email_verified_at` drives `email_verified` (ID token,
  userinfo, admin claim preview). A self-service change is held in
  `unconfirmed_email` until a `generates_token_for(:email_confirmation)` link
  sent to the new address is followed; an admin change takes effect but is
  unverified until the same link is followed; accepting an invitation
  verifies. Existing accounts were backfilled as verified, since that is what
  relying parties have been told so far.
- CLN-05: subjects live in `oidc_pairwise_subjects`, seeded from the consent
  `sid` relying parties already hold, and outlive consent. Destroying a
  consent revokes that user's tokens for the application, whichever path
  destroys it, and userinfo and introspection refuse a token with no consent
  behind it regardless (401 / `{"active": false}`), as CLN-01 does for
  disabled users. Nothing falls back to the numeric user id. The review
  suggested an HMAC-derived subject; a stored one was used instead, because
  existing random subjects have to be kept anyway, and a stored value does not
  change if the server key does.

Tests: `test/integration/email_verification_test.rb`,
`test/integration/pairwise_subject_stability_test.rb`, and the inverted CLN-05
probe.

CLN-03, same day: `SignInThrottle` counts failures per account in
`Rails.cache` — 10 passwords per email address (counted for addresses with no
account too, with the same answer, so it enumerates nothing) and 5 TOTP codes
per user, each over an hour. While over the limit even a correct answer is
refused, or the limit would not bound guessing. The pending TOTP and passkey
state now carries its start time and lapses after five minutes, and the per-IP
limit on the TOTP step counts POSTs only. Tests:
`test/integration/sign_in_throttle_test.rb`.

Still open: CLN-02 step 3, CLN-06, CLN-10, CLN-15, CLN-16, CLN-18, CLN-20.

---

## Fix soon

### CLN-01 · Disabled users' OIDC tokens stay valid until expiry

**Severity:** High · **Status:** Verified · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

**What.** The userinfo and introspection endpoints check that the token and the
application are active but never that the token's user still is. The
deactivation callback on the user model destroys browser sessions only. A
disabled user's access token keeps returning their profile, and introspects as
`active: true`, until it expires. Access token lifetime can be configured up to
24 hours.

**Why it matters.** Disabling an account is the admin's emergency lever. Relying
parties that trust introspection or userinfo will keep serving the user for the
rest of the token lifetime. API keys have the same gap at the model level,
although the forward-auth controller does re-check at use time.

**Fix.** Add `user.active?` checks to userinfo and introspection. In the
deactivation callback, also revoke the user's OIDC access tokens, refresh
tokens, and API keys. Consider deleting pending authorization codes and device
codes too.

**Where.**
- `app/controllers/oidc_controller.rb:1006` (userinfo)
- `app/controllers/oidc_controller.rb:1115` (introspect)
- `app/models/user.rb:254` (`revoke_sessions_when_deactivated`)

---

### CLN-02 · Passkey sign-in counted as two-factor without user verification

**Severity:** High · **Status:** By inspection · **Effort:** Small

- [~] Partly fixed — 3 September 2026. Steps 1 and 2 of the staged plan are
  done: `webauthn_credentials.user_verified` now records the UV flag at both
  registration and login (a sign-in without UV logs a warning), and
  registration requires `userVerification: "required"` so no new PIN-less key
  can be enrolled. **Step 3 is still open:** after a week of data, if the logs
  show no UV-less sign-ins, require UV at login too and stop stamping acr 2
  without it. Existing keys are deliberately untouched until then, so a
  PIN-less key registered before today still yields acr 2.

**What.** Both the authentication challenge and credential registration request
`userVerification: "preferred"`. A roaming security key with no PIN or
biometric satisfies "preferred" with a touch alone, which proves possession
only. The resulting session is stamped `acr: "2"`, ID tokens carry that claim,
and no second factor is requested.

**Why it matters.** Relying parties and the forward-auth policy treat acr 2 as
multi-factor. A stolen security key with no PIN becomes a complete credential
for every application behind Clinch, including the admin panel.

**Fix.** Preferred approach: require user verification for both ceremonies
(`user_verification: "required"`). Alternative: after `verify`, read the UV
flag from the assertion's authenticator data
(`webauthn_credential.response.authenticator_data.user_verified?`) and assign
acr 2 only when it is set, falling through to TOTP when it is not. Store the UV
state on the credential at registration so the login page can predict which
path applies.

**Where.**
- `app/controllers/sessions_controller.rb:226` (challenge options)
- `app/controllers/sessions_controller.rb:323` (`start_new_session_for ... acr: "2"`)
- `app/controllers/webauthn_controller.rb:191` (registration options)

---

### CLN-03 · Sign-in throttles are per IP only; pending 2FA state never expires

**Severity:** High · **Status:** By inspection · **Effort:** Medium

- [x] Fixed — 23 September 2026. See Progress.

**What.** The password step allows 20 attempts per 3 minutes and the TOTP step
10 per 3 minutes, both keyed by client IP through Rails' `rate_limit`. There is
no per-account counter for either. The pending TOTP and pending WebAuthn user
IDs are written to the cookie session with no timestamp, so the second-factor
page stays valid indefinitely once a password has been accepted. The TOTP limit
also counts GET page loads because one action serves both verbs.

**Why it matters.** An attacker who has phished or reused a password can hold
the TOTP step open and rotate source addresses. Six-digit codes with a 90-second
acceptance window are within reach of a distributed guesser that faces no
per-account limit. Backup codes already have a per-user limit of five per hour,
which is the right model.

**Fix.** Add a per-user failure counter for password and TOTP verification,
mirroring `rate_limit_backup_code_verification?`. Store an issued-at time
alongside each pending user ID and reject the step after a few minutes. Split
GET and POST for the verification page so page loads do not spend the budget.
This subsumes the "Per-Account Rate Limiting" and "Account Lockout" items in
`security-todo.md`.

**Where.**
- `app/controllers/sessions_controller.rb:3` (rate limits)
- `app/controllers/sessions_controller.rb:80` (`pending_totp_user_id`)
- `app/controllers/sessions_controller.rb:208` (`pending_webauthn_user_id`)
- `app/models/user.rb:146` (existing per-user backup-code throttle to copy)

---

### CLN-04 · Refresh grant runs without a row lock and mints before checking consent

**Severity:** Medium · **Status:** Partly verified · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

**What.** The authorization code and device code grants wrap redemption in a
transaction with `lock!`. The refresh grant reads the token, checks `revoked?`,
revokes it, and creates new tokens with no lock. Two concurrent requests
presenting the same refresh token can both pass the check and both receive
fresh token pairs, which defeats the rotation reuse detection. Separately, the
consent lookup happens after the new tokens are created and the old one is
revoked, so a missing consent returns an error but leaves a live orphaned
access and refresh token behind. The orphan behaviour is confirmed by test; the
race was established by reading the code.

**Why it matters.** Rotation with reuse detection is the main defence for
leaked refresh tokens, especially for public clients that cannot authenticate.
A race that yields two valid chains from one token silently disables it.

**Fix.** Wrap the refresh grant in `OidcRefreshToken.transaction` with `lock!`,
exactly as the code grant does. Move the consent and `user_allowed?` checks
before `revoke!` and before minting.

**Where.**
- `app/controllers/oidc_controller.rb:864` (lookup, no lock)
- `app/controllers/oidc_controller.rb:902` (`revoke!` before consent check)
- `app/controllers/oidc_controller.rb:935` (consent check after minting)

---

### CLN-05 · "Revoke all" leaves tokens alive and the pairwise subject is not stable

**Severity:** Medium · **Status:** Verified · **Effort:** Medium

- [x] Fixed — 23 September 2026. See Progress.

**What.** The single-application revoke action revokes tokens and then deletes
the consent. The bulk "revoke all" action deletes consents only. Existing
access and refresh tokens keep working. Because the pairwise subject lives on
the consent row, userinfo then falls back to the raw numeric user ID as `sub`,
and the next consent generates a brand-new UUID. A relying party therefore sees
the same person as three different subjects: the original UUID, the numeric ID,
then a second UUID.

**Why it matters.** Subject stability is the contract an IdP makes with relying
parties. Breaking it orphans accounts on the RP side, and the numeric fallback
is correlatable across every client, which is the property pairwise identifiers
exist to prevent.

**Fix.** Revoke tokens in the bulk action as the single-app action already
does. Refuse userinfo and introspection with 401 when no consent exists instead
of falling back. Derive the pairwise subject deterministically, for example an
HMAC of the user ID and client ID under a server key, so it survives consent
deletion. Keep the stored `sid` for backchannel logout. Migrate carefully so
existing consents keep their current `sid` value as their subject.

**Where.**
- `app/controllers/active_sessions_controller.rb:569` (`revoke_all_consents`)
- `app/controllers/oidc_controller.rb:1014` (userinfo `sub` fallback)
- `app/controllers/oidc_controller.rb:1144` (introspect `sub` fallback)
- `app/services/oidc_jwt_service.rb:14` (id_token `sub` fallback)
- `app/models/oidc_user_consent.rb` (`set_sid`)

---

### CLN-06 · RP-initiated logout is triggerable by any site; `id_token_hint` ignored

**Severity:** Medium · **Status:** Verified · **Effort:** Medium

- [ ] Fixed

**What.** The logout handler reads `id_token_hint` and discards it. A bare GET
to `/logout` from any origin destroys the Clinch session and enqueues
backchannel logout requests to every connected application.
`post_logout_redirect_uri` is validated against the redirect URIs of every
registered client rather than the client named in the hint.

**Why it matters.** Any web page can sign the user out of the IdP and every
downstream app with an image tag. The OpenID Connect RP-Initiated Logout
specification says the OP should ask the user to confirm when no verified hint
is supplied. Accepting any client's redirect URI turns the endpoint into a
redirector for whichever client has the loosest registration.

**Fix.** When `id_token_hint` is present, verify its signature and issuer
(`OidcJwtService.decode_id_token` already exists), and confirm its subject
matches the current session. When it is absent, render a confirmation page
instead of logging out on GET. Validate `post_logout_redirect_uri` against the
hinted client only. Fix the state appending so it uses `&` when the URI already
carries a query string.

**Where.**
- `app/controllers/oidc_controller.rb:1243` (`params[:id_token_hint]` discarded)
- `app/controllers/oidc_controller.rb:1265` (`?state=` appended unconditionally)
- `app/controllers/oidc_controller.rb:1482` (`validate_logout_redirect_uri`)

---

### CLN-07 · `email_verified` is always true; email changes are never confirmed

**Severity:** Medium · **Status:** By inspection · **Effort:** Medium

- [x] Fixed — 23 September 2026. See Progress.

**What.** ID tokens and userinfo hard-code `email_verified: true`. Invited
users do prove control of their address by following the invitation link, but
the first user signs up with any address, admins can set any address, and a
user can change their own address from the profile page with only their
password. No confirmation is sent to the new address before it takes effect.

**Why it matters.** Many relying parties link or auto-provision accounts on a
verified email. A user who changes their address to a colleague's can be merged
into that colleague's account on any such app.

**Fix.** Add an `email_verified_at` column. Set it on invitation acceptance and
on confirmation of a change. Stage profile email changes as a pending address
until the confirmation link is followed. Emit `email_verified` from the column.

**Where.**
- `app/services/oidc_jwt_service.rb:37`
- `app/controllers/oidc_controller.rb:1034`
- `app/controllers/profiles_controller.rb:282`

---

## Worth fixing

### CLN-08 · Consent page is served without a form-action CSP directive

**Severity:** Medium · **Status:** Verified · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

**What.** In Rails, calling `csp.form_action` with no arguments deletes the
directive and returns its old value. The authorize action calls it twice: once
inside `respond_to?`, which removes the directive, and once to append, which
returns nil and raises `NoMethodError`. The rescue logs a warning and the page
ships with no form-action restriction at all. The sign-in page already has the
correct pattern in `allow_oauth_redirect_in_csp`, and the CSP test suite covers
only that page.

**Why it matters.** Form-action is the CSP defence against a form being
retargeted by injected markup. The consent page is exactly where an
authorization code is about to be handed over. Today a header the team believes
is in place is silently absent.

**Fix.** Replace the block with a call to the existing helper, mutating
`csp.directives["form-action"]`. Extend the CSP integration test to assert
form-action on the consent response.

**Where.**
- `app/controllers/oidc_controller.rb:449`
- `app/controllers/concerns/authentication.rb:70` (correct pattern)
- `test/integration/csp_test.rb:35` (extend)

---

### CLN-09 · Internal-IP host authorisation patterns are unanchored

**Severity:** Low · **Status:** Verified · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

**What.** With `CLINCH_ALLOW_INTERNAL_IPS=true`, which is the value in the
example env file, the allowed-host list gains regexes such as
`/192\.168\.\d+\.\d+/`. They are not anchored, so `192.168.1.1.evil.com` is an
allowed host. The registrable-domain pattern directly above them is anchored
correctly.

**Why it matters.** Host authorisation is the DNS-rebinding defence. The app
generally avoids trusting the request host, but the cookie domain is derived
from it, so a rebinding attack could get further than intended.

**Fix.** Anchor with `\A` and `\z`, and either require octets to be in range or
match with `IPAddr` in a proc.

**Where.**
- `config/environments/production.rb:144`
- `.env.example` (documents `CLINCH_ALLOW_INTERNAL_IPS=true`)

---

### CLN-10 · Session cookie is scoped to the registrable domain and never fully cleared

**Severity:** Medium · **Status:** By inspection · **Effort:** Small

- [ ] Fixed

**What.** On sign-in the session cookie is set with `Domain=.example.com` so
that reverse proxies can forward it to `/api/verify`. Every host under that
domain therefore receives the IdP session cookie on every request, including
every application behind forward auth and anything else on a sibling
subdomain. A compromised app can replay the cookie against Clinch as that user,
including admins. Any sibling host can also plant a cookie for the parent
domain, which enables session swapping. Sign-out and the `prompt=login` /
`max_age` paths call `cookies.delete(:session_id)` without the domain option,
so the browser keeps the stale cookie; the server-side session is destroyed, so
this part is hygiene rather than a bypass.

**Why it matters.** This is the standard trade-off of cookie-based forward auth
and Authelia makes the same choice, but it deserves to be an explicit,
documented decision rather than an implicit one. OIDC-only deployments pay the
cost without the benefit.

**Fix.** Document the trust boundary prominently in the README. Set the domain
attribute only when at least one forward-auth application exists. Pass the same
domain to every `cookies.delete`. Longer term, consider a separate short-lived
forward-auth cookie so the primary IdP session never leaves the auth host.

**Where.**
- `app/controllers/concerns/authentication.rb:83` (domain derived and set)
- `app/controllers/concerns/authentication.rb:125` (`terminate_session` delete)
- `app/controllers/oidc_controller.rb:312` and `:342` (deletes in authorize)

---

### CLN-11 · Changing a password from the profile keeps other sessions alive

**Severity:** Low · **Status:** Verified · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

**What.** Password reset by email destroys every session. Changing the password
from the profile page, which is what a user does after noticing something
suspicious, leaves all other sessions intact.

**Fix.** After a successful profile password change, destroy every session
except the current one. Consider the same for passkey removal and TOTP disable.

**Where.**
- `app/controllers/profiles_controller.rb:267`
- `app/controllers/passwords_controller.rb:24` (existing behaviour to mirror)

---

### CLN-12 · Revocation endpoint does not check token ownership

**Severity:** Low · **Status:** By inspection · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

**What.** After authenticating the calling client, the revoke action looks up
the token and revokes it without confirming the token was issued to that
client. RFC 7009 §2.1 requires the request to be refused in that case. Public
clients cannot revoke at all because a secret is required.

**Fix.** Compare `record.application_id` to the caller before revoking, and
still return 200. Allow public clients to revoke their own tokens with
`client_id` alone, as the specification permits.

**Where.**
- `app/controllers/oidc_controller.rb:1174` (secret required)
- `app/controllers/oidc_controller.rb:1213` (no ownership check)

---

## Lower priority

### CLN-13 · ActionCable connection skips session expiry and active-user checks

**Severity:** Low · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

The cable connection looks up the session by ID only, without the `active` and
`for_active_user` scopes used by the HTTP path. Nothing subscribes today, so
there is no current exposure. Reuse the same scoped lookup, or remove the
`/cable` mount until a channel needs it.

**Where.** `app/channels/application_cable/connection.rb:12`

---

### CLN-14 · Userinfo accepts the access token in the query string

**Severity:** Low · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

A GET with `?access_token=` is honoured, which puts bearer tokens in proxy and
application logs. RFC 6750 §2.3 discourages this method. Accept the
Authorization header and form body only.

**Where.** `app/controllers/oidc_controller.rb:982`

---

### CLN-15 · Encryption still accepts unencrypted TOTP secrets

**Severity:** Low · **Effort:** Small

- [ ] Fixed

`support_unencrypted_data` is true, so a plaintext value in the TOTP secret
column is read silently instead of raising. Run the re-encryption task on
existing rows and set the flag to false.

**Where.** `config/initializers/active_record_encryption.rb:28`

---

### CLN-16 · Single signing key with no rotation path

**Severity:** Low · **Effort:** Medium

- [ ] Fixed

JWKS publishes one RSA key derived from `OIDC_PRIVATE_KEY`. Rotating it
invalidates every outstanding ID token and logout token at once, so in practice
it will never be rotated. Accept an optional previous key, publish both in JWKS
during the overlap, sign with the current one, and document the procedure in
`oidc-key-setup.md`.

**Where.** `app/services/oidc_jwt_service.rb:134`, `:166`

---

### CLN-17 · Forward-auth API key path allows requests with no host header

**Severity:** Low · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

The cookie path fails closed when no forwarded host is present. The bearer path
only checks the domain when a host is present, so a proxy misconfiguration that
drops the header still yields identity headers. Require a forwarded host on
both paths.

**Where.** `app/controllers/api/forward_auth_controller.rb:132`

---

### CLN-18 · Backchannel logout leaves a DNS rebinding window after the SSRF check

**Severity:** Low · **Effort:** Small

- [ ] Fixed

The job resolves the host to confirm it is public, then hands the hostname to
Net::HTTP, which resolves it again. A hostile DNS server can answer differently
the second time. The URI is admin-configured, so exposure is limited. Connect
to the checked IP address and set the Host header and SNI to the original
hostname.

**Where.** `app/jobs/backchannel_logout_job.rb:34`

---

### CLN-19 · WebAuthn failures echo library exception text to the client

**Severity:** Low · **Effort:** Small

- [x] Fixed — fixed 3 September 2026, regression test in place

Registration and authentication rescue blocks interpolate `e.message` into the
JSON response, which can reveal origin, RP ID, and counter details. Log the
message and return a fixed string.

**Where.** `app/controllers/sessions_controller.rb:332`,
`app/controllers/webauthn_controller.rb:265`

---

### CLN-20 · No audit log of admin actions or authentication events

**Severity:** Low · **Effort:** Large

- [ ] Fixed

Sign-ins, failed attempts, admin edits to users, groups, and applications, and
credential changes are written to the application log only, at varying levels.
There is no queryable record and nothing an admin can review from the UI. Add
an append-only events table written from the controllers that already send
security emails, plus admin CRUD. Expose recent events on the admin dashboard
and on each user's page.

**Where.** `app/mailers/security_mailer.rb`, `app/controllers/admin/`

---

## What held up

These areas were examined and found sound. Listing them keeps the team from
re-auditing what is already right.

- PKCE restricted to S256 and required for public clients
- Authorization codes single-use under a row lock, with family revocation on replay
- Device codes single-use under a row lock, CSPRNG user codes, `slow_down` capped
- Tokens and codes stored as HMACs, never in plaintext
- Client secrets bcrypt hashed and shown once
- Redirect URIs exact-matched before any redirect-based error
- Consent endpoint keeps CSRF protection; parameters come from the server session
- Introspection restricted to the issuing client or a registered resource server
- Forward-auth handoff token bound to the destination host, 60-second TTL, single use
- Forward-auth redirect targets validated against registered domain patterns
- `CLINCH_HOST` required at boot; request host never used for the issuer or login URL
- Backchannel logout URIs checked against private, loopback, and link-local space
- CSP with per-response nonces, no `unsafe-inline`, `frame-ancestors 'none'`
- TOTP replay closed with the `after:` parameter; backup codes bcrypt hashed and per-user throttled
- Passkey clone detection on the signature counter with user notification
- Sensitive parameters filtered from logs; Sentry PII disabled
- Dynamic client registration off by default; registered clients are default-deny
- Access control is default-deny: an app with no groups admits nobody
- Container runs as a non-root user; Brakeman and bundler-audit wired in as rake tasks
- Security emails on password, email, passkey, TOTP, and API key changes

Brakeman's three warnings are not actionable: `:admin` in group mass assignment
is intended admin functionality, the `landing_url` link is admin-controlled and
format-validated, and the QR code SVG is generated from a server-side value.

---

## Suggested order of work

1. ~~**CLN-01, CLN-04, CLN-08, CLN-09, CLN-11** are each under an hour and four of
   them already have a failing test in the appendix. Ship these together.~~
   **Done 3 September 2026**, together with CLN-12, 13, 14, 17 and 19.
2. **CLN-02 and CLN-03** change sign-in behaviour and need a decision on whether
   to require user verification outright. Decide, then implement in one release
   with a changelog note.
3. **CLN-05, CLN-06, CLN-07** touch the contract with relying parties. Plan the
   deterministic subject migration carefully so existing consents keep their
   current `sid`.
4. Fold the remaining items into normal maintenance.

Each fix should start from a failing test. The probes below assert the
*insecure* behaviour, so inverting each assertion produces the regression test
for that finding.

---

## Appendix: verification probes

This is the integration test used to confirm the verified findings. It passed
7 of 7 against revision `bf10995`, meaning every insecure behaviour it asserts
was present.

It now lives at `test/integration/security_review_probe_test.rb` with every
assertion inverted as its finding was fixed, so it reads as a regression suite
rather than a probe. The version below is preserved as the original evidence —
do not re-run it as-is; it asserts the bugs.

```ruby
require "test_helper"

# Each test asserts the *insecure* behaviour, so a PASS confirms the finding.
class ReviewProbeTest < ActionDispatch::IntegrationTest
  test "CLN-08 consent page CSP has no form-action directive" do
    bob = users(:bob)
    app = applications(:kavita_app)
    sign_in_as(bob)
    get "/oauth/authorize", params: {
      client_id: app.client_id, redirect_uri: "https://kavita.example.com/signin-oidc",
      response_type: "code", scope: "openid"
    }
    assert_response :success
    assert_match(/requesting access/, response.body)
    csp = response.headers["Content-Security-Policy"].to_s
    refute_match(/form-action/, csp, "expected form-action to be missing: #{csp}")
  end

  test "CLN-01 disabled user's access token still works at userinfo and introspect" do
    alice = users(:alice)
    app = applications(:kavita_app)
    token = OidcAccessToken.create!(application: app, user: alice, scope: "openid email")
    alice.update!(status: :disabled)
    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}
    assert_response :success
    assert_equal "alice@example.com", JSON.parse(response.body)["email"]

    secret = app.generate_new_client_secret!
    post "/oauth/introspect", params: {token: token.plaintext_token, client_id: app.client_id, client_secret: secret}
    assert_equal true, JSON.parse(response.body)["active"]
  end

  test "CLN-05 revoke_all_consents leaves tokens valid and sub falls back to numeric user id" do
    alice = users(:alice)
    app = applications(:kavita_app)
    token = OidcAccessToken.create!(application: app, user: alice, scope: "openid email")
    sign_in_as(alice)
    delete "/active_sessions/revoke_all_consents"
    assert_redirected_to "/active_sessions"
    assert_equal 0, alice.oidc_user_consents.count
    get "/oauth/userinfo", headers: {"Authorization" => "Bearer #{token.plaintext_token}"}
    assert_response :success
    assert_equal alice.id.to_s, JSON.parse(response.body)["sub"]
  end

  test "CLN-06 GET /logout with no id_token_hint destroys the session" do
    alice = users(:alice)
    sign_in_as(alice)
    sid = Session.last.id
    get "/logout"
    assert_redirected_to "/"
    assert_nil Session.find_by(id: sid)
  end

  test "CLN-11 profile password change keeps other sessions alive" do
    alice = users(:alice)
    other = alice.sessions.create!(user_agent: "other device")
    sign_in_as(alice)
    patch "/profile", params: {user: {current_password: "password", password: "newpassword123", password_confirmation: "newpassword123"}}
    assert_redirected_to "/profile"
    assert Session.exists?(other.id), "other session should have been revoked"
  end

  test "CLN-09 internal-IP host patterns are unanchored" do
    assert_match(/192\.168\.\d+\.\d+/, "192.168.1.1.evil.com")
    assert_match(/10\.\d+\.\d+\.\d+/, "evil.com.10.0.0.1")
  end

  test "CLN-04 refresh grant creates new tokens before consent check" do
    alice = users(:alice)
    app = applications(:another_app) # alice has no consent here
    secret = app.generate_new_client_secret!
    at = OidcAccessToken.create!(application: app, user: alice, scope: "openid")
    rt = OidcRefreshToken.create!(application: app, user: alice, oidc_access_token: at, scope: "openid")
    grant_everyone_access(app)
    before = OidcAccessToken.where(application: app, user: alice).count
    post "/oauth/token", params: {grant_type: "refresh_token", refresh_token: rt.token, client_id: app.client_id, client_secret: secret}
    assert_response :bad_request
    assert_equal "invalid_grant", JSON.parse(response.body)["error"]
    assert_equal before + 1, OidcAccessToken.where(application: app, user: alice).count, "a fresh access token was minted despite the error"
    assert rt.reload.revoked?, "the presented refresh token was revoked despite the error"
  end
end
```

---

**Scope.** Full read of `app/controllers`, `app/models`, `app/services`,
`app/jobs`, `config/initializers`, and production configuration at revision
`bf10995`, plus Brakeman and bundler-audit runs. Not in scope: the JavaScript
controllers, the reverse-proxy examples in `docs/`, and runtime penetration
testing against a deployed instance.
