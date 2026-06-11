# Security Review — Tracking

Status of findings from the multi-surface security review (OIDC/OAuth2, ForwardAuth,
WebAuthn/TOTP, sessions, admin/config). Work landed on branch
`security/forward-auth-and-consent-csrf`.

## ✅ Done (branch `security/forward-auth-and-consent-csrf`)

All HIGH findings are closed. Each fix has tests; suite is green.

| Commit | Fix | Sev |
|--------|-----|-----|
| `703d24e` | ForwardAuth fail-open when no host header; consent endpoint CSRF | HIGH ×2 |
| `8a095e4` | Bearer API-key skipped group check at use-time | HIGH |
| `96a657e` | Open redirect via unvalidated `X-Forwarded-Host` in login redirect | HIGH |
| `84ed462` | `CLINCH_HOST` made mandatory in deployed envs; dropped request-host fallback | MEDIUM |
| `f38ac2e` | TOTP code replay within drift window (+ latent plaintext backup-code bug) | HIGH |
| `406a79d` | SSRF via `backchannel_logout_uri` (metadata/loopback/RFC1918) | HIGH |
| `57d7d1f` | Host-auth regex unanchored (`evil-example.com` matched) | HIGH |
| `89bd5f1` | Disabled user could complete 2FA mid-flow / keep session; enforce active status | HIGH |
| `cd862c7` | TOTP/backup/OAuth/PKCE `code` params not filtered from logs | MEDIUM |
| `2426687` | `revoke_family!` didn't revoke access tokens on refresh-token reuse | HIGH |
| `44892e3` | WebAuthn clone detection logged but didn't block; false-positive on synced passkeys | HIGH |
| `d49e7ce` | CSP `unsafe-inline` removed (script-src + style-src → nonces) | HIGH |

**Verified false positive (no change):** PKCE *is* required by default —
`require_pkce` column defaults to `true` (`db/schema.rb`), token endpoint enforces
it, admin UI exposes the opt-out. Operational check: confirm no legacy confidential
apps sit on `require_pkce = false`.

**Follow-up before relying on CSP change:** do one manual browser pass (DevTools
console) on `/signin`, OAuth consent, a Turbo navigation, dark-mode toggle, and a
WebAuthn sign-in — expect zero CSP violations. Dev is report-only so violations
surface as warnings without breaking. Fallback if style-src surprises: keep
`style-src 'unsafe-inline'`, ship script-src only.

## ☐ Remaining — MEDIUM

- [ ] **`id_token_hint` ignored at OIDC logout** — any client can redirect logout to
      any other registered client's post-logout URI. Validate the hint's `aud` and
      scope the redirect to that app. `app/controllers/oidc_controller.rb` (logout).
- [ ] **`offline_access` doesn't gate refresh-token issuance** — refresh tokens are
      minted unconditionally; gate on the granted scope.
      `app/controllers/oidc_controller.rb` (authorization_code grant, ~line 564).
- [ ] **CSP-report endpoint hardening** — unauthenticated, no rate limit / body-size
      cap, logs raw CRLF (log injection). Sanitize values, cap size, rate-limit.
      `app/controllers/api/csp_controller.rb`.
- [ ] **Port not stripped from `X-Forwarded-Host`** in main verify + bearer paths →
      403 outages on non-standard ports (also a correctness bug). Reuse the
      port-stripping done in `check_forward_auth_token`.
      `app/controllers/api/forward_auth_controller.rb`.
- [ ] **WebAuthn `acr:"2"` without enforced user verification** — `user_verification:
      "preferred"` lets a PIN-less key authenticate yet reports verified 2FA. Use
      `"required"`, or downgrade `acr` to `"1"` when the UV flag is absent.
      `app/controllers/sessions_controller.rb` (webauthn_challenge/verify),
      `app/controllers/webauthn_controller.rb`.
- [ ] **`RESERVED_CLAIMS` incomplete** — missing `at_hash`/`auth_time`/`acr`; and
      `ApplicationUserClaims` has no reserved-name validation (User/Group do). Could
      let a custom claim overwrite a security claim. `app/services/oidc_jwt_service.rb`,
      `app/models/application_user_claim.rb`.
- [ ] **`reset_session` not called on login** — defensive best practice for an IdP;
      clears pre-auth session state. `app/controllers/concerns/authentication.rb`
      (`start_new_session_for`).
- [x] **Hardcoded private IP `192.168.2.246`** in `config/environments/production.rb`
      — removed; it was redundant with the `192.168.0.0/16` regex already in the
      `CLINCH_ALLOW_INTERNAL_IPS` block.
- [ ] **CSP `form-action` widened by unvalidated `redirect_uri`** before auth — only
      add to `form-action` if the client_id+redirect_uri is a registered pair.
      `app/controllers/concerns/authentication.rb` (`allow_oauth_redirect_in_csp`).
- [ ] **SVG `style` attribute permits `url()`/`expression()`** — mitigated today by
      `Content-Disposition: attachment`, but fragile. Sanitize CSS values or drop
      `style` from the allowlist. `app/models/svg_scrubber.rb`.
- [ ] **WebAuthn error messages leak internals** — return generic errors to client,
      log detail server-side. `app/controllers/sessions_controller.rb`,
      `app/controllers/webauthn_controller.rb`.
- [ ] **Account enumeration via webauthn challenge** — distinguishes "user not found"
      vs "no passkey". Return a uniform message. `app/controllers/sessions_controller.rb`
      (`webauthn_challenge`).
- [ ] **`token_family_id` only 31 bits** (`SecureRandom.random_number(2**31)`) —
      birthday collision ~46k; use a UUID/string. `app/models/oidc_refresh_token.rb`.
- [ ] **Session cookie uses sequential integer DB id** — HMAC-signed so not forgeable,
      but consider a random `token` column (Rails 8 generator default).
      `app/models/session.rb`, `app/controllers/concerns/authentication.rb`.
- [ ] **Login rate-limit is IP-only** — no account lockout (distributed brute force /
      credential stuffing). Add failed-count + `locked_until` on users.
- [ ] **Backup-code rate limit not reset on success** and is cache-based (resets on
      cache flush). Reset on success; consider DB-backed counter. `app/models/user.rb`.

## ☐ Remaining — LOW / INFO

- [ ] Public clients can't revoke their own tokens (revoke endpoint requires secret).
- [ ] Basic-auth client creds not URL-decoded per RFC 6749 §2.3.1.
- [ ] `token_hmac` columns nullable at DB level despite model `presence: true`.
- [ ] Group names allow commas → injection into `X-Remote-Groups` (false memberships
      downstream). Add a format validator. `app/models/group.rb`.
- [ ] `fa_token` leaks in redirect URL / Referer / history (60s TTL, host-bound).
- [ ] Admin `domain_pattern` allows ReDoS — add a format validator.
      `app/models/application.rb`.
- [ ] Forced-TOTP-setup login path can redirect-loop (`totp_required` + no TOTP).
- [ ] `complete_setup` creates an unprompted session for any authenticated user.
- [ ] Password min length only 8 — consider 12 + a max (bcrypt 72-byte truncation).
- [ ] `support_unencrypted_data: true` left enabled (TOTP secret encryption migration).
      `config/initializers/active_record_encryption.rb`.
- [ ] All crypto keys derived from a single `SECRET_KEY_BASE` root — document setting
      independent `ACTIVE_RECORD_ENCRYPTION_*` keys in production.
- [ ] Log injection via user `email_address` in ForwardAuth logs (strip CRLF / use
      structured logging). `app/controllers/api/forward_auth_controller.rb`.
- [ ] WebAuthn RP ID is the registrable domain (cross-subdomain credential roaming) —
      set `CLINCH_RP_ID` to the exact host unless roaming is intended.
      `config/initializers/webauthn.rb`.
