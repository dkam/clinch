# Security Status

**Last Audit:** 2025-12-31
**Target Users:** Self-hosters, small businesses

> **Beta Release Criteria:** See [beta-checklist.md](beta-checklist.md) for overall release readiness assessment.
>
> This document demonstrates our proactive approach to security through systematic vulnerability tracking and remediation.

---

## Summary

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1-2 | ✅ Complete | Rate limiting, security headers, tests |
| Phase 3 | ✅ Complete | Critical fixes (token DoS, plaintext storage, fail-open) |
| Phase 4 | ✅ Complete | High priority (PKCE, WebAuthn, email re-auth, TOTP encryption) |
| Phase 5 | 🟡 In Progress | Security enhancements |
| Phase 6 | ⏳ Optional | Hardening & documentation |

---

## Outstanding Security Issues

---

### MEDIUM - Account Lockout Mechanism

**Files:** `app/controllers/sessions_controller.rb`, `app/models/user.rb`
**Impact:** Brute force attack mitigation

**Implementation:**
- Add `failed_login_attempts` and `locked_until` columns to users
- Progressive delays: 5 attempts → 5s, 10 → 1min, 15 → 15min, 20+ → 1hr
- Admin notification on lockout
- Configurable via `MAX_LOGIN_ATTEMPTS` ENV

---

### MEDIUM - Per-Account Rate Limiting

**Files:** `app/controllers/sessions_controller.rb`, `config/initializers/rack_attack.rb`
**Impact:** Distributed brute force prevention

**Current:** Global rate limiting only
**Needed:** Add per-email rate limiting (10 failed attempts/email/hour)

---

### LOW - WebAuthn Clone Detection Action

**File:** `app/controllers/sessions_controller.rb:252-256`
**Impact:** Cloned credential detection

**Current:** Logs warning on suspicious sign count
**Improvement:** Block authentication, notify user/admin

---

## Configuration Choices (Not Vulnerabilities)

These are policy decisions for self-hosters, not security bugs:

| Item | Default | Notes |
|------|---------|-------|
| Session cookie domain | Root domain | Enables SSO across subdomains. Add `SECURE_SUBDOMAIN_ISOLATION` ENV to disable |
| CSP policy | unsafe-inline, unsafe-eval | Required for Stimulus/Turbo. Audit JS to remove if needed |
| Logout redirect validation | Allows query params | Per OAuth 2.0 spec. Document behavior |
| Invitation token lifetime | 24 hours | Add `INVITATION_TOKEN_LIFETIME` ENV for high-security deployments |
| Password minimum length | 8 chars | Add `PASSWORD_MIN_LENGTH` ENV, consider zxcvbn |
| Admin self-demotion check | String comparison | Minor - use `.to_i` for integer comparison |

---

## Completed Fixes

### Phase 3 - Critical (December 2025)

**1. Token Lookup DoS** ✅
- Problem: O(n) BCrypt comparisons on token lookup
- Solution: HMAC-based token prefix for O(1) indexed lookup
- Files: `token_prefixable.rb`, token models, migration

**2. Plaintext Token Storage** ✅
- Problem: Access tokens stored in plaintext
- Solution: Removed `token` column, use BCrypt digest only
- Files: Migration, fixtures, tests

**3. Forward Auth Fail-Open** ✅
- Problem: Unmatched domains allowed by default
- Solution: Changed to fail-closed (403 for unconfigured domains)
- Files: `forward_auth_controller.rb`

---

### Phase 4 - High Priority (December 2025)

**4. PKCE Enforcement** ✅
- Problem: PKCE was optional
- Solution: Per-app PKCE with mandatory enforcement for public clients
- Files: Application model, OIDC controller, migration

**5. WebAuthn Info Disclosure** ✅
- Problem: `/webauthn/check` leaked user_id and preferred_method
- Solution: Minimal response, rate limiting (10/min), identical responses for non-existent users
- Files: `webauthn_controller.rb`

**6. OIDC State URL Encoding** ✅
- Problem: State parameter not consistently URL-encoded
- Solution: `CGI.escape()` on all redirect URLs
- Files: `oidc_controller.rb` (4 locations)

**7. Email Change Re-authentication** ✅
- Problem: Email could be changed without password
- Solution: Require current password for email changes
- Files: `profiles_controller.rb`, view

**12. TOTP Secret Encryption** ✅
- Problem: TOTP secrets stored in plaintext
- Solution: Rails `encrypts` with keys derived from SECRET_KEY_BASE
- Files: `user.rb`, `active_record_encryption.rb`

**13. WebAuthn Credential ID Enumeration** ✅
- Problem: Global credential lookup allowed enumeration via 404 vs 403 responses
- Solution: Scoped credential lookup to current user, identical responses
- Files: `webauthn_controller.rb`, `webauthn_credential_enumeration_test.rb`

---

## Security Strengths

- **Token security:** HMAC prefix + BCrypt, no plaintext storage
- **Authorization codes:** Pessimistic locking, single-use enforcement
- **Refresh tokens:** Family tracking for rotation attack detection
- **Reserved claims:** Validation prevents claim override attacks
- **Rate limiting:** Applied on all authentication endpoints
- **Forward auth:** Fail-closed by default
- **TOTP:** AES-256-GCM encryption at rest
- **Email changes:** Require password re-authentication
- **Credential isolation:** Scoped lookups prevent enumeration attacks

---

## Audit History

| Date | Event |
|------|-------|
| 2025-12-31 | Credential ID enumeration fix (scoped lookups) |
| 2025-12-31 | Security review - 1 new issue found (credential enumeration) |
| 2025-12-31 | Phase 4 completed (PKCE, WebAuthn, email re-auth, TOTP) |
| 2025-12-30 | Phase 3 completed (token DoS, plaintext storage, fail-open) |
| 2025-12-30 | Comprehensive security audit - 18 issues identified |
| Earlier | Phase 1-2 completed (rate limiting, headers, tests) |
