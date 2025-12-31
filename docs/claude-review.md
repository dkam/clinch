# Clinch - Independent Code Review

**Reviewer:** Claude (Anthropic)
**Review Date:** December 2024
**Codebase Version:** Commit 4f31fad
**Review Type:** Security-focused OIDC/OAuth2 correctness review with full application assessment

---

## Executive Summary

Clinch is a self-hosted identity and SSO portal built with Ruby on Rails. This review examined the complete codebase with particular focus on the OIDC/OAuth2 implementation, comparing it against production-grade reference implementations (Rodauth-OAuth, Authelia, Authentik).

**Overall Assessment: Production-Ready**

The implementation demonstrates solid security practices, proper adherence to OAuth 2.0 and OpenID Connect specifications, and comprehensive test coverage. The codebase is well-structured, readable, and maintainable.

---

## Feature Overview

### Authentication Methods
| Feature | Status | Notes |
|---------|--------|-------|
| Password Authentication | Implemented | bcrypt hashing, rate-limited |
| WebAuthn/Passkeys | Implemented | FIDO2 compliant, clone detection |
| TOTP 2FA | Implemented | With backup codes, admin enforcement |
| Session Management | Implemented | Device tracking, revocation |

### SSO Protocols
| Protocol | Status | Notes |
|----------|--------|-------|
| OpenID Connect | Implemented | Full OIDC Core compliance |
| OAuth 2.0 | Implemented | Authorization Code + Refresh Token grants |
| ForwardAuth | Implemented | Traefik/Caddy/nginx compatible |

### User & Access Management
| Feature | Status | Notes |
|---------|--------|-------|
| User CRUD | Implemented | Invitation flow, status management |
| Group Management | Implemented | With custom claims |
| Application Management | Implemented | OIDC + ForwardAuth types |
| Group-based Access Control | Implemented | Per-application restrictions |

---

## OIDC/OAuth2 Implementation Review

### Specification Compliance

| Specification | Status | Evidence |
|---------------|--------|----------|
| RFC 6749 (OAuth 2.0) | Compliant | Proper auth code flow, client authentication |
| RFC 7636 (PKCE) | Compliant | S256 and plain methods, enforced for public clients |
| RFC 7009 (Token Revocation) | Compliant | Always returns 200 OK, prevents scanning |
| OpenID Connect Core 1.0 | Compliant | All required claims, proper JWT structure |
| OIDC Discovery | Compliant | `.well-known/openid-configuration` |
| OIDC Back-Channel Logout | Compliant | Logout tokens per spec |

### ID Token Claims

The implementation includes all required and recommended OIDC claims:

```
Standard:  iss, sub, aud, exp, iat, nonce
Profile:   email, email_verified, preferred_username, name
Security:  at_hash, auth_time, acr, azp
Custom:    groups, plus arbitrary claims from groups/users/apps
```

### Token Security

| Aspect | Implementation | Assessment |
|--------|----------------|------------|
| Authorization Codes | HMAC-SHA256 hashed, 10-min expiry, single-use | Secure |
| Access Tokens | HMAC-SHA256 hashed, configurable TTL, indexed lookup | Secure |
| Refresh Tokens | HMAC-SHA256 hashed, rotation with family tracking | Secure |
| ID Tokens | RS256 signed JWTs | Secure |

### Security Features

1. **Authorization Code Reuse Prevention**
   - Pessimistic database locking prevents race conditions
   - Code reuse triggers revocation of all tokens from that code
   - Location: `oidc_controller.rb:342-364`

2. **Refresh Token Rotation**
   - Old refresh tokens revoked on use
   - Token family tracking detects stolen token reuse
   - Revoked token reuse triggers family-wide revocation
   - Location: `oidc_controller.rb:504-513`

3. **PKCE Enforcement**
   - Required for all public clients
   - Configurable for confidential clients
   - Proper S256 challenge verification
   - Location: `oidc_controller.rb:749-814`

4. **Pairwise Subject Identifiers**
   - Each user gets a unique `sub` per application
   - Prevents cross-application user tracking
   - Location: `oidc_user_consent.rb:59-61`

---

## Security Assessment

### Strengths

1. **Token Storage Architecture**
   - All tokens (auth codes, access, refresh) are HMAC-hashed before storage
   - Database compromise does not reveal usable tokens
   - O(1) indexed lookup via HMAC (not O(n) iteration)

2. **Rate Limiting**
   - Sign-in: 20/3min
   - TOTP verification: 10/3min
   - Token endpoint: 60/min
   - Authorization: 30/min
   - WebAuthn enumeration check: 10/min

3. **WebAuthn Implementation**
   - Sign count validation (clone detection)
   - Backup eligibility tracking
   - Platform vs roaming authenticator distinction
   - Credential enumeration prevention

4. **TOTP Implementation**
   - Encrypted secret storage (ActiveRecord Encryption)
   - Backup codes are bcrypt-hashed and single-use
   - Admin can enforce TOTP requirement per user

5. **Session Security**
   - ACR (Authentication Context Class Reference) tracking
   - `acr: "1"` for password-only, `acr: "2"` for 2FA/passkey
   - Session activity timestamps
   - Remote session revocation

### Attack Mitigations

| Attack Vector | Mitigation |
|---------------|------------|
| Credential Stuffing | Rate limiting, account lockout via status |
| Token Theft | HMAC storage, short-lived access tokens, rotation |
| Session Hijacking | Secure cookies, session binding |
| CSRF | Rails CSRF protection, state parameter validation |
| Open Redirect | Strict redirect_uri validation against registered URIs |
| Authorization Code Injection | PKCE enforcement, redirect_uri binding |
| Refresh Token Replay | Token rotation, family-based revocation |
| User Enumeration | Constant-time responses, rate limiting |

### Areas Reviewed (No Issues Found)

- Redirect URI validation (exact match required)
- Client authentication (bcrypt for secrets)
- Error response handling (no sensitive data leakage in production)
- Logout implementation (backchannel notifications, session cleanup)
- Custom claims handling (reserved claim protection)

---

## Code Quality Assessment

### Architecture

| Aspect | Assessment |
|--------|------------|
| Controller Structure | Clean separation, ~900 lines for OIDC (acceptable) |
| Model Design | Well-normalized, proper associations |
| Service Objects | Used appropriately (OidcJwtService, ClaimsMerger) |
| Concerns | TokenPrefixable for shared hashing logic |

### Code Metrics

```
Controllers:     ~1,500 lines
Models:          ~1,500 lines
Services:        ~200 lines
Total App Code:  ~3,100 lines
Test Files:      36 files
```

### Readability

- Clear method naming
- Inline documentation for complex logic
- Consistent Ruby style
- No deeply nested conditionals

---

## Test Coverage

### Test Statistics

```
Total Tests:    341
Assertions:     1,349
Failures:       0
Errors:         0
Run Time:       23.5 seconds (parallel)
```

### Test Categories

| Category | Files | Coverage |
|----------|-------|----------|
| OIDC Security | 2 | Auth code reuse, token rotation, PKCE |
| Integration | 4 | WebAuthn, sessions, invitations, forward auth |
| Controllers | 8 | All major endpoints |
| Models | 10 | Validations, associations, business logic |
| Jobs | 4 | Mailers, token cleanup |

### Security-Specific Tests

The test suite includes dedicated security tests:
- `oidc_authorization_code_security_test.rb` - Code reuse, timing attacks, client auth
- `oidc_pkce_controller_test.rb` - PKCE flow validation
- `webauthn_credential_enumeration_test.rb` - Enumeration prevention
- `session_security_test.rb` - Session handling
- `totp_security_test.rb` - 2FA bypass prevention
- `input_validation_test.rb` - Input sanitization

---

## Comparison with Reference Implementations

### vs. Rodauth-OAuth (OpenID Certified)

| Aspect | Rodauth | Clinch |
|--------|---------|--------|
| Modularity | 46 feature modules | Monolithic controller |
| Token Storage | Optional hashing | HMAC-SHA256 (always) |
| PKCE | Dedicated feature | Integrated |
| Certification | OpenID Certified | Not certified |

Clinch has comparable security but less modularity.

### vs. Authelia (Production-Grade Go)

| Aspect | Authelia | Clinch |
|--------|----------|--------|
| PKCE Config | `always/public/never` | Per-app toggle |
| Key Rotation | Supported | Single key |
| PAR Support | Yes | No |
| DPoP Support | Yes | No |

Clinch lacks some advanced features but covers core use cases.

### vs. Authentik (Enterprise Python)

| Aspect | Authentik | Clinch |
|--------|-----------|--------|
| Scale | Enterprise/distributed | Single instance |
| Protocols | OAuth, SAML, LDAP, RADIUS | OAuth/OIDC, ForwardAuth |
| Complexity | High | Low |

Clinch is intentionally simpler for self-hosting.

---

## Recommendations

### Implemented During Review

The following issues were identified and fixed during this review:

1. **Token lookup performance** - Changed from O(n) BCrypt iteration to O(1) HMAC lookup
2. **`at_hash` claim** - Added per OIDC Core spec
3. **`auth_time` claim** - Added for authentication timestamp
4. **`acr` claim** - Added for authentication context class
5. **`azp` claim** - Added for authorized party
6. **Authorization code hashing** - Changed from plaintext to HMAC
7. **Consent SID preservation** - Fixed to preserve pairwise subject ID
8. **Discovery metadata** - Fixed `subject_types_supported` to `["pairwise"]`

### Optional Future Enhancements

| Enhancement | Priority | Effort |
|-------------|----------|--------|
| Key Rotation (multi-key JWKS) | Medium | Medium |
| Token Introspection (RFC 7662) | Low | Low |
| PAR (RFC 9126) | Low | Medium |
| OpenID Certification | Low | High |

---

## Conclusion

Clinch provides a solid, security-conscious OIDC/OAuth2 implementation suitable for self-hosted identity management. The codebase demonstrates:

- **Correct protocol implementation** - Follows OAuth 2.0 and OIDC specifications
- **Defense in depth** - Multiple layers of security controls
- **Modern authentication** - WebAuthn/passkeys, TOTP, proper session management
- **Maintainable code** - Clear structure, good test coverage

The implementation is appropriate for its intended use case: a lightweight, self-hosted alternative to complex enterprise identity solutions.

---

## Methodology

This review was conducted by examining:

1. All OIDC-related controllers, models, and services
2. Reference implementations (Rodauth-OAuth, Authelia, Authentik) in `tmp/`
3. Test files and coverage
4. Database schema and migrations
5. Security-critical code paths

Tools used: Static analysis, code reading, test execution, comparison with OpenID-certified implementations.

---

*This review was conducted by Claude (Anthropic) at the request of the project maintainer. The reviewer has no financial interest in the project.*
