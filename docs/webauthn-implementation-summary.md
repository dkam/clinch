# WebAuthn/Passkeys Implementation - Quick Start

This is a companion summary to the [full implementation plan](webauthn-passkeys-plan.md).

## What We're Building

Add modern passwordless authentication (passkeys) to Clinch, allowing users to sign in with Face ID, Touch ID, Windows Hello, or hardware security keys (YubiKey).

## Quick Overview

### Features
- **Passwordless login** - Sign in with biometrics, no password needed
- **Multi-device support** - Register passkeys on multiple devices
- **Synced passkeys** - Works with iCloud Keychain, Google Password Manager
- **2FA option** - Use passkeys as second factor instead of TOTP
- **Hardware keys** - Support for YubiKey and other FIDO2 devices
- **User management** - Register, name, and delete multiple passkeys

### Tech Stack
- `webauthn` gem (~3.0) - Server-side WebAuthn implementation
- Browser WebAuthn API - Native browser support (no JS libraries needed)
- Stimulus controller - Frontend UX management

## 5-Phase Implementation

### Phase 1: Foundation (Week 1-2)
Core WebAuthn registration and authentication
- Database schema for credentials
- Registration ceremony (add passkey)
- Authentication ceremony (sign in with passkey)
- Basic JavaScript integration

### Phase 2: User Experience (Week 2-3)
Polished UI and management
- Profile page: list/manage passkeys
- Login page: "Sign in with Passkey" button
- Nickname management
- First-run wizard update

### Phase 3: Security (Week 3-4)
Advanced security features
- Sign count verification (clone detection)
- Attestation validation (optional)
- User verification requirements
- Admin controls and policies

### Phase 4: Integration (Week 4)
Connect with existing features
- OIDC integration (AMR claims)
- WebAuthn as 2FA option
- ForwardAuth compatibility
- Account recovery flows

### Phase 5: Testing & Docs (Week 4-5)
Quality assurance
- Unit, integration, and system tests
- Virtual authenticator testing
- User and admin documentation
- Security audit

## Database Schema

### New Table: `webauthn_credentials`
```ruby
create_table :webauthn_credentials do |t|
  t.references :user, null: false, foreign_key: true
  t.string :external_id, null: false        # Credential ID
  t.string :public_key, null: false         # Public key
  t.integer :sign_count, default: 0         # For clone detection
  t.string :nickname                        # "MacBook Touch ID"
  t.string :authenticator_type              # platform/cross-platform
  t.datetime :last_used_at
  t.timestamps
end
```

### Update `users` table
```ruby
add_column :users, :webauthn_id, :string           # User handle
add_column :users, :webauthn_required, :boolean    # Policy enforcement
```

## Key User Flows

### 1. Register Passkey
```
User profile → "Add Passkey" → Browser prompt →
Touch ID/Face ID → Passkey saved → Can sign in
```

### 2. Sign In with Passkey
```
Login page → Enter email → "Continue with Passkey" →
Browser prompt → Touch ID/Face ID → Signed in
```

### 3. WebAuthn as 2FA
```
Enter password → Prompted for passkey →
Touch ID/Face ID → Signed in
```

## Security Highlights

1. **Phishing-resistant** - Passkeys are bound to the domain
2. **No shared secrets** - Public key cryptography
3. **Clone detection** - Sign count verification
4. **User verification** - Biometric or PIN required
5. **Privacy-preserving** - Opaque user handles

## Integration Points

### OIDC
- Add `amr` claim: `["webauthn"]`
- Support `acr_values=webauthn` in authorization request
- Include authentication method in ID token

### ForwardAuth
- WebAuthn creates standard sessions
- Works automatically with existing `/api/verify` endpoint
- Optional header: `Remote-Auth-Method: webauthn`

### Admin Controls
- Require WebAuthn for specific users/groups
- View all registered passkeys
- Revoke compromised credentials
- Audit log of authentications

## Files to Create/Modify

### New Files (~12)
- `app/models/webauthn_credential.rb`
- `app/controllers/webauthn_controller.rb`
- `app/javascript/controllers/webauthn_controller.js`
- `config/initializers/webauthn.rb`
- Views for registration/management
- Tests (model, controller, integration, system)
- Documentation (user guide, admin guide)

### Modified Files (~8)
- `Gemfile` - Add webauthn gem
- `app/models/user.rb` - Add associations/methods
- `app/controllers/sessions_controller.rb` - WebAuthn authentication
- `app/views/sessions/new.html.erb` - Add passkey button
- `app/views/profiles/show.html.erb` - Passkey management
- `config/routes.rb` - WebAuthn routes
- `README.md` - Document feature
- `app/controllers/oidc_controller.rb` - AMR claims

## Browser Support

### Supported (WebAuthn Level 2)
- Chrome/Edge 90+
- Firefox 90+
- Safari 14+ (macOS Big Sur / iOS 14+)

### Platform Authenticators
- macOS: Touch ID
- iOS/iPadOS: Face ID, Touch ID
- Windows: Windows Hello (face, fingerprint, PIN)
- Android: Fingerprint, face unlock

### Roaming Authenticators
- YubiKey 5 series
- SoloKeys
- Google Titan Security Key
- Any FIDO2-certified hardware key

## Open Questions

1. **Attestation**: Validate authenticator hardware? (Recommend: No for v1)
2. **Resident Keys**: Require discoverable credentials? (Recommend: Preferred, not required)
3. **Synced Passkeys**: Allow iCloud/Google sync? (Recommend: Yes)
4. **Recovery**: How to recover if all passkeys lost? (Recommend: Email verification)
5. **2FA**: Replace TOTP or offer both? (Recommend: Offer both)
6. **Enforcement**: When to require passkeys? (Recommend: 3 months after launch for admins)

## Success Metrics

### Adoption
- % of users with ≥1 passkey
- % of logins using passkey vs password
- Average registration time

### Security
- Reduced password reset requests
- Reduced account takeover attempts
- Zero phishing success (passkeys can't be phished)

### Performance
- Faster authentication time
- Low error rate (<5%)
- High browser compatibility (>95%)

## Timeline

- **Week 1-2**: Foundation (Phase 1)
- **Week 2-3**: UX & Testing (Phase 2 + Phase 5 start)
- **Week 3-4**: Security & Integration (Phase 3 + Phase 4)
- **Week 4-5**: Beta testing and documentation
- **Week 5+**: Production rollout

**Total**: 4-6 weeks for full implementation and testing

## Next Steps

1. ✅ Review this plan
2. ⬜ Create Gitea issues for each phase
3. ⬜ Add `webauthn` gem to Gemfile
4. ⬜ Create database migrations
5. ⬜ Implement Phase 1 (registration ceremony)
6. ⬜ Implement Phase 1 (authentication ceremony)
7. ⬜ Add JavaScript frontend
8. ⬜ Test with virtual authenticators
9. ⬜ Continue through remaining phases

## Resources

- [Full Implementation Plan](webauthn-passkeys-plan.md) - Detailed 50+ page document
- [W3C WebAuthn Spec](https://www.w3.org/TR/webauthn-2/)
- [webauthn-ruby gem](https://github.com/cedarcode/webauthn-ruby)
- [WebAuthn Guide](https://webauthn.guide/)
- [MDN Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)

## Questions?

Refer to the [full implementation plan](webauthn-passkeys-plan.md) for:
- Detailed technical specifications
- Security considerations
- Code examples
- Testing strategies
- Migration strategies
- Complete API reference

---

*Status: Ready for Review*
*See: [webauthn-passkeys-plan.md](webauthn-passkeys-plan.md) for full details*
