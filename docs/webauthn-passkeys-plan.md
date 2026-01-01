# WebAuthn / Passkeys Implementation Plan for Clinch

## Executive Summary

This document outlines a comprehensive plan to add WebAuthn/Passkeys support to Clinch, enabling modern passwordless authentication alongside the existing password + TOTP authentication methods.

## Goals

1. **Primary Authentication**: Allow users to register and use passkeys as their primary login method (passwordless)
2. **MFA Enhancement**: Support passkeys as a second factor alongside TOTP
3. **Cross-Device Support**: Enable both platform authenticators (Face ID, Touch ID, Windows Hello) and roaming authenticators (YubiKey, security keys)
4. **User Experience**: Provide seamless registration, authentication, and management of multiple passkeys
5. **Backward Compatibility**: Maintain existing password + TOTP flows without disruption

## Architecture Overview

### Technology Stack
- **webauthn gem** (~3.0): Ruby library for WebAuthn server implementation
- **Rails 8.1**: Existing framework
- **Browser WebAuthn API**: Native browser support (all modern browsers)

### Core Components

1. **WebAuthn Credentials Model**: Store registered authenticators
2. **WebAuthn Controller**: Handle registration and authentication ceremonies
3. **Session Flow Updates**: Integrate passkey authentication into existing login flow
4. **User Management UI**: Allow users to register, name, and delete passkeys
5. **Admin Controls**: Configure WebAuthn policies per user/group

---

## Database Schema

### New Table: `webauthn_credentials`

```ruby
create_table :webauthn_credentials do |t|
  t.references :user, null: false, foreign_key: true, index: true

  # WebAuthn specification fields
  t.string :external_id, null: false, index: { unique: true }  # credential ID (base64)
  t.string :public_key, null: false                             # public key (base64)
  t.integer :sign_count, null: false, default: 0                # signature counter (clone detection)

  # Metadata
  t.string :nickname                                            # User-friendly name ("MacBook Touch ID")
  t.string :authenticator_type                                  # "platform" or "cross-platform"
  t.boolean :backup_eligible, default: false                    # Can be backed up (passkey sync)
  t.boolean :backup_state, default: false                       # Currently backed up

  # Tracking
  t.datetime :last_used_at
  t.string :last_used_ip
  t.string :user_agent                                          # Browser/OS info

  timestamps
end

add_index :webauthn_credentials, [:user_id, :external_id], unique: true
```

### Update `users` table

```ruby
add_column :users, :webauthn_required, :boolean, default: false, null: false
add_column :users, :webauthn_id, :string  # WebAuthn user handle (random, stable, opaque)
add_index :users, :webauthn_id, unique: true
```

---

## Implementation Phases

### Phase 1: Foundation (Core WebAuthn Support)

**Objective**: Enable basic passkey registration and authentication

#### 1.1 Setup & Dependencies

- [ ] Add `webauthn` gem to Gemfile (~3.0)
- [ ] Create WebAuthn initializer with configuration
- [ ] Generate migration for `webauthn_credentials` table
- [ ] Add WebAuthn user handle generation to User model

#### 1.2 Models

**File**: `app/models/webauthn_credential.rb`
```ruby
class WebauthnCredential < ApplicationRecord
  belongs_to :user

  validates :external_id, presence: true, uniqueness: true
  validates :public_key, presence: true
  validates :sign_count, presence: true, numericality: { greater_than_or_equal_to: 0 }

  scope :active, -> { where(revoked_at: nil) }
  scope :platform_authenticators, -> { where(authenticator_type: "platform") }
  scope :roaming_authenticators, -> { where(authenticator_type: "cross-platform") }

  # Update last used timestamp and sign count after successful authentication
  def update_usage!(sign_count:, ip_address: nil)
    update!(
      last_used_at: Time.current,
      last_used_ip: ip_address,
      sign_count: sign_count
    )
  end
end
```

**Update**: `app/models/user.rb`
```ruby
has_many :webauthn_credentials, dependent: :destroy

# Generate stable WebAuthn user handle on first use
def webauthn_user_handle
  return webauthn_id if webauthn_id.present?

  # Generate random 64-byte opaque identifier (base64url encoded)
  handle = SecureRandom.urlsafe_base64(64)
  update_column(:webauthn_id, handle)
  handle
end

def webauthn_enabled?
  webauthn_credentials.active.exists?
end

def can_authenticate_with_webauthn?
  webauthn_enabled? && active?
end
```

#### 1.3 WebAuthn Configuration

**File**: `config/initializers/webauthn.rb`
```ruby
WebAuthn.configure do |config|
  # Relying Party name (displayed in authenticator)
  config.origin = ENV.fetch("CLINCH_HOST", "http://localhost:3000")

  # Relying Party ID (must match origin domain)
  config.rp_name = "Clinch Identity Provider"

  # Credential timeout (60 seconds)
  config.credential_options_timeout = 60_000

  # Supported algorithms (ES256, RS256)
  config.algorithms = ["ES256", "RS256"]
end
```

#### 1.4 Registration Flow (Ceremony)

**File**: `app/controllers/webauthn_controller.rb`

Key actions:
- `GET /webauthn/new` - Display registration page
- `POST /webauthn/challenge` - Generate registration challenge
- `POST /webauthn/create` - Verify and store credential

**Registration Process**:
1. User clicks "Add Passkey" in profile settings
2. Server generates challenge options (stored in session)
3. Browser calls `navigator.credentials.create()`
4. User authenticates with device (Touch ID, Face ID, etc.)
5. Browser returns signed credential
6. Server verifies signature and stores credential

#### 1.5 Authentication Flow (Ceremony)

**Update**: `app/controllers/sessions_controller.rb`

New actions:
- `POST /sessions/webauthn/challenge` - Generate authentication challenge
- `POST /sessions/webauthn/verify` - Verify credential and sign in

**Authentication Process**:
1. User clicks "Sign in with Passkey" on login page
2. Server generates challenge (stored in session)
3. Browser calls `navigator.credentials.get()`
4. User authenticates with device
5. Browser returns signed assertion
6. Server verifies signature, checks sign count, creates session

#### 1.6 Frontend JavaScript

**File**: `app/javascript/controllers/webauthn_controller.js` (Stimulus)

Responsibilities:
- Encode/decode base64url data for WebAuthn API
- Handle browser WebAuthn API calls
- Error handling and user feedback
- Progressive enhancement (feature detection)

**Example registration**:
```javascript
async register() {
  const options = await this.fetchChallenge()
  const credential = await navigator.credentials.create(options)
  await this.submitCredential(credential)
}
```

---

### Phase 2: User Experience & Management

**Objective**: Provide intuitive UI for managing passkeys

#### 2.1 Profile Management

**File**: `app/views/profiles/show.html.erb` (update)

Features:
- List all registered passkeys with nicknames
- Show last used timestamp
- Badge for platform vs roaming authenticators
- Add new passkey button
- Delete passkey button (with confirmation)
- Show "synced passkey" badge if backup_state is true

#### 2.2 Registration Improvements

- Auto-detect device type and suggest nickname ("Chrome on MacBook")
- Show preview of what authenticator will display
- Require at least one authentication method (password OR passkey)
- Warning if removing last authentication method

#### 2.3 Login Page Updates

**File**: `app/views/sessions/new.html.erb` (update)

- Add "Sign in with Passkey" button (conditional rendering)
- Show button only if WebAuthn is supported by browser
- Progressive enhancement: fallback to password if WebAuthn fails
- Email field for identifying which user's passkeys to request

**Flow**:
1. User enters email address
2. Server checks if user has passkeys
3. If yes, show "Continue with Passkey" button
4. If no passkeys, show password field

#### 2.4 First-Run Wizard Update

**File**: `app/views/users/new.html.erb` (first-run wizard)

- Option to register passkey immediately after creating account
- Skip passkey registration if not supported or user declines
- Encourage passkey setup but don't require it

---

### Phase 3: Security & Advanced Features

**Objective**: Harden security and add enterprise features

#### 3.1 Sign Count Verification

**Purpose**: Detect cloned authenticators

Implementation:
- Store sign_count after each authentication
- Verify new sign_count > old sign_count
- If count doesn't increase: log warning, optionally disable credential
- Add admin alert for suspicious activity

#### 3.2 Attestation Validation (Optional)

**Purpose**: Verify authenticator is genuine hardware

Options:
- None (most compatible, recommended for self-hosted)
- Indirect (some validation)
- Direct (strict validation, enterprise)

**Configuration** (per-application):
```ruby
class Application < ApplicationRecord
  enum webauthn_attestation: {
    none: 0,
    indirect: 1,
    direct: 2
  }, _default: :none
end
```

#### 3.3 User Verification Requirements

**Levels**:
- `discouraged`: No user verification (not recommended)
- `preferred`: Request if available (default)
- `required`: Must have PIN/biometric (high security apps)

**Configuration**: Per-application setting

#### 3.4 Resident Keys (Discoverable Credentials)

**Feature**: Passkey contains username, no email entry needed

**Implementation**:
- Set `residentKey: "preferred"` or `"required"` in credential options
- Allow users to sign in without entering email first
- Add `POST /sessions/webauthn/discoverable` endpoint

**Benefits**:
- Faster login (no email typing)
- Better UX on mobile devices
- Works with password managers (1Password, etc.)

#### 3.5 Admin Controls

**File**: `app/views/admin/users/edit.html.erb`

Admin capabilities:
- View all user passkeys
- Revoke compromised passkeys
- Require WebAuthn for specific users/groups
- View WebAuthn authentication audit log
- Configure WebAuthn policies

**New fields**:
```ruby
# On User model
webauthn_required: boolean  # Must have at least one passkey

# On Group model
webauthn_enforcement: enum  # :none, :encouraged, :required
```

---

### Phase 4: Integration with Existing Flows

**Objective**: Seamlessly integrate with OIDC, ForwardAuth, and 2FA

#### 4.1 OIDC Authorization Flow

**Update**: `app/controllers/oidc_controller.rb`

Integration points:
- If user has no password but has passkey, trigger WebAuthn
- Application can request `webauthn` in `acr_values` parameter
- Include `amr` claim in ID token: `["webauthn"]` or `["pwd", "totp"]`

**Example ID token**:
```json
{
  "sub": "user-123",
  "email": "user@example.com",
  "amr": ["webauthn"],  // Authentication Methods References
  "acr": "urn:mace:incommon:iap:silver"
}
```

#### 4.2 WebAuthn as Second Factor

**Scenario**: User signs in with password, then WebAuthn as 2FA

**Flow**:
1. User enters password (first factor)
2. If `webauthn_required` is true OR user chooses WebAuthn
3. Trigger WebAuthn challenge (instead of TOTP)
4. User authenticates with passkey
5. Create session

**Configuration**:
```ruby
# User can choose 2FA method
user.preferred_2fa  # :totp or :webauthn

# Admin can require specific 2FA method
user.required_2fa   # :any, :totp, :webauthn
```

#### 4.3 ForwardAuth Integration

**Update**: `app/controllers/api/forward_auth_controller.rb`

No changes needed! WebAuthn creates standard sessions, ForwardAuth works as-is.

**Header injection**:
```
Remote-User: user@example.com
Remote-Groups: admin,family
Remote-Auth-Method: webauthn  # NEW optional header
```

#### 4.4 Backup Codes

**Consideration**: What if user loses all passkeys?

**Options**:
1. Keep existing backup codes system (works for TOTP, not WebAuthn-only)
2. Require email verification for account recovery
3. Require at least one roaming authenticator (YubiKey) + platform authenticator

**Recommended**: Require password OR email-verified recovery flow

---

### Phase 5: Testing & Documentation

**Objective**: Ensure reliability and provide clear documentation

#### 5.1 Automated Tests

**Test Coverage**:

1. **Model tests** (`test/models/webauthn_credential_test.rb`)
   - Credential creation and validation
   - Sign count updates
   - Credential scopes and queries

2. **Controller tests** (`test/controllers/webauthn_controller_test.rb`)
   - Registration challenge generation
   - Credential verification
   - Authentication challenge generation
   - Assertion verification

3. **Integration tests** (`test/integration/webauthn_authentication_test.rb`)
   - Full registration flow
   - Full authentication flow
   - Error handling (invalid signatures, expired challenges)

4. **System tests** (`test/system/webauthn_test.rb`)
   - End-to-end browser testing with virtual authenticator
   - Chrome DevTools Protocol virtual authenticator

**Example virtual authenticator test**:
```ruby
test "user registers passkey" do
  driver.add_virtual_authenticator(protocol: :ctap2)

  visit profile_path
  click_on "Add Passkey"
  fill_in "Nickname", with: "Test Key"
  click_on "Register"

  assert_text "Passkey registered successfully"
end
```

#### 5.2 Documentation

**Files to create/update**:

1. **User Guide** (`docs/webauthn-user-guide.md`)
   - What are passkeys?
   - How to register a passkey
   - How to sign in with a passkey
   - Managing multiple passkeys
   - Troubleshooting

2. **Admin Guide** (`docs/webauthn-admin-guide.md`)
   - WebAuthn policies and configuration
   - Enforcing passkeys for users/groups
   - Security considerations
   - Audit logging

3. **Developer Guide** (`docs/webauthn-developer-guide.md`)
   - Architecture overview
   - WebAuthn ceremony flows
   - Testing with virtual authenticators
   - OIDC integration details

4. **README Update** (`README.md`)
   - Add WebAuthn/Passkeys to Authentication Methods section
   - Update feature list

#### 5.3 Browser Compatibility

**Supported Browsers**:
- Chrome/Edge 90+ (Chromium)
- Firefox 90+
- Safari 14+ (macOS Big Sur, iOS 14)

**Graceful Degradation**:
- Feature detection: check `window.PublicKeyCredential`
- Hide passkey UI if not supported
- Always provide password fallback

---

## Security Considerations

### 1. Challenge Storage
- Store challenges in server-side session (not cookies)
- Challenges expire after 60 seconds
- One-time use (mark as used after verification)

### 2. Origin Validation
- WebAuthn library automatically validates origin
- Ensure `CLINCH_HOST` environment variable is correct
- Must use HTTPS in production (required by WebAuthn spec)

### 3. Relying Party ID
- Must match the origin domain
- Cannot be changed after credentials are registered
- Use apex domain for subdomain compatibility (e.g., `example.com` works for `auth.example.com` and `app.example.com`)

### 4. User Handle Privacy
- User handle is opaque, random, and stable
- Never use email or user ID as user handle
- Store in `users.webauthn_id` column

### 5. Sign Count Verification
- Always check sign_count increases
- Log suspicious activity (counter didn't increase)
- Consider disabling credential if counter resets

### 6. Credential Backup Awareness
- Track `backup_eligible` and `backup_state` flags
- Inform users about synced passkeys
- Higher security apps may want to disallow backed-up credentials

### 7. Account Recovery
- Don't lock users out if they lose all passkeys
- Require email verification for recovery
- Send alerts when recovery is used

---

## Migration Strategy

### For Existing Users

**Option 1: Opt-in (Recommended)**
- Add "Register Passkey" button in profile settings
- Show banner encouraging passkey setup
- Don't require passkeys initially
- Gradually increase adoption through UI prompts

**Option 2: Mandatory Migration**
- Set deadline for passkey registration
- Email users with instructions
- Admins can enforce passkey requirement per group
- Provide support documentation

### For New Users

**During First-Run Wizard**:
1. Create account with email + password (existing flow)
2. Offer optional passkey registration
3. If accepted, walk through registration
4. If declined, remind later in dashboard

---

## Performance Considerations

### Database Indexes
```ruby
# Essential indexes for performance
add_index :webauthn_credentials, :user_id
add_index :webauthn_credentials, :external_id, unique: true
add_index :webauthn_credentials, [:user_id, :last_used_at]
```

### Query Optimization
- Eager load credentials with user: `User.includes(:webauthn_credentials)`
- Cache credential count: `user.webauthn_credentials.count`

### Cleanup Jobs
- Remove expired challenges from session store
- Archive old credentials (last_used > 1 year ago)

---

## Rollout Plan

### Phase 1: Development (Week 1-2)
- [ ] Setup gem and database schema
- [ ] Implement registration ceremony
- [ ] Implement authentication ceremony
- [ ] Add basic UI components

### Phase 2: Testing (Week 2-3)
- [ ] Write unit and integration tests
- [ ] Test with virtual authenticators
- [ ] Test on real devices (iOS, Android, Windows, macOS)
- [ ] Security audit

### Phase 3: Beta (Week 3-4)
- [ ] Deploy to staging environment
- [ ] Enable for admin users only
- [ ] Gather feedback
- [ ] Fix bugs and UX issues

### Phase 4: Production (Week 4-5)
- [ ] Deploy to production
- [ ] Enable for all users (opt-in)
- [ ] Monitor error rates and adoption
- [ ] Document and share user guides

### Phase 5: Enforcement (Week 6+)
- [ ] Analyze adoption metrics
- [ ] Consider enforcement for high-security groups
- [ ] Continuous improvement based on feedback

---

## Open Questions & Decisions Needed

1. **Attestation Level**: Should we validate authenticator attestation? (Recommendation: No for v1)

2. **Resident Key Strategy**: Require resident keys (discoverable credentials)? (Recommendation: Preferred, not required)

3. **Backup Credential Policy**: Allow synced passkeys (iCloud Keychain, Google Password Manager)? (Recommendation: Yes, allow)

4. **Account Recovery**: How should users recover if they lose all passkeys? (Recommendation: Email verification + temporary password)

5. **2FA Replacement**: Should WebAuthn replace TOTP for 2FA? (Recommendation: Offer both, user choice)

6. **Enforcement Timeline**: When should we require passkeys for admins? (Recommendation: 3 months after launch)

7. **Cross-Platform Keys**: Encourage users to register both platform and roaming authenticators? (Recommendation: Yes, show prompt)

8. **Audit Logging**: Log all WebAuthn events? (Recommendation: Yes, use Rails ActiveSupport::Notifications)

---

## Dependencies

### Ruby Gems
- `webauthn` (~> 3.0) - WebAuthn server library
- `base64` (stdlib) - Encoding/decoding credentials

### JavaScript Libraries
- Native WebAuthn API (no libraries needed)
- Stimulus controller for UX

### Browser Requirements
- WebAuthn API support
- HTTPS (required in production)
- Modern browser (Chrome 90+, Firefox 90+, Safari 14+)

---

## Success Metrics

### Adoption Metrics
- % of users with at least one passkey registered
- % of logins using passkey vs password
- Time to register passkey (UX metric)

### Security Metrics
- Reduction in password reset requests
- Reduction in account takeover attempts
- Phishing resistance (passkeys can't be phished)

### Performance Metrics
- Average authentication time (should be faster)
- Error rate during registration/authentication
- Browser compatibility issues

---

## Future Enhancements

### Post-Launch Improvements
1. **Conditional UI**: Show passkey option only if user has credentials for that device
2. **Cross-Device Flow**: QR code to authenticate on one device, complete login on another
3. **Passkey Sync Status**: Show which passkeys are synced vs device-only
4. **Authenticator Icons**: Display icons for known authenticators (YubiKey, etc.)
5. **Security Key Attestation**: Verify hardware security keys for high-security apps
6. **Multi-Device Registration**: Easy workflow to register passkey on multiple devices
7. **Admin Analytics**: Dashboard showing WebAuthn adoption and usage stats
8. **FIDO2 Compliance**: Full FIDO2 conformance certification

---

## References

### Specifications
- [W3C WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 Overview](https://fidoalliance.org/fido2/)
- [WebAuthn Guide](https://webauthn.guide/)

### Ruby Libraries
- [webauthn-ruby gem](https://github.com/cedarcode/webauthn-ruby)
- [webauthn-ruby documentation](https://github.com/cedarcode/webauthn-ruby#usage)

### Browser APIs
- [MDN: Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [Chrome: WebAuthn](https://developer.chrome.com/docs/devtools/webauthn/)

### Best Practices
- [FIDO2 Server Best Practices](https://fidoalliance.org/specifications/)
- [WebAuthn Awesome List](https://github.com/herrjemand/awesome-webauthn)

---

## Appendix A: File Changes Summary

### New Files
- `app/models/webauthn_credential.rb`
- `app/controllers/webauthn_controller.rb`
- `app/javascript/controllers/webauthn_controller.js`
- `app/views/webauthn/new.html.erb`
- `app/views/webauthn/show.html.erb`
- `config/initializers/webauthn.rb`
- `db/migrate/YYYYMMDD_create_webauthn_credentials.rb`
- `db/migrate/YYYYMMDD_add_webauthn_to_users.rb`
- `test/models/webauthn_credential_test.rb`
- `test/controllers/webauthn_controller_test.rb`
- `test/integration/webauthn_authentication_test.rb`
- `test/system/webauthn_test.rb`
- `docs/webauthn-user-guide.md`
- `docs/webauthn-admin-guide.md`
- `docs/webauthn-developer-guide.md`

### Modified Files
- `Gemfile` - Add webauthn gem
- `app/models/user.rb` - Add webauthn associations and methods
- `app/controllers/sessions_controller.rb` - Add webauthn authentication
- `app/views/sessions/new.html.erb` - Add "Sign in with Passkey" button
- `app/views/profiles/show.html.erb` - Add passkey management section
- `app/controllers/oidc_controller.rb` - Add AMR claim support
- `config/routes.rb` - Add webauthn routes
- `README.md` - Document WebAuthn feature

### Database Migrations
1. Create `webauthn_credentials` table
2. Add `webauthn_id` and `webauthn_required` to `users` table

---

## Appendix B: Example User Flows

### Flow 1: Register First Passkey
1. User logs in with password
2. Sees banner: "Secure your account with a passkey"
3. Clicks "Set up passkey"
4. Browser prompts: "Save a passkey for auth.example.com?"
5. User authenticates with Touch ID
6. Success message: "Passkey registered as 'MacBook Touch ID'"

### Flow 2: Sign In with Passkey
1. User visits login page
2. Enters email address
3. Clicks "Continue with Passkey"
4. Browser prompts: "Sign in to auth.example.com with your passkey?"
5. User authenticates with Touch ID
6. Immediately signed in, redirected to dashboard

### Flow 3: WebAuthn as 2FA
1. User enters password (first factor)
2. Instead of TOTP, prompted for passkey
3. User authenticates with Face ID
4. Signed in successfully

### Flow 4: Cross-Device Authentication
1. User on desktop enters email
2. Clicks "Use passkey from phone"
3. QR code displayed
4. User scans with phone, authenticates
5. Desktop session created

---

## Conclusion

This plan provides a comprehensive roadmap for adding WebAuthn/Passkeys to Clinch. The phased approach allows for iterative development, testing, and rollout while maintaining backward compatibility with existing authentication methods.

**Key Benefits**:
- Enhanced security (phishing-resistant)
- Better UX (faster, no passwords to remember)
- Modern authentication standard (FIDO2)
- Cross-platform support (iOS, Android, Windows, macOS)
- Synced passkeys (iCloud, Google Password Manager)

**Estimated Timeline**: 4-6 weeks for full implementation and testing.

**Next Steps**:
1. Review and approve this plan
2. Create GitHub issues for each phase
3. Begin Phase 1 implementation
4. Set up development environment for testing

---

*Document Version: 1.0*
*Last Updated: 2025-10-26*
*Author: Claude (Anthropic)*
*Status: Awaiting Review*
