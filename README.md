# Clinch

> [!NOTE]
> This software is experimental. If you'd like to try it out, find bugs, security flaws and improvements, please do. 

**A lightweight, self-hosted identity & SSO / IpD portal**

Clinch gives you one place to manage users and lets any web app authenticate against it without managing its own users.

## Why Clinch?

Do you host your own web apps? MeTube, Kavita, Audiobookshelf, Gitea, Grafana, Proxmox? Rather than managing all those separate user accounts, set everyone up on Clinch and let it do the authentication and user management.

Clinch runs as a single Docker container, using SQLite as the database, the job queue (Solid Queue) and the shared cache (Solid Cache). The webserver, Puma, runs the job queue in-process, avoiding the need for another container.

Clinch sits in a sweet spot between two excellent open-source identity solutions:

**[Authelia](https://www.authelia.com)** is a fantastic choice for those who prefer external user management through LDAP and enjoy comprehensive YAML-based configuration. It's lightweight, secure, and works beautifully with reverse proxies.

**[Authentik](https://goauthentik.io)** is an enterprise-grade powerhouse offering extensive protocol support (OAuth2, SAML, LDAP, RADIUS), advanced policy engines, and distributed "outpost" architecture for complex deployments.

**Clinch** offers a middle ground with built-in user management, a modern web interface, and focused SSO capabilities (OIDC + ForwardAuth). It's perfect for users who want self-hosted simplicity without external dependencies or enterprise complexity.

---

## Screenshots

### User Dashboard
[![User Dashboard](docs/screenshots/thumbs/0-dashboard.png)](docs/screenshots/0-dashboard.png)

### Sign In
[![Sign In](docs/screenshots/thumbs/1-signin.png)](docs/screenshots/1-signin.png)

### Sign In with 2FA
[![Sign In with 2FA](docs/screenshots/thumbs/2-signin.png)](docs/screenshots/2-signin.png)

### Users Management
[![Users Management](docs/screenshots/thumbs/3-users.png)](docs/screenshots/3-users.png)

### Welcome Screen
[![Welcome Screen](docs/screenshots/thumbs/4-welcome.png)](docs/screenshots/4-welcome.png)

### Welcome Setup
[![Welcome Setup](docs/screenshots/thumbs/5-welcome-2.png)](docs/screenshots/5-welcome-2.png)

### Setup 2FA
[![Setup 2FA](docs/screenshots/thumbs/6-setup-2fa.png)](docs/screenshots/6-setup-2fa.png)

### Forward Auth Example 1
[![Forward Auth Example 1](docs/screenshots/thumbs/7-forward-auth-1.png)](docs/screenshots/7-forward-auth-1.png)

### Forward Auth Example 2
[![Forward Auth Example 2](docs/screenshots/thumbs/8-forward-auth-2.png)](docs/screenshots/8-forward-auth-2.png)

## Features

### User Management
- **First-run wizard** - Initial user automatically becomes admin
- **Admin dashboard** - Create, disable, and delete users
- **Group-based organization** - Organize users into groups (admin, family, friends, etc.)
- **User statuses** - Active, disabled, or pending invitation

### Authentication Methods
- **WebAuthn/Passkeys** - Modern passwordless authentication using FIDO2 standards
- **Password authentication** - Secure bcrypt-based password storage
- **TOTP 2FA** - Optional time-based one-time passwords with QR code setup
- **Backup codes** - 10 single-use recovery codes per user
- **Configurable 2FA enforcement** - Admins can require TOTP for specific users

### SSO Protocols

Apps that speak OIDC use the OIDC flow.
Apps that only need "who is it?", or you want available from the internet behind authentication (MeTube, Jellyfin) use ForwardAuth.

#### OpenID Connect (OIDC)
Standard OAuth2/OIDC provider with endpoints:
- `/.well-known/openid-configuration` - Discovery endpoint
- `/authorize` - Authorization endpoint with PKCE support
- `/token` - Token endpoint (authorization_code and refresh_token grants)
- `/userinfo` - User info endpoint
- `/revoke` - Token revocation endpoint (RFC 7009)

Features:
- **Refresh tokens** - Long-lived tokens (30 days default) with automatic rotation and revocation
- **Token family tracking** - Advanced security detects token replay attacks and revokes compromised token families
- **Configurable token expiry** - Set access token (5min-24hr), refresh token (1-90 days), and ID token TTL per application
- **Token security** - All tokens HMAC-SHA256 hashed (suitable for 256-bit random data), automatic cleanup of expired tokens
- **Pairwise subject identifiers** - Each user gets a unique, stable `sub` claim per application for enhanced privacy

**ID Token Claims** (JWT with RS256 signature):

| Claim | Description | Notes |
|-------|-------------|-------|
| Standard Claims | | |
| `iss` | Issuer (Clinch URL) | From `CLINCH_HOST` |
| `sub` | Subject (user identifier) | Pairwise SID - unique per app |
| `aud` | Audience | OAuth client_id |
| `exp` | Expiration timestamp | Configurable TTL |
| `iat` | Issued-at timestamp | Token creation time |
| `email` | User email | |
| `email_verified` | Email verification | Always `true` |
| `preferred_username` | Username/email | Fallback to email |
| `name` | Display name | User's name or email |
| `nonce` | Random value | From auth request (prevents replay) |
| **Security Claims** | | |
| `at_hash` | Access token hash | SHA-256 hash of access_token (OIDC Core §3.1.3.6) |
| `auth_time` | Authentication time | Unix timestamp of when user logged in (OIDC Core §2) |
| `acr` | Auth context class | `"1"` = password, `"2"` = 2FA/passkey (OIDC Core §2) |
| `azp` | Authorized party | OAuth client_id (OIDC Core §2) |
| Custom Claims | | |
| `groups` | User's groups | Array of group names |
| *custom* | Arbitrary key-values | From groups, users, or app-specific config |

**Authentication Context Class Reference (`acr`):**
- `"1"` - Something you know (password only)
- `"2"` - Two-factor or phishing-resistant (TOTP, backup codes, WebAuthn/passkey)

Client apps (Audiobookshelf, Kavita, Proxmox, Grafana, etc.) redirect to Clinch for login and receive ID tokens, access tokens, and refresh tokens.

#### Trusted-Header SSO (ForwardAuth)
Works with reverse proxies (Caddy, Traefik, Nginx):
1. Proxy sends every request to `/api/verify`
2. Response handling:
   - **200 OK** → Proxy injects headers (`Remote-User`, `Remote-Groups`, `Remote-Email`) and forwards to app
   - **Any other status** → Proxy returns that response directly to client (typically 302 redirect to login page)

**Note:** ForwardAuth requires applications to run on the same domain as Clinch (e.g., `app.yourdomain.com` with Clinch at `auth.yourdomain.com`) for secure session cookie sharing. Take a look at Authentik if you need multi domain support.

### SMTP Integration
Send emails for:
- Invitation links (one-time token, 7-day expiry)
- Password reset links (one-time token, 1-hour expiry)

### Session Management
- **Device tracking** - See all active sessions with device names and IPs
- **Remember me** - Long-lived sessions (30 days) for trusted devices
- **Session revocation** - Users and admins can revoke individual sessions

### Access Control

#### Group-Based Application Access
Clinch uses groups to control which users can access which applications:

- **Create groups** - Organize users into logical groups (readers, editors, family, developers, etc.)
- **Assign groups to applications** - Each app defines which groups are allowed to access it
  - Example: Kavita app allows the "readers" group → only users in the "readers" group can sign in
  - If no groups are assigned to an app → all active users can access it
- **Automatic enforcement** - Access checks happen automatically:
  - During OIDC authorization flow (before consent)
  - During ForwardAuth verification (before proxying requests)
  - Users not in allowed groups receive a "You do not have permission" error

#### Group Claims in Tokens
- **OIDC tokens include group membership** - ID tokens contain a `groups` claim with all user's groups
- **Custom claims** - Add arbitrary key-value pairs to tokens via groups and users
  - Group claims apply to all members (e.g., `{"role": "viewer"}`)
  - User claims override group claims for fine-grained control
  - Perfect for app-specific authorization (e.g., admin vs. read-only roles)

#### Custom Claims Merging
Custom claims from groups and users are merged into OIDC ID tokens with the following precedence:

1. **Default OIDC claims** - Standard claims (`iss`, `sub`, `aud`, `exp`, `email`, etc.)
2. **Standard Clinch claims** - `groups` array (list of user's group names)
3. **Group custom claims** - Merged in order; later groups override earlier ones
4. **User custom claims** - Override all group claims
5. **Application-specific claims** - Highest priority; override all other claims

**Example:**
- Group "readers" has `{"role": "viewer", "max_items": 10}`
- Group "premium" has `{"role": "subscriber", "max_items": 100}`
- User (in both groups) has `{"max_items": 500}`
- **Result:** `{"role": "subscriber", "max_items": 500}` (user overrides max_items, premium overrides role)

#### Application-Specific Claims
Configure different claims for different applications on a per-user basis:

- **Per-app customization** - Each application can have unique claims for each user
- **Highest precedence** - App-specific claims override group and user global claims
- **Use case** - Different roles in different apps (e.g., admin in Kavita, user in Audiobookshelf)
- **Admin UI** - Configure via Admin → Users → Edit User → App-Specific Claim Overrides

**Example:**
- User Alice, global claims: `{"theme": "dark"}`
- Kavita app-specific: `{"kavita_groups": ["admin"]}`
- Audiobookshelf app-specific: `{"abs_groups": ["user"]}`
- **Result:** Kavita receives `{"theme": "dark", "kavita_groups": ["admin"]}`, Audiobookshelf receives `{"theme": "dark", "abs_groups": ["user"]}`

---

## Data Model

### Core Models

**User**
- Email address (unique, normalized to lowercase)
- Password (bcrypt hashed)
- Admin flag
- TOTP secret and backup codes (encrypted)
- TOTP enforcement flag
- Status (active, disabled, pending_invitation)
- Custom claims (JSON) - arbitrary key-value pairs added to OIDC tokens
- Token generation for invitations, password resets, and magic logins

**Group**
- Name (unique, normalized to lowercase)
- Description
- Custom claims (JSON) - shared claims for all members (merged with user claims)
- Many-to-many with Users and Applications

**Session**
- User reference
- IP address and user agent
- Device name (parsed from user agent)
- Remember me flag
- Expiry (24 hours or 30 days if remembered)
- Last activity timestamp

**Application**
- Name and slug (URL-safe identifier)
- Type (oidc or forward_auth)
- Client ID and secret (for OIDC apps)
- Redirect URIs (for OIDC apps)
- Domain pattern (for ForwardAuth apps, supports wildcards like *.example.com)
- Headers config (for ForwardAuth apps, JSON configuration for custom header names)
- Token TTL configuration (access_token_ttl, refresh_token_ttl, id_token_ttl)
- Metadata (flexible JSON storage)
- Active flag
- Many-to-many with Groups (allowlist)

**OIDC Tokens**
- Authorization codes (opaque, HMAC-SHA256 hashed, 10-minute expiry, one-time use, PKCE support)
- Access tokens (opaque, HMAC-SHA256 hashed, configurable expiry 5min-24hr, revocable)
- Refresh tokens (opaque, HMAC-SHA256 hashed, configurable expiry 1-90 days, single-use with rotation)
- ID tokens (JWT, signed with RS256, configurable expiry 5min-24hr)

---

## Authentication Flows

### OIDC Authorization Flow
1. Client redirects user to `/authorize` with client_id, redirect_uri, scope (optional PKCE)
2. User authenticates with Clinch (username/password + optional TOTP)
3. Access control check: Is user in an allowed group for this app?
4. If allowed, generate authorization code and redirect to client
5. Client exchanges code at `/token` for ID token, access token, and refresh token
6. Client uses access token to fetch fresh user info from `/userinfo`
7. When access token expires, client uses refresh token to get new tokens (no re-authentication)

### ForwardAuth Flow
1. User requests protected resource at `https://app.example.com/dashboard`
2. Reverse proxy sends request to Clinch at `/api/verify`
3. Clinch checks for valid session cookie
4. If valid session and user allowed:
   - Return 200 with `Remote-User`, `Remote-Groups`, `Remote-Email` headers
   - Proxy forwards request to app with injected headers
5. If no session or not allowed:
   - Return 401/403
   - Proxy redirects to Clinch login page
   - After login, redirect back to original URL

#### Race Condition Handling

After successful login, you may notice an `fa_token` query parameter appended to redirect URLs (e.g., `https://app.example.com/dashboard?fa_token=...`). This solves a timing issue:

**The Problem:**
1. User signs in → session cookie is set
2. Browser gets redirected to protected resource
3. Browser may not have processed the `Set-Cookie` header yet
4. Reverse proxy checks `/api/verify` → no cookie yet → auth fails ❌

**The Solution:**
- A one-time token (`fa_token`) is added to the redirect URL as a query parameter
- `/api/verify` checks for this token first, before checking cookies
- Token is cached for 60 seconds and deleted immediately after use
- This gives the browser's cookie handling time to catch up

This is transparent to end users and requires no configuration.

---

## Setup & Installation

### Requirements
- Ruby 3.3+
- SQLite 3.8+
- SMTP server (for sending emails)

### Local Development

```bash
# Install dependencies
bundle install

# Setup database
bin/rails db:setup

# Run migrations
bin/rails db:migrate

# Start server
bin/dev
```

---

## Production Deployment

### Docker

```bash
# Build image
docker build -t clinch .

# Run container
docker run -p 3000:3000 \
  -v clinch-storage:/rails/storage \
  -e SECRET_KEY_BASE=your-secret-key \
  -e SMTP_ADDRESS=smtp.example.com \
  -e SMTP_PORT=587 \
  -e SMTP_USERNAME=your-username \
  -e SMTP_PASSWORD=your-password \
  clinch
```

### Backup & Restore

Clinch stores all persistent data in the `storage/` directory (or `/rails/storage` in Docker):
- SQLite database (`production.sqlite3`)
- Uploaded files via ActiveStorage (application icons)

**Database Backup:**

Use SQLite's `VACUUM INTO` command for safe, atomic backups of a running database:

```bash
# Local development
sqlite3 storage/production.sqlite3 "VACUUM INTO 'backup.sqlite3';"

# Docker
docker exec clinch sqlite3 /rails/storage/production.sqlite3 "VACUUM INTO '/rails/storage/backup.sqlite3';"
```

This creates an optimized copy of the database that's safe to make even while Clinch is running.

**Full Backup (Database + Uploads):**

For complete backups including uploaded files, backup the database and uploads separately:

```bash
# 1. Backup database (safe while running)
sqlite3 storage/production.sqlite3 "VACUUM INTO 'backup-$(date +%Y%m%d).sqlite3';"

# 2. Backup uploaded files (ActiveStorage files are immutable)
tar -czf uploads-backup-$(date +%Y%m%d).tar.gz storage/uploads/

# Docker equivalent
docker exec clinch sqlite3 /rails/storage/production.sqlite3 "VACUUM INTO '/rails/storage/backup-$(date +%Y%m%d).sqlite3';"
docker exec clinch tar -czf /rails/storage/uploads-backup-$(date +%Y%m%d).tar.gz /rails/storage/uploads/
```

**Restore:**

```bash
# Stop Clinch first
# Then restore database
cp backup-YYYYMMDD.sqlite3 storage/production.sqlite3

# Restore uploads
tar -xzf uploads-backup-YYYYMMDD.tar.gz -C storage/
```

**Docker Volume Backup:**

**Option 1: While Running (Online Backup)**

a) **Mapped volumes** (recommended, e.g., `-v /host/path:/rails/storage`):
```bash
# Database backup (safe while running)
sqlite3 /host/path/production.sqlite3 "VACUUM INTO '/host/path/backup-$(date +%Y%m%d).sqlite3';"

# Then sync to off-server storage
rsync -av /host/path/backup-*.sqlite3 /host/path/uploads/ remote:/backups/clinch/
```

b) **Docker volumes** (e.g., `-v clinch_storage:/rails/storage`):
```bash
# Database backup (safe while running)
docker exec clinch sqlite3 /rails/storage/production.sqlite3 "VACUUM INTO '/rails/storage/backup.sqlite3';"

# Copy out of container
docker cp clinch:/rails/storage/backup.sqlite3 ./backup-$(date +%Y%m%d).sqlite3
```

**Option 2: While Stopped (Offline Backup)**

If Docker is stopped, you can copy the entire storage:
```bash
docker compose down

# For mapped volumes
tar -czf clinch-backup-$(date +%Y%m%d).tar.gz /host/path/

# For docker volumes
docker run --rm -v clinch_storage:/data -v $(pwd):/backup ubuntu \
  tar czf /backup/clinch-backup-$(date +%Y%m%d).tar.gz /data

docker compose up -d
```

**Important:** Do not use tar/snapshots on a running database - use `VACUUM INTO` instead or stop the container first.

---

## Configuration

### Environment Variables

Create a `.env` file (see `.env.example`):

```bash
# Rails
SECRET_KEY_BASE=generate-with-bin-rails-secret
RAILS_ENV=production

# Database
# SQLite database stored in storage/ directory (Docker volume mount point)

# SMTP (for sending emails)
SMTP_ADDRESS=smtp.example.com
SMTP_PORT=587
SMTP_DOMAIN=example.com
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
SMTP_AUTHENTICATION=plain
SMTP_ENABLE_STARTTLS=true

# Application
CLINCH_HOST=https://auth.example.com
CLINCH_FROM_EMAIL=noreply@example.com

# OIDC (optional - generates temporary key in development)
# Generate with: openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
OIDC_PRIVATE_KEY=<contents-of-private-key.pem>
```

### First Run
1. Visit Clinch at `http://localhost:3000` (or your configured domain)
2. First-run wizard creates initial admin user
3. Admin can then:
   - Create groups
   - Invite users
   - Register applications
   - Configure access control

---

## Rails Console

One advantage of being a Rails application is direct access to the Rails console for administrative tasks. This is particularly useful for debugging, emergency access, or bulk operations.

### Starting the Console

```bash
# Docker / Docker Compose
docker exec -it clinch bin/rails console
# or
docker compose exec -it clinch bin/rails console

# Local development
bin/rails console
```

### Finding Users

```ruby
# Find by email
user = User.find_by(email_address: 'alice@example.com')

# Find by username
user = User.find_by(username: 'alice')

# List all users
User.all.pluck(:id, :email_address, :status)

# Find admins
User.admins.pluck(:email_address)

# Find users in a specific status
User.active.count
User.disabled.pluck(:email_address)
User.pending_invitation.pluck(:email_address)
```

### Creating Users

```ruby
# Create a regular user
User.create!(
  email_address: 'newuser@example.com',
  password: 'secure-password-here',
  status: :active
)

# Create an admin user
User.create!(
  email_address: 'admin@example.com',
  password: 'secure-password-here',
  status: :active,
  admin: true
)
```

### Managing Passwords

```ruby
user = User.find_by(email_address: 'alice@example.com')
user.password = 'new-secure-password'
user.save!
```

### Two-Factor Authentication (TOTP)

```ruby
user = User.find_by(email_address: 'alice@example.com')

# Check if TOTP is enabled
user.totp_enabled?

# Get current TOTP code (useful for testing/debugging)
puts user.console_totp

# Enable TOTP (generates secret and backup codes)
backup_codes = user.enable_totp!
puts backup_codes  # Display backup codes to give to user

# Disable TOTP
user.disable_totp!

# Force user to set up TOTP on next login
user.update!(totp_required: true)
```

### Managing User Status

```ruby
user = User.find_by(email_address: 'alice@example.com')

# Disable a user (prevents login)
user.disabled!

# Re-enable a user
user.active!

# Check current status
user.status  # => "active", "disabled", or "pending_invitation"

# Grant admin privileges
user.update!(admin: true)

# Revoke admin privileges
user.update!(admin: false)
```

### Managing Groups

```ruby
user = User.find_by(email_address: 'alice@example.com')

# View user's groups
user.groups.pluck(:name)

# Add user to a group
family = Group.find_by(name: 'family')
user.groups << family

# Remove user from a group
user.groups.delete(family)

# Create a new group
Group.create!(name: 'developers', description: 'Development team')
```

### Managing Sessions

```ruby
user = User.find_by(email_address: 'alice@example.com')

# View active sessions
user.sessions.pluck(:id, :device_name, :client_ip, :created_at)

# Revoke all sessions (force logout everywhere)
user.sessions.destroy_all

# Revoke a specific session
user.sessions.find(123).destroy
```

### Managing Applications

```ruby
# List all OIDC applications
Application.oidc.pluck(:name, :client_id)

# Find an application
app = Application.find_by(slug: 'kavita')

# Regenerate client secret
new_secret = app.generate_new_client_secret!
puts new_secret  # Display once - not stored in plain text

# Check which users can access an app
app.allowed_groups.flat_map(&:users).uniq.pluck(:email_address)

# Revoke all tokens for an application
app.oidc_access_tokens.destroy_all
app.oidc_refresh_tokens.destroy_all
```

### Revoking OIDC Consents

```ruby
user = User.find_by(email_address: 'alice@example.com')
app = Application.find_by(slug: 'kavita')

# Revoke consent for a specific app
user.revoke_consent!(app)

# Revoke all OIDC consents
user.revoke_all_consents!
```

---

## Testing & Security

### Running Tests

Clinch has comprehensive test coverage with 341 tests covering integration, models, controllers, services, and system tests.

```bash
# Run all tests
bin/rails test

# Run specific test types
bin/rails test:integration
bin/rails test:models
bin/rails test:controllers
bin/rails test:system

# Run with code coverage report
COVERAGE=1 bin/rails test
# View coverage report at coverage/index.html
```

### Security Scanning

Clinch uses multiple automated security tools to ensure code quality and security:

```bash
# Run all security checks
bin/rake security

# Individual security scans
bin/brakeman --no-pager              # Static security analysis
bin/bundler-audit check --update     # Dependency vulnerability scan
bin/importmap audit                  # JavaScript dependency scan
```

**CI/CD Integration:**
All security scans run automatically on every pull request and push to main via GitHub Actions.

**Security Tools:**
- **Brakeman** - Static analysis for Rails security vulnerabilities
- **bundler-audit** - Checks gems for known CVEs
- **SimpleCov** - Code coverage tracking
- **RuboCop** - Code style and quality enforcement

**Current Status:**
- ✅ All security scans passing
- ✅ 341 tests, 1349 assertions, 0 failures
- ✅ No known dependency vulnerabilities
- ✅ Phases 1-4 security hardening complete (18+ vulnerabilities fixed)
- 🟡 3 outstanding security issues (all MEDIUM/LOW priority)

**Security Documentation:**
- [docs/security-todo.md](docs/security-todo.md) - Detailed vulnerability tracking and remediation history
- [docs/beta-checklist.md](docs/beta-checklist.md) - Beta release readiness criteria

---

## Technology Stack

- **Rails 8.1** - Modern Rails with authentication generator
- **SQLite** - Lightweight database (production-ready with Rails 8)
- **Tailwind CSS** - Utility-first styling
- **Hotwire** - Turbo and Stimulus for reactive UI
- **ROTP** - TOTP implementation for 2FA
- **bcrypt** - Password hashing

---

## License

MIT