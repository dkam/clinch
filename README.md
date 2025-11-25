# Clinch

> [!NOTE]
> This software is experiemental. If you'd like to try it out, find bugs, security flaws and improvements, please do. 

**A lightweight, self-hosted identity & SSO / IpD portal**

Clinch gives you one place to manage users and lets any web app authenticate against it without maintaining its own user table. 

I've completed all planned features:

* Create Admin user on first login
* TOTP ( QR Code ) 2FA, with backup codes ( encrypted at rest )
* Passkey generation and login, with detection of Passkey during login
* Forward Auth configured and working
* OIDC provider with auto discovery, refresh tokens, and token revocation
* Configurable token expiry per application (access, refresh, ID tokens)
* Invite users by email, assign to groups
* Self managed password reset by email
* Use Groups to assign Applications ( Family group can access Kavita, Developers can access Gitea )
* Configurable Group and User custom claims for OIDC token
* Display all Applications available to the user on their Dashboard
* Display all logged in sessions and OIDC logged in sessions

What remains now is ensure test coverage, 

## Why Clinch?

Do you host your own web apps? MeTube, Kavita, Audiobookshelf, Gitea? Rather than managing all those separate user accounts, set everyone up on Clinch and let it do the authentication and user management.

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

#### OpenID Connect (OIDC)
Standard OAuth2/OIDC provider with endpoints:
- `/.well-known/openid-configuration` - Discovery endpoint
- `/authorize` - Authorization endpoint with PKCE support
- `/token` - Token endpoint (authorization_code and refresh_token grants)
- `/userinfo` - User info endpoint
- `/revoke` - Token revocation endpoint (RFC 7009)

Features:
- **Refresh tokens** - Long-lived tokens (30 days default) with automatic rotation and revocation
- **Configurable token expiry** - Set access token (5min-24hr), refresh token (1-90 days), and ID token TTL per application
- **Token security** - BCrypt-hashed tokens, automatic cleanup of expired tokens
- **Pairwise subject identifiers** - Each user gets a unique, stable `sub` claim per application for enhanced privacy

Client apps (Audiobookshelf, Kavita, Grafana, etc.) redirect to Clinch for login and receive ID tokens, access tokens, and refresh tokens.

#### Trusted-Header SSO (ForwardAuth)
Works with reverse proxies (Caddy, Traefik, Nginx):
1. Proxy sends every request to `/api/verify`
2. **200 OK** → Proxy injects headers (`Remote-User`, `Remote-Groups`, `Remote-Email`) and forwards to app
3. **401/403** → Proxy redirects to Clinch login; after login, user returns to original URL

Apps that speak OIDC use the OIDC flow; apps that only need "who is it?" headers use ForwardAuth.

**Note:** ForwardAuth requires applications to run on the same domain as Clinch (e.g., `app.yourdomain.com` with Clinch at `auth.yourdomain.com`) for secure session cookie sharing. Take a look at Authentik if you need multi domain support.

### SMTP Integration
Send emails for:
- Invitation links (one-time token, 7-day expiry)
- Password reset links (one-time token, 1-hour expiry)
- 2FA backup codes

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
- Authorization codes (10-minute expiry, one-time use, PKCE support)
- Access tokens (opaque, BCrypt-hashed, configurable expiry 5min-24hr, revocable)
- Refresh tokens (opaque, BCrypt-hashed, configurable expiry 1-90 days, single-use with rotation)
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

### Docker Deployment

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

## Roadmap

### In Progress
- OIDC provider implementation
- ForwardAuth endpoint
- Admin UI for user/group/app management
- First-run wizard

### Planned Features
- **Audit logging** - Track all authentication events
- **WebAuthn/Passkeys** - Hardware key support

#### Maybe
- **SAML support** - SAML 2.0 identity provider
- **Policy engine** - Rule-based access control
  - Example: `IF user.email =~ "*@gmail.com" AND app.slug == "kavita" THEN DENY`
  - Stored as JSON, evaluated after auth but before consent
- **LDAP sync** - Import users from LDAP/Active Directory

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