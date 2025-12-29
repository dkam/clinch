# OpenID Connect Backchannel Logout

## Overview

Backchannel logout is an OpenID Connect feature that enables Clinch to notify applications when a user logs out, ensuring sessions are terminated across all connected applications immediately.

## How It Works

When a user logs out from Clinch (or any connected application), Clinch sends server-to-server HTTP POST requests to all applications that have configured a backchannel logout endpoint. This happens automatically in the background.

### Logout Triggers

Backchannel logout notifications are sent when:

1. **User clicks "Sign Out" in Clinch** - All connected OIDC applications are notified, then the Clinch session is terminated
2. **User logs out via OIDC `/logout` endpoint** (RP-Initiated Logout) - All connected applications are notified, then the Clinch session is terminated
3. **User clicks "Logout" on an app (Dashboard)** - Backchannel logout is sent to that app, all access/refresh tokens are revoked, but OAuth consent is preserved (user can sign back in without re-authorizing)
4. **User clicks "Revoke Access" for a specific app (Active Sessions page)** - Backchannel logout is sent to that app to terminate its session, all access/refresh tokens are revoked, then the OAuth consent is permanently destroyed (user must re-authorize the app to use it again)
5. **User clicks "Revoke All App Access"** - All connected applications receive backchannel logout notifications, all tokens are revoked, then all OAuth consents are permanently destroyed

### The Logout Flow

```
User logs out → Clinch finds all connected apps
                ↓
        For each app with backchannel_logout_uri:
                ↓
        Generate signed JWT logout token
                ↓
        HTTP POST to app's logout endpoint
                ↓
        App validates JWT and terminates session
                ↓
        Clinch revokes access and refresh tokens
```

### Logout vs Revoke Access

Clinch provides two distinct actions for managing application access:

| Action | Location | What Happens | When to Use |
|--------|----------|--------------|-------------|
| **Logout** | Dashboard | • Sends backchannel logout to app<br>• Revokes all access tokens<br>• Revokes all refresh tokens<br>• **Keeps OAuth consent intact** | You want to end your session with an app but still trust it. Next login will skip the authorization screen. |
| **Revoke Access** | Active Sessions page | • Sends backchannel logout to app<br>• Revokes all access tokens<br>• Revokes all refresh tokens<br>• **Destroys OAuth consent** | You want to completely de-authorize an app. Next login will require you to re-authorize the app. |

**Key Difference**: "Logout" preserves the authorization relationship while terminating the active session. "Revoke Access" completely removes the app's authorization to access your account.

**Example Use Cases**:
- **Logout**: "I left my Jellyfin session open at a friend's house. I want to kill that session but I still use Jellyfin."
- **Revoke Access**: "I no longer trust this app and want to remove its authorization completely."

**Technical Details**:
- Both actions revoke access tokens (opaque, database-backed, validated on each use)
- Both actions revoke refresh tokens (prevents obtaining new access tokens)
- ID tokens remain valid until expiry (stateless JWTs), but apps should honor backchannel logout
- Backchannel logout ensures the app clears its local session immediately

## Configuring Applications

### In Clinch Admin UI

1. Navigate to **Admin → Applications**
2. Edit or create an OIDC application
3. In the "Backchannel Logout URI" field, enter the application's logout endpoint
   - Example: `https://kavita.local/oidc/backchannel-logout`
   - Must be HTTPS in production
   - Leave blank if the application doesn't support backchannel logout

### Checking Support

The OIDC discovery endpoint advertises backchannel logout support:

```bash
curl https://clinch.local/.well-known/openid-configuration | jq
```

Look for:
```json
{
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

## Implementing a Backchannel Logout Endpoint (for RPs)

If you're developing an application that integrates with Clinch, here's how to implement backchannel logout support:

### 1. Create the Endpoint

The endpoint must:
- Accept HTTP POST requests
- Parse the `logout_token` parameter from the form body
- Validate the JWT signature
- Terminate the user's session
- Return 200 OK quickly (within 5 seconds)

### 2. Example Implementation (Ruby/Rails)

```ruby
# config/routes.rb
post '/oidc/backchannel-logout', to: 'oidc_backchannel_logout#logout'

# app/controllers/oidc_backchannel_logout_controller.rb
class OidcBackchannelLogoutController < ApplicationController
  skip_before_action :verify_authenticity_token  # Server-to-server call
  skip_before_action :authenticate_user!         # No user session yet

  def logout
    logout_token = params[:logout_token]

    unless logout_token.present?
      head :bad_request
      return
    end

    begin
      # Decode and verify the JWT
      # Get Clinch's public key from JWKS endpoint
      jwks = fetch_clinch_jwks
      decoded = JWT.decode(
        logout_token,
        nil,  # Will be verified using JWKS
        true,
        {
          algorithms: ['RS256'],
          jwks: jwks,
          verify_aud: true,
          aud: YOUR_CLIENT_ID,
          verify_iss: true,
          iss: 'https://clinch.local'  # Your Clinch URL
        }
      )

      claims = decoded.first

      # Validate required claims
      unless claims['events']&.key?('http://schemas.openid.net/event/backchannel-logout')
        head :bad_request
        return
      end

      # Get session ID from the token
      sid = claims['sid']
      sub = claims['sub']

      # Terminate sessions
      if sid.present?
        # Terminate specific session by SID (recommended)
        Session.where(oidc_sid: sid).destroy_all
      elsif sub.present?
        # Terminate all sessions for this user
        user = User.find_by(oidc_sub: sub)
        user&.sessions&.destroy_all
      end

      Rails.logger.info "Backchannel logout: Terminated session for sid=#{sid}, sub=#{sub}"
      head :ok

    rescue JWT::DecodeError => e
      Rails.logger.error "Backchannel logout: Invalid JWT - #{e.message}"
      head :bad_request
    rescue => e
      Rails.logger.error "Backchannel logout: Error - #{e.class}: #{e.message}"
      head :internal_server_error
    end
  end

  private

  def fetch_clinch_jwks
    # Cache this in production!
    response = HTTParty.get('https://clinch.local/.well-known/jwks.json')
    JSON.parse(response.body, symbolize_names: true)
  end
end
```

### 3. Required JWT Claims Validation

The logout token will contain:

| Claim | Description | Required |
|-------|-------------|----------|
| `iss` | Issuer (Clinch URL) | Yes |
| `aud` | Your application's client_id | Yes |
| `iat` | Issued at timestamp | Yes |
| `jti` | Unique token ID | Yes |
| `sub` | Pairwise subject identifier (user's SID) | Yes |
| `sid` | Session ID (same as sub) | Yes |
| `events` | Must contain `http://schemas.openid.net/event/backchannel-logout` | Yes |
| `nonce` | Must NOT be present (spec requirement) | No |

### 4. Session Tracking Requirements

To support backchannel logout, your application must:

1. **Store the `sid` claim from ID tokens**:
   ```ruby
   # When user logs in via OIDC
   id_token = decode_id_token(params[:id_token])
   session[:oidc_sid] = id_token['sid']  # Store this!
   ```

2. **Associate sessions with SID**:
   ```ruby
   # Create session with SID tracking
   Session.create!(
     user: current_user,
     oidc_sid: id_token['sid'],
     ...
   )
   ```

3. **Terminate sessions by SID**:
   ```ruby
   # When backchannel logout is received
   Session.where(oidc_sid: sid).destroy_all
   ```

### 5. Testing Your Endpoint

Test with curl:

```bash
# Get a valid logout token (you'll need to capture this from Clinch logs)
LOGOUT_TOKEN="eyJhbGc..."

curl -X POST https://your-app.local/oidc/backchannel-logout \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "logout_token=$LOGOUT_TOKEN"
```

Expected response: `200 OK` (empty body)

## Monitoring and Troubleshooting

### Checking Logs

Clinch logs all backchannel logout attempts:

```bash
# In development
tail -f log/development.log | grep BackchannelLogout

# Example log output:
# BackchannelLogout: Successfully sent logout notification to Kavita (https://kavita.local/oidc/backchannel-logout)
# BackchannelLogout: Application Jellyfin doesn't support backchannel logout
# BackchannelLogout: Timeout sending logout to HomeAssistant (https://ha.local/logout): Connection timeout
```

### Common Issues

**1. HTTP Timeout**
- Symptom: `Timeout sending logout to...` in logs
- Solution: Ensure the RP's backchannel logout endpoint responds within 5 seconds
- Note: Clinch will retry 3 times with exponential backoff

**2. HTTP Errors (Non-200 Status)**
- Symptom: `Application X returned HTTP 400/500...` in logs
- Solution: Check the RP's logs for JWT validation errors
- Common causes:
  - Wrong JWKS (public key mismatch)
  - Incorrect `aud` (client_id) validation
  - Missing required claims validation

**3. Network Unreachable**
- Symptom: `Failed to send logout to...` with connection errors
- Solution: Ensure the RP's logout endpoint is accessible from Clinch server
- Check: Firewalls, DNS, SSL certificates

**4. Sessions Not Terminating**
- Symptom: User still logged into RP after logging out of Clinch
- Solution: Verify the RP is storing and checking `sid` correctly
- Debug: Add logging to the RP's backchannel logout handler

### Verification Checklist

For RPs (Application Developers):
- [ ] Endpoint accepts POST requests
- [ ] Endpoint validates JWT signature using Clinch's JWKS
- [ ] Endpoint validates all required claims
- [ ] Endpoint terminates sessions by SID
- [ ] Endpoint returns 200 OK quickly (< 5 seconds)
- [ ] Sessions store the `sid` claim from ID tokens
- [ ] Backchannel logout URI is configured in Clinch admin

For Administrators:
- [ ] Application has `backchannel_logout_uri` configured
- [ ] URI uses HTTPS (in production)
- [ ] URI is reachable from Clinch server
- [ ] Check logs for successful logout notifications

## Security Considerations

1. **JWT Signature Verification**: Always verify the logout token signature using Clinch's public key
2. **Audience Validation**: Ensure the `aud` claim matches your client_id
3. **Issuer Validation**: Ensure the `iss` claim matches your Clinch URL
4. **No Authentication Required**: The endpoint should not require user authentication (it's server-to-server)
5. **HTTPS Only**: Always use HTTPS in production (Clinch enforces this)
6. **Fire-and-Forget**: RPs should log failures but not block on errors

## Comparison with Other Logout Methods

| Method | Communication | When Sessions Terminate | Reliability |
|--------|--------------|------------------------|-------------|
| **Backchannel Logout** | Server-to-server POST | Immediately | High (retries on failure) |
| **Front-Channel Logout** | Browser iframes | When browser loads iframes | Low (blocked by privacy settings) |
| **RP-Initiated Logout** | User redirects to Clinch | Only affects Clinch session | N/A (just triggers other methods) |
| **Token Expiry** | None | When access token expires | Guaranteed but delayed |

## References

- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [RFC 7009: OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [Clinch OIDC Discovery](/.well-known/openid-configuration)
