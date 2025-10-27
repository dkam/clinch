# Forward Authentication

## Overview

Forward authentication allows a reverse proxy (like Caddy, Nginx, Traefik) to delegate authentication decisions to a separate service. Clinch implements this pattern to provide SSO for multiple applications.

## Key Implementation Details

### Tip 1: Forward URL Configuration ✅

Clinch includes the original destination URL in the redirect parameters:

```ruby
login_params = {
  rd: original_url,    # redirect destination
  rm: request.method   # request method
}
login_url = "#{base_url}/signin?#{login_params.to_query}"
```

Example: `https://clinch.example.com/signin?rd=https://metube.example.com/&rm=GET`

### Tip 2: Root Domain Cookies ✅

Clinch sets authentication cookies on the root domain to enable cross-subdomain authentication:

```ruby
def extract_root_domain(host)
  # clinch.example.com -> .example.com
  # app.example.co.uk -> .example.co.uk
  # localhost -> nil (no domain restriction)
end

cookies.signed.permanent[:session_id] = {
  value: session.id,
  httponly: true,
  same_site: :lax,
  secure: Rails.env.production?,
  domain: ".example.com"  # Available to all subdomains
}
```

This allows the same session cookie to work across:
- `clinch.example.com` (auth service)
- `metube.example.com` (protected app)
- `sonarr.example.com` (protected app)

### Tip 3: Race Condition Solution with One-Time Tokens ✅

**Problem**: After successful authentication, there's a race condition where the browser immediately follows the redirect to the protected application, but the reverse proxy makes a forward auth request before the browser has processed and started sending the new session cookie.

**Solution**: Clinch uses a one-time token system to bridge this timing gap:

```ruby
# During authentication (authentication.rb)
def create_forward_auth_token(session_obj)
  token = SecureRandom.urlsafe_base64(32)

  # Store token for 30 seconds
  Rails.cache.write("forward_auth_token:#{token}", session_obj.id, expires_in: 30.seconds)

  # Add token to redirect URL
  if session[:return_to_after_authenticating].present?
    original_url = session[:return_to_after_authenticating]
    uri = URI.parse(original_url)
    query_params = URI.decode_www_form(uri.query || "").to_h
    query_params['fa_token'] = token
    uri.query = URI.encode_www_form(query_params)
    session[:return_to_after_authenticating] = uri.to_s
  end
end
```

```ruby
# In forward auth verification (forward_auth_controller.rb)
def check_forward_auth_token
  token = params[:fa_token]
  return nil unless token.present?

  session_id = Rails.cache.read("forward_auth_token:#{token}")
  return nil unless session_id

  session = Session.find_by(id: session_id)
  return nil unless session && !session.expired?

  # Delete token immediately (one-time use)
  Rails.cache.delete("forward_auth_token:#{token}")

  Rails.logger.info "ForwardAuth: Valid one-time token used for session #{session_id}"
  session_id
end
```

**How it works:**
1. User authenticates → Rails sets session cookie + generates one-time token
2. Token gets appended to redirect URL: `https://metube.example.com/?fa_token=abc123...`
3. Browser follows redirect → Caddy makes forward auth request with token
4. Forward auth validates token → authenticates user immediately
5. Token is deleted (one-time use) → subsequent requests use normal cookies

**Security Features:**
- Tokens expire after 30 seconds
- One-time use (deleted after validation)
- Secure random generation
- Session validation before token acceptance

## Authelia Analysis

### Implementation Comparison

**Authelia Approach (from analysis of `tmp/authelia/`):**
- Returns `302 Found` or `303 See Other` with `Location` header
- Direct browser redirects (bypasses some proxy logic)
- Uses StatusFound (302) or StatusSeeOther (303)

**Clinch Current Implementation:**
- Returns `302 Found` directly to login URL (matching Authelia)
- Includes `rd` (redirect destination) and `rm` (request method) parameters
- Uses root domain cookies for cross-subdomain authentication

## How Clinch Forward Auth Works

### Authentication Flow

1. **User visits** `https://metube.example.com/`
2. **Caddy forwards** to `http://clinch:9000/api/verify?rd=https://clinch.example.com`
3. **Clinch checks session**:
   - **If authenticated**: Returns `200 OK` with user headers
   - **If not authenticated**: Returns `302 Found` to login URL with redirect parameters
4. **Browser follows redirect** to Clinch login page
5. **User logs in** (with TOTP if enabled):
   - Rails creates session and sets cross-domain cookie
   - **Rails generates one-time token** and appends to redirect URL
   - User is redirected to: `https://metube.example.com/?fa_token=abc123...`
6. **Browser follows redirect** → Caddy makes forward auth request with token
7. **Clinch validates one-time token** → authenticates user immediately
8. **Token is deleted** → subsequent requests use normal session cookies
9. **Caddy forwards to MEtube** with proper authentication headers

### Response Headers

**Successful Authentication (200 OK):**
```
Remote-User: user@example.com
Remote-Email: user@example.com
Remote-Groups: media-managers,users
Remote-Admin: false
```

**Redirect to Login (302 Found):**
```
Location: https://clinch.example.com/signin?rd=https://metube.example.com/&rm=GET
```

## Caddy Configuration

```caddyfile
# Clinch SSO (main authentication server)
clinch.example.com {
    reverse_proxy clinch:9000
}

# MEtube (protected by Clinch)
metube.example.com {
    forward_auth clinch:9000 {
        uri /api/verify?rd=https://clinch.example.com
        copy_headers Remote-User Remote-Email Remote-Groups Remote-Admin
    }

    handle {
        reverse_proxy * {
            to http://192.168.2.223:8081
            header_up X-Real-IP {remote_host}
        }
    }
}
```

## Key Files

- **Forward Auth Controller**: `app/controllers/api/forward_auth_controller.rb`
- **Authentication Logic**: `app/controllers/concerns/authentication.rb`
- **Caddy Examples**: `docs/caddy-example.md`
- **Authelia Analysis**: `docs/authelia-forward-auth.md`

## Testing

```bash
# Test forward auth endpoint directly
curl -v http://localhost:9000/api/verify?rd=https://clinch.example.com

# Should return 302 redirect to login page
# Or 200 OK if you have a valid session cookie
```

## Troubleshooting

### Common Issues

1. **Authentication Loop**: Check that cookies are set on the root domain
2. **Session Not Shared**: Verify `extract_root_domain` is working correctly
3. **Caddy Connection**: Ensure `clinch:9000` resolves from your Caddy container
4. **Race Condition After Authentication**:
   - **Problem**: Forward auth fails immediately after login due to cookie timing
   - **Solution**: One-time tokens automatically bridge this gap
   - **Debug**: Look for "ForwardAuth: Valid one-time token used" in logs

### Debug Logging

Enable debug logging in `forward_auth_controller.rb` to see:
- Headers received from Caddy
- Domain extraction results
- Redirect URLs being generated
- Token validation during race condition resolution

```ruby
Rails.logger.info "ForwardAuth Headers: Host=#{host}, X-Forwarded-Host=#{original_host}"
Rails.logger.info "Setting 302 redirect to: #{login_url}"
Rails.logger.info "ForwardAuth: Valid one-time token used for session #{session_id}"
Rails.logger.info "Authentication: Added forward auth token to redirect URL: #{url}"
```

**Key log messages to watch for:**
- `"Authentication: Added forward auth token to redirect URL"` - Token generation during login
- `"ForwardAuth: Valid one-time token used for session X"` - Successful race condition resolution
- `"ForwardAuth: Session cookie present: false"` - Cookie timing issue (should be resolved by token)

## Other References

- https://www.reddit.com/r/selfhosted/comments/1hybe81/i_wanted_to_implement_my_own_forward_auth_proxy/
- https://www.kevinsimper.dk/posts/implementing-a-forward_auth-proxy-tips-and-details