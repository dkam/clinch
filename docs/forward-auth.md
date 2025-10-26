# Forward Authentication

References:
- https://www.reddit.com/r/selfhosted/comments/1hybe81/i_wanted_to_implement_my_own_forward_auth_proxy/
- https://www.kevinsimper.dk/posts/implementing-a-forward_auth-proxy-tips-and-details

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

Example: `https://clinch.aapamilne.com/signin?rd=https://metube.aapamilne.com/&rm=GET`

### Tip 2: Root Domain Cookies ✅

Clinch sets authentication cookies on the root domain to enable cross-subdomain authentication:

```ruby
def extract_root_domain(host)
  # clinch.aapamilne.com -> .aapamilne.com
  # app.example.co.uk -> .example.co.uk
  # localhost -> nil (no domain restriction)
end

cookies.signed.permanent[:session_id] = {
  value: session.id,
  httponly: true,
  same_site: :lax,
  secure: Rails.env.production?,
  domain: ".aapamilne.com"  # Available to all subdomains
}
```

This allows the same session cookie to work across:
- `clinch.aapamilne.com` (auth service)
- `metube.aapamilne.com` (protected app)
- `sonarr.aapamilne.com` (protected app)

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

1. **User visits** `https://metube.aapamilne.com/`
2. **Caddy forwards** to `http://clinch:9000/api/verify?rd=https://clinch.aapamilne.com`
3. **Clinch checks session**:
   - **If authenticated**: Returns `200 OK` with user headers
   - **If not authenticated**: Returns `302 Found` to login URL with redirect parameters
4. **Browser follows redirect** to Clinch login page
5. **User logs in** → gets redirected back to original MEtube URL
6. **Caddy tries again** → succeeds and forwards to MEtube

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
Location: https://clinch.aapamilne.com/signin?rd=https://metube.aapamilne.com/&rm=GET
```

## Caddy Configuration

```caddyfile
# Clinch SSO (main authentication server)
clinch.aapamilne.com {
    reverse_proxy clinch:9000
}

# MEtube (protected by Clinch)
metube.aapamilne.com {
    forward_auth clinch:9000 {
        uri /api/verify?rd=https://clinch.aapamilne.com
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
curl -v http://localhost:9000/api/verify?rd=https://clinch.aapamilne.com

# Should return 302 redirect to login page
# Or 200 OK if you have a valid session cookie
```

## Troubleshooting

### Common Issues

1. **Authentication Loop**: Check that cookies are set on the root domain
2. **Session Not Shared**: Verify `extract_root_domain` is working correctly
3. **Caddy Connection**: Ensure `clinch:9000` resolves from your Caddy container

### Debug Logging

Enable debug logging in `forward_auth_controller.rb` to see:
- Headers received from Caddy
- Domain extraction results
- Redirect URLs being generated

```ruby
Rails.logger.info "ForwardAuth Headers: Host=#{host}, X-Forwarded-Host=#{original_host}"
Rails.logger.info "Setting 302 redirect to: #{login_url}"
```