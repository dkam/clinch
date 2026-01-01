# Forward Auth Testing Guide

## Overview
Testing forward authentication requires testing multiple layers: HTTP requests, session management, and header forwarding. This guide provides practical testing approaches.

## Quick Start

### 1. Start Rails Server
```bash
rails server
```

### 2. Basic curl Tests

#### Test 1: Unauthenticated Request
```bash
curl -v http://localhost:3000/api/verify \
  -H "X-Forwarded-Host: test.example.com"
```

**Expected Result:** 302 redirect to login
```
< HTTP/1.1 302 Found
< Location: http://localhost:3000/signin?rd=https://test.example.com/
< X-Auth-Reason: No session cookie
```

#### Test 2: Authenticated Request
1. Sign in at http://localhost:3000/signin
2. Copy session cookie from browser
3. Run:
```bash
curl -v http://localhost:3000/api/verify \
  -H "X-Forwarded-Host: test.example.com" \
  -H "Cookie: _clinch_session_id=YOUR_SESSION_COOKIE"
```

**Expected Result:** 200 OK with headers
```
< HTTP/1.1 200 OK
< X-Remote-User: your-email@example.com
< X-Remote-Email: your-email@example.com
< X-Remote-Name: your-email@example.com
< X-Remote-Groups: group-name
< X-Remote-Admin: true/false
```

## Testing Header Configurations

### Create Test Rules in Admin Interface

1. **Default Headers Rule** (`test.example.com`)
   - Leave header fields empty (uses defaults)
   - Expected: X-Remote-* headers

2. **No Headers Rule** (`metube.example.com`)
   - Set all header fields to empty strings
   - Expected: No authentication headers (access only)

3. **Custom Headers Rule** (`grafana.example.com`)
   - Set custom header names:
     - User Header: `X-WEBAUTH-USER`
     - Groups Header: `X-WEBAUTH-ROLES`
     - Email Header: `X-WEBAUTH-EMAIL`
   - Expected: Custom header names

### Test Different Configurations

```bash
# Test default headers
curl -v http://localhost:3000/api/verify \
  -H "X-Forwarded-Host: test.example.com" \
  -H "Cookie: _clinch_session_id=YOUR_SESSION_COOKIE"

# Test no headers (access only)
curl -v http://localhost:3000/api/verify \
  -H "X-Forwarded-Host: metube.example.com" \
  -H "Cookie: _clinch_session_id=YOUR_SESSION_COOKIE"

# Test custom headers
curl -v http://localhost:3000/api/verify \
  -H "X-Forwarded-Host: grafana.example.com" \
  -H "Cookie: _clinch_session_id=YOUR_SESSION_COOKIE"
```

## Domain Pattern Testing

Test various domain patterns:

```bash
# Wildcard subdomains
curl -v http://localhost:3000/api/verify \
  -H "X-Forwarded-Host: app.test.example.com"

# Exact domains
curl -v http://localhost:3000/api/verify \
  -H "X-Forwarded-Host: api.example.com"

# No matching rule (should use defaults)
curl -v http://localhost:3000/api/verify \
  -H "X-Forwarded-Host: unknown.example.com"
```

## Integration Testing

### Test with Real Reverse Proxy (Caddy Example)

1. Set up Caddy with forward auth:
```caddyfile
example.com {
    forward_auth localhost:3000 {
        uri /api/verify
        copy_headers X-Remote-User X-Remote-Email X-Remote-Groups X-Remote-Admin
    }

    reverse_proxy localhost:8080
}
```

2. Test by visiting `https://example.com` in browser
3. Should redirect to Clinch login, then back to application

## Unit Testing (Rails Console)

Test the header logic directly:

```ruby
# Rails console: rails console

# Get a user
user = User.first

# Test default headers
rule = ForwardAuthRule.create!(domain_pattern: 'test.example.com', active: true)
headers = rule.headers_for_user(user)
puts headers
# => {"X-Remote-User" => "user@example.com", "X-Remote-Email" => "user@example.com", ...}

# Test custom headers
rule.update!(headers_config: { user: 'X-Custom-User', groups: 'X-Custom-Groups' })
headers = rule.headers_for_user(user)
puts headers
# => {"X-Custom-User" => "user@example.com", "X-Remote-Email" => "user@example.com", ...}

# Test no headers
rule.update!(headers_config: { user: '', email: '', name: '', groups: '', admin: '' })
headers = rule.headers_for_user(user)
puts headers
# => {}
```

## Testing Checklist

### Basic Functionality
- [ ] Unauthenticated requests redirect to login
- [ ] Authenticated requests return 200 OK
- [ ] Headers are correctly forwarded to applications
- [ ] Session cookies work correctly

### Header Configurations
- [ ] Default headers (X-Remote-*) work
- [ ] Custom headers work with specific applications
- [ ] No headers option works for access-only apps
- [ ] Empty header fields are handled correctly

### Domain Matching
- [ ] Wildcard domains (*.example.com) work
- [ ] Exact domains work
- [ ] Case insensitivity works
- [ ] No matching rule falls back to defaults

### Access Control
- [ ] Group restrictions work correctly
- [ ] Inactive users are denied access
- [ ] Inactive rules are ignored
- [ ] Bypass mode (no groups) works

## Troubleshooting

### Common Issues

1. **Headers not being sent**
   - Check rule is active
   - Verify headers configuration
   - Check user is in allowed groups

2. **Authentication loops**
   - Check session cookie domain
   - Verify redirect URLs
   - Check browser cookie settings

3. **Headers not reaching application**
   - Check reverse proxy configuration
   - Verify proxy is forwarding headers
   - Check application expects correct header names

### Debug Logging

Enable debug logging in `forward_auth_controller.rb`:
```ruby
Rails.logger.level = Logger::DEBUG
```

This will show detailed information about:
- Session extraction
- Rule matching
- Header generation
- Redirect URLs

## Production Testing

Before deploying to production:

1. **SSL/TLS Testing**: Test with HTTPS
2. **Cookie Domains**: Test cross-subdomain cookies
3. **Performance**: Test response times under load
4. **Security**: Test with invalid sessions and malformed headers
5. **Monitoring**: Set up logging and alerting

## Automation

For automated testing, consider:

1. **Integration Tests**: Use Rails integration tests for controller testing
2. **API Tests**: Use tools like Postman or Insomnia for API testing
3. **Browser Tests**: Use Selenium or Cypress for end-to-end testing
4. **Load Testing**: Use tools like k6 or JMeter for performance testing