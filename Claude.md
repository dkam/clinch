# Claude Code Guidelines for Clinch

This document provides guidelines for AI assistants (Claude, ChatGPT, etc.) working on this codebase.

## Project Context

Clinch is a lightweight identity provider (IdP) supporting:
- **OIDC/OAuth2** - Standard OAuth flows for modern apps
- **ForwardAuth** - Trusted-header SSO for reverse proxies (Traefik, Caddy, Nginx)
- **WebAuthn/Passkeys** - Passwordless authentication
- Group-based access control

Key characteristics:
- Rails 8 application with SQLite database
- Focus on simplicity and self-hosting
- No external dependencies for core functionality

## Testing Guidelines

### Do Not Test Rails Framework Functionality

When writing tests, focus on testing **our application's specific behavior and logic**, not standard Rails framework functionality.

**Examples of what NOT to test:**
- Session isolation between users (Rails handles this)
- Basic ActiveRecord associations (Rails handles this)
- Standard cookie signing/verification (Rails handles this)
- Default controller rendering behavior (Rails handles this)
- Infrastructure-level error handling (database connection failures, network issues, etc.)

**Examples of what TO test:**
- Forward auth business logic (group-based access control, header configuration, etc.)
- Custom authentication flows
- Application-specific session expiration behavior
- Domain pattern matching logic
- Custom response header generation

**Why:**
Testing Rails framework functionality adds no value and can create maintenance burden. Trust that Rails works correctly and focus tests on verifying our application's unique behavior.

### Integration Test Patterns

**Session handling:**
- Do NOT manually manipulate cookies in integration tests
- Use the session provided by the test framework
- To get the actual session ID, use `Session.last.id` after sign-in, not `cookies[:session_id]` (which is signed)

**Application setup:**
- Always create Application records for the domains you're testing
- Use wildcard patterns (e.g., `*.example.com`) when testing multiple subdomains
- Remember: `*` matches one level only (`*.example.com` matches `app.example.com` but NOT `sub.app.example.com`)

**Header assertions:**
- Always normalize header names to lowercase when asserting (HTTP headers are case-insensitive)
- Use `response.headers["x-remote-user"]` not `response.headers["X-Remote-User"]`

**Avoid threading in integration tests:**
- Rails integration tests use a single cookie jar
- Convert threaded tests to sequential requests instead

### Common Testing Pitfalls

1. **Don't test concurrent users with manual cookie manipulation** - Integration tests can't properly simulate multiple concurrent sessions
2. **Don't expect `cookies[:session_id]` to be the actual ID** - It's a signed cookie value
3. **Don't assume wildcard patterns match multiple levels** - `*.domain.com` only matches one level
