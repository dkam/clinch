# OIDC Refresh Tokens - Client Implementation Guide

## Overview

Clinch now supports **OAuth 2.0 Refresh Tokens**, allowing your applications to maintain long-lived sessions without requiring users to re-authenticate every hour.

**Key Benefits:**
- ✅ No user re-authentication for 30 days (configurable)
- ✅ Silent token refresh - no redirects, no user interaction
- ✅ Secure token rotation - prevents reuse attacks
- ✅ Token revocation support - users can invalidate sessions

---

## Quick Start

### Before (Without Refresh Tokens)
```
User logs in → Access token (1 hour)
After 1 hour → Redirect to /oauth/authorize
User auto-approves → New access token
Repeat every hour... 😞
```

### Now (With Refresh Tokens)
```
User logs in → Access token (1 hour) + Refresh token (30 days)
After 1 hour → POST to /oauth/token with refresh_token
Get new tokens → No redirect! No user interaction! 🎉
```

---

## Initial Authorization

### 1. Authorization Code Flow (Unchanged)

**Step 1: Redirect user to authorization endpoint**
```
GET https://auth.example.com/oauth/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://yourapp.com/callback&
  response_type=code&
  scope=openid%20profile%20email&
  state=RANDOM_STATE&
  code_challenge=BASE64URL(SHA256(code_verifier))&
  code_challenge_method=S256
```

**Step 2: Exchange authorization code for tokens**
```http
POST https://auth.example.com/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTHORIZATION_CODE
&redirect_uri=https://yourapp.com/callback
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
&code_verifier=CODE_VERIFIER
```

**Response (NEW - now includes refresh_token):**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGc...",
  "refresh_token": "abc123xyz...",
  "scope": "openid profile email"
}
```

**IMPORTANT:** Store the `refresh_token` securely! You'll need it to get new access tokens.

---

## Token Refresh Flow

When your `access_token` expires (after 1 hour), use the `refresh_token` to get new tokens **without user interaction**.

### How to Refresh Tokens

**Request:**
```http
POST https://auth.example.com/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=YOUR_REFRESH_TOKEN
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
```

**Response:**
```json
{
  "access_token": "eyJhbGc...NEW",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGc...NEW",
  "refresh_token": "def456uvw...NEW",
  "scope": "openid profile email"
}
```

**CRITICAL:**
- The old `refresh_token` is **immediately revoked** (single-use)
- You receive a **new `refresh_token`** to use next time
- **Replace** the old refresh token with the new one in your storage

---

## Token Lifecycle

```
┌─────────────────────────────────────────────────────────┐
│ Initial Authorization                                   │
├─────────────────────────────────────────────────────────┤
│ GET /oauth/authorize → User logs in                     │
│ POST /oauth/token (authorization_code grant)            │
│   ↓                                                      │
│ Receive: access_token (1h) + refresh_token (30d)        │
└─────────────────────────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────┐
│ Token Refresh (Silent, No User Interaction)            │
├─────────────────────────────────────────────────────────┤
│ After 1 hour (access_token expires):                    │
│ POST /oauth/token (refresh_token grant)                 │
│   ↓                                                      │
│ Receive: NEW access_token + NEW refresh_token           │
│ Old refresh_token is revoked                            │
└─────────────────────────────────────────────────────────┘
                         │
                         ↓ (Repeat for 30 days)
┌─────────────────────────────────────────────────────────┐
│ Session Expiry                                          │
├─────────────────────────────────────────────────────────┤
│ After 30 days (refresh_token expires):                  │
│ Redirect user to /oauth/authorize for re-authentication │
└─────────────────────────────────────────────────────────┘
```

---

## Token Storage Best Practices

### ✅ Secure Storage Recommendations

**Web Applications (Server-Side):**
- Store refresh tokens in **server-side session** (encrypted)
- Use **HttpOnly, Secure cookies** for access tokens
- **Never** send refresh tokens to browser JavaScript

**Single Page Applications (SPAs):**
- Store access tokens in **memory only** (JavaScript variable)
- Store refresh tokens in **HttpOnly, Secure cookie** (via backend)
- Use Backend-for-Frontend (BFF) pattern for refresh

**Mobile Apps:**
- Use platform-specific **secure storage**:
  - iOS: Keychain
  - Android: EncryptedSharedPreferences or Keystore
- **Never** store in UserDefaults/SharedPreferences

**Desktop Apps:**
- Use OS-specific credential storage
- Encrypt tokens at rest

### ❌ DO NOT Store Refresh Tokens In:
- LocalStorage (XSS vulnerable)
- SessionStorage (XSS vulnerable)
- Unencrypted cookies
- Plain text files
- Source code or config files

---

## Token Revocation

Allow users to invalidate their sessions (e.g., "Sign out of all devices").

### Revoke a Token

**Request:**
```http
POST https://auth.example.com/oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=YOUR_TOKEN
&token_type_hint=refresh_token
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
```

**Parameters:**
- `token` (required) - The token to revoke (access or refresh token)
- `token_type_hint` (optional) - "access_token" or "refresh_token"
- `client_id` + `client_secret` (required) - Client authentication

**Response:**
```
HTTP/1.1 200 OK
```

**Note:** Per RFC 7009, the response is always `200 OK`, even if the token was invalid or already revoked (prevents token scanning attacks).

---

## Error Handling

### Refresh Token Errors

#### 1. Invalid or Expired Refresh Token
```json
{
  "error": "invalid_grant",
  "error_description": "Invalid refresh token"
}
```
**Action:** Redirect user to /oauth/authorize for re-authentication

#### 2. Refresh Token Revoked (Reuse Detected!)
```json
{
  "error": "invalid_grant",
  "error_description": "Refresh token has been revoked"
}
```
**Action:**
- This indicates a **security issue** (possible token theft)
- All tokens in the same family are revoked
- Redirect user to /oauth/authorize
- Consider alerting the user about suspicious activity

#### 3. Invalid Client Credentials
```json
{
  "error": "invalid_client"
}
```
**Action:** Check your `client_id` and `client_secret`

---

## Implementation Examples

### Example 1: Node.js Express

```javascript
const axios = require('axios');

class OAuthClient {
  constructor(config) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.tokenEndpoint = config.tokenEndpoint;
    this.accessToken = null;
    this.refreshToken = null;
    this.expiresAt = null;
  }

  // Exchange authorization code for tokens
  async exchangeCode(code, redirectUri, codeVerifier) {
    const response = await axios.post(this.tokenEndpoint, new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code_verifier: codeVerifier
    }));

    this.storeTokens(response.data);
    return response.data;
  }

  // Refresh access token
  async refreshAccessToken() {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await axios.post(this.tokenEndpoint, new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: this.refreshToken,
      client_id: this.clientId,
      client_secret: this.clientSecret
    }));

    this.storeTokens(response.data);
    return response.data;
  }

  // Get valid access token (auto-refresh if needed)
  async getAccessToken() {
    // Check if token is expired or about to expire (5 min buffer)
    if (this.expiresAt && Date.now() >= this.expiresAt - 300000) {
      await this.refreshAccessToken();
    }

    return this.accessToken;
  }

  storeTokens(tokenResponse) {
    this.accessToken = tokenResponse.access_token;
    this.refreshToken = tokenResponse.refresh_token;
    this.expiresAt = Date.now() + (tokenResponse.expires_in * 1000);
  }

  // Revoke tokens
  async revokeToken(token, tokenTypeHint) {
    await axios.post('https://auth.example.com/oauth/revoke', new URLSearchParams({
      token: token,
      token_type_hint: tokenTypeHint,
      client_id: this.clientId,
      client_secret: this.clientSecret
    }));
  }
}

// Usage
const client = new OAuthClient({
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  tokenEndpoint: 'https://auth.example.com/oauth/token'
});

// After initial login
await client.exchangeCode(authCode, redirectUri, codeVerifier);

// Make API calls (auto-refreshes if needed)
const token = await client.getAccessToken();
const apiResponse = await axios.get('https://api.example.com/data', {
  headers: { Authorization: `Bearer ${token}` }
});

// Logout - revoke refresh token
await client.revokeToken(client.refreshToken, 'refresh_token');
```

### Example 2: Python

```python
import requests
import time
from urllib.parse import urlencode

class OAuthClient:
    def __init__(self, client_id, client_secret, token_endpoint):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.access_token = None
        self.refresh_token = None
        self.expires_at = None

    def exchange_code(self, code, redirect_uri, code_verifier):
        """Exchange authorization code for tokens"""
        response = requests.post(self.token_endpoint, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code_verifier': code_verifier
        })
        response.raise_for_status()
        self._store_tokens(response.json())
        return response.json()

    def refresh_access_token(self):
        """Refresh the access token using refresh token"""
        if not self.refresh_token:
            raise ValueError('No refresh token available')

        response = requests.post(self.token_endpoint, data={
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        })
        response.raise_for_status()
        self._store_tokens(response.json())
        return response.json()

    def get_access_token(self):
        """Get valid access token, refresh if needed"""
        # Check if token is expired (with 5 min buffer)
        if self.expires_at and time.time() >= self.expires_at - 300:
            self.refresh_access_token()

        return self.access_token

    def _store_tokens(self, token_response):
        """Store tokens and expiration time"""
        self.access_token = token_response['access_token']
        self.refresh_token = token_response['refresh_token']
        self.expires_at = time.time() + token_response['expires_in']

    def revoke_token(self, token, token_type_hint='refresh_token'):
        """Revoke a token"""
        requests.post('https://auth.example.com/oauth/revoke', data={
            'token': token,
            'token_type_hint': token_type_hint,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        })

# Usage
client = OAuthClient(
    client_id='your-client-id',
    client_secret='your-client-secret',
    token_endpoint='https://auth.example.com/oauth/token'
)

# After initial login
client.exchange_code(auth_code, redirect_uri, code_verifier)

# Make API calls (auto-refreshes if needed)
token = client.get_access_token()
response = requests.get('https://api.example.com/data',
                       headers={'Authorization': f'Bearer {token}'})

# Logout
client.revoke_token(client.refresh_token, 'refresh_token')
```

---

## Security Considerations

### 1. Token Rotation (Implemented ✅)
- Each refresh token is **single-use only**
- After use, old refresh token is immediately revoked
- New refresh token is issued
- Prevents replay attacks

### 2. Token Family Tracking (Implemented ✅)
- All refresh tokens in a rotation chain share a `token_family_id`
- If a **revoked** refresh token is reused → **entire family is revoked**
- Detects stolen token attacks

### 3. Refresh Token Binding
- Refresh tokens are bound to:
  - Specific client (client_id)
  - Specific user
  - Specific scopes
- Cannot be used by different clients

### 4. Expiration Times (Configurable per application)
- **Access tokens:** 5 minutes - 24 hours (default: 1 hour)
- **Refresh tokens:** 1 day - 90 days (default: 30 days)
- **ID tokens:** 5 minutes - 24 hours (default: 1 hour)

---

## Discovery Endpoint Updates

The OIDC discovery endpoint now advertises refresh token support:

**GET `https://auth.example.com/.well-known/openid-configuration`**

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "userinfo_endpoint": "https://auth.example.com/oauth/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "response_types_supported": ["code"],
  "scopes_supported": ["openid", "profile", "email", "groups"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  ...
}
```

---

## Testing Your Implementation

### Test 1: Initial Token Exchange
```bash
# Get authorization code (manual - visit in browser)
# Then exchange for tokens:

curl -X POST https://auth.example.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "redirect_uri=https://yourapp.com/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=YOUR_CODE_VERIFIER"

# Response should include refresh_token
```

### Test 2: Token Refresh
```bash
curl -X POST https://auth.example.com/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"

# Response should include NEW access_token and NEW refresh_token
```

### Test 3: Token Revocation
```bash
curl -X POST https://auth.example.com/oauth/revoke \
  -d "token=YOUR_REFRESH_TOKEN" \
  -d "token_type_hint=refresh_token" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"

# Should return 200 OK
```

### Test 4: Reuse Detection (Security Test)
```bash
# 1. Use refresh token to get new tokens
curl -X POST ... (as in Test 2)

# 2. Try to use the OLD refresh token again
curl -X POST ... (with OLD refresh_token)

# Should return error: "invalid_grant" - token has been revoked
```

---

## FAQ

### Q: How long do refresh tokens last?
**A:** By default, 30 days. This is configurable per application (1-90 days).

### Q: Can I use the same refresh token multiple times?
**A:** No. Refresh tokens are **single-use**. After using a refresh token, you get a new one.

### Q: What happens if my refresh token is stolen?
**A:** If someone tries to use a revoked refresh token, all tokens in that family are immediately revoked (token rotation security).

### Q: Do I need to store the ID token?
**A:** Usually no. The ID token is for authentication (verify user identity). You typically decode it, verify it, extract claims, then discard it.

### Q: Can I refresh an access token before it expires?
**A:** Yes! It's recommended to refresh tokens 5-10 minutes before expiration to avoid race conditions.

### Q: What if my refresh token expires?
**A:** User must re-authenticate via the normal OAuth flow (redirect to /oauth/authorize).

### Q: Can I revoke all of a user's sessions at once?
**A:** Yes, but you need to track all refresh tokens per user on your backend, then revoke them all.

### Q: Are access tokens revocable?
**A:** Yes! You can revoke access tokens using the same `/oauth/revoke` endpoint.

---

## Migration Guide (From Access Token Only)

### Before (Access Token Only):
```javascript
// User logs in
const tokens = await exchangeAuthCode(code);
localStorage.setItem('access_token', tokens.access_token);

// After 1 hour -> Token expires -> Redirect to login
if (isTokenExpired()) {
  window.location = '/oauth/authorize';
}
```

### After (With Refresh Tokens):
```javascript
// User logs in
const tokens = await exchangeAuthCode(code);
sessionStorage.setItem('access_token', tokens.access_token);
secureStorage.set('refresh_token', tokens.refresh_token); // Encrypted

// After 1 hour -> Refresh silently
if (isTokenExpired()) {
  const newTokens = await refreshAccessToken();
  sessionStorage.setItem('access_token', newTokens.access_token);
  secureStorage.set('refresh_token', newTokens.refresh_token);
}
```

---

## Additional Resources

- **RFC 6749 (OAuth 2.0):** https://datatracker.ietf.org/doc/html/rfc6749
- **RFC 7009 (Token Revocation):** https://datatracker.ietf.org/doc/html/rfc7009
- **OIDC Core Spec:** https://openid.net/specs/openid-connect-core-1_0.html
- **OAuth 2.0 Security Best Practices:** https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics

---

## Support

For issues or questions about refresh token implementation, contact your Clinch administrator or check the application documentation.

**Version:** 1.0
**Last Updated:** November 2025
