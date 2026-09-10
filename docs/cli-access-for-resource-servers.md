# Giving a CLI (or an agent) authenticated access to your app

**The flow is the OAuth 2.0 Device Authorization Grant (RFC 8628)** — "device flow"
for short. A CLI prints a short code and a URL; a human approves in a browser with
their passkey; the CLI polls until it receives tokens. It is what `c2a2 login` does,
and it is how any clinch-fronted app should give a terminal tool or an AI agent
access to its API.

Do not reach for `client_credentials` — clinch does not implement it, deliberately.
See [ADR 0006](decisions/0006-no-client-credentials-grant.md) for why.

Reference implementation: the `c2a2` repo. The CLI half (`cli/lib/clinch_cli/`) is
app-agnostic, stdlib-only, and meant to be copied; the server half is
`app/lib/clinch_api_token.rb`, `app/controllers/well_known_controller.rb`, and
`ApplicationController#valid_api_auth?`. `c2a2/docs/ai-production-access.md` is the
narrative version.

---

## What you are building

```
  CLI  ──(1) device flow, resource=https://yourapp ──▶  clinch    (issues token, aud=yourapp)
  CLI  ──(2) Authorization: Bearer <token> ──────────▶  your app

  then, depending on the client's access_token_format:
  opaque:  your app ──POST /oauth/introspect (Basic auth)──▶  clinch   (per request)
  jwt:     your app verifies the signature locally against a cached JWKS  (no call)
```

The token is bound to your app as its audience (RFC 8707), so a token minted for a
different clinch-protected app cannot be replayed against yours. Your app never
decodes the token — clinch is the only authority on whether it is live
([ADR 0001](decisions/0001-opaque-vs-jwt-access-tokens.md)).

---

## Server side — five pieces

Assume your app already does browser SSO against clinch (gr and booko both do), so
`OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / the issuer are already configured. You are
adding the API half.

### 1. A canonical resource identifier

One env var, the external origin of your app, no trailing slash:

```ruby
# ApplicationController
def resource_base_url
  ENV.fetch("MYAPP_RESOURCE_URL", request.base_url).chomp("/")
end
```

The env override matters behind a proxy: the audience you validate must be the origin
the *client* sees, not what Rails sees. This exact string is what the CLI sends as
`resource=` and what clinch stamps into `aud`. Any mismatch — scheme, port, trailing
slash — is a 401 you will spend an hour on.

### 2. Choose a token format

Two ways for your app to validate a bearer token, set per-client in clinch via
`access_token_format` ([ADR 0007](decisions/0007-jwt-access-tokens.md)):

| | `opaque` (default) | `jwt` (RFC 9068) |
|---|---|---|
| Validation | POST to `/oauth/introspect` | Verify signature against the JWKS, locally |
| Per-request cost | HTTP round trip (cacheable) | ~50µs RSA check, no I/O |
| Depends on clinch being up | Yes, on cache miss | No |
| Revocation | Instant | When the token expires |
| Needs a client secret | Yes | No |
| Needs `resource_identifiers` registered | Yes | No — `aud` is in the token |

**Pick `jwt` if your API serves more than a few requests per second** (c2a2 and shopo
do). Pick `opaque` — the default — if "revoke" has to mean *now*. If you choose `jwt`,
set a *short* `access_token_ttl`: under JWT the TTL is the revocation window, which is
the opposite of how it behaves with opaque tokens.

Sections 3 and 4 below apply to both. Section 2a applies only to `opaque`, 2b only to
`jwt`.

### 2a. Opaque: introspection-backed bearer auth

Copy `c2a2/app/lib/clinch_api_token.rb` essentially verbatim. It:

- discovers `introspection_endpoint` from `{issuer}/.well-known/openid-configuration`
  (cached 12h, falls back to `{issuer}/oauth/introspect`),
- POSTs `token=` there with **HTTP Basic** using your `OIDC_CLIENT_ID` /
  `OIDC_CLIENT_SECRET` — introspection is a confidential-client call,
- requires `active == true` **and** `aud == your resource identifier`,
- reads `username` (the email) and `groups` from the response,
- caches by token digest for ~5 minutes, negatives included, so a client looping on a
  dead token does not hammer clinch,
- never raises: any transport failure is a nil, which becomes a 401.

Then wire it in:

```ruby
def valid_api_auth?
  token = bearer_token
  return false if token.blank?

  email = ClinchApiToken.authorized_email(token, resource: resource_base_url)
  @api_user_email = email if email
  email.present?
end
```

Note what clinch will and will not tell you: `username` comes back only if the token
carries the `email` scope, `groups` only with the `groups` scope
([ADR 0005](decisions/0005-introspection-authorization.md)). Ask for both in the CLI's
scope list or you will get an active token with no identity attached.

### 2b. JWT: offline verification

No client secret, no callback. Fetch clinch's JWKS, verify, check the claims yourself:

```ruby
payload, header = JWT.decode(token, jwks_key_for(header_kid), true, {algorithm: "RS256"})

raise unless header["typ"] == "at+jwt"          # RFC 9068 §2.1 — not an ID token
raise unless payload["iss"] == clinch_issuer    # minted by our IdP
raise unless payload["aud"] == resource_base_url # RFC 8707 — minted for *us*
# exp is checked by the decode itself
```

All four checks matter. `typ` stops an ID token being presented as an access token;
`aud` is the confused-deputy protection that introspection would otherwise have given
you. The identity is in the token: `email` and `groups`, gated on the same scopes
introspection gates them on.

**Cache the JWKS, but refetch on an unknown `kid`.** Every token names its signing key
in the `kid` header. If you cache the JWKS on a fixed TTL alone, the first key rotation
blackholes every request until that TTL lapses. Cache for 12–24h *and* refetch (rate
limited, say once a minute) whenever a token arrives with a `kid` you don't hold. gr's
`OidcService#decode_with_jwks` already does exactly this for ID tokens — the same
pattern, reused.

clinch publishes a single key today and has no rotation mechanism, so this costs you
nothing now and saves an outage later.

### 3. Register the resource identifier in clinch

*(`opaque` clients only — a JWT carries its audience in the token.)*

Introspection is authorized, not open. Clinch discloses a token to you only if it was
issued to your client **or** bound to a resource you are registered to serve. Set
`resource_identifiers` on your `Application` row in clinch to a JSON array containing
your resource identifier — the exact same string as step 1.

Get this wrong and clinch answers `{"active": false}` — identical to a dead token, by
design (RFC 7662 §4). `ClinchApiToken` logs the ambiguity explicitly rather than
claiming "invalid token", because the two failures have completely different fixes.

### 4. Authorization on identity

Introspection tells you *who*; you still decide *whether*. Copy c2a2's shape: an
email/domain allow-list OR clinch group membership.

```ruby
ClinchAuthorization.authorized_identity?(email: info["email"], groups: info["groups"])
```

Group-based is usually what you want — make a group in clinch, put people in it, leave
the email list empty.

### 5. Protected Resource Metadata (RFC 9728) — optional but cheap

Lets an OAuth 2.1 / MCP client discover clinch on its own from a 401:

```ruby
# GET /.well-known/oauth-protected-resource(/*resource_path)
{
  resource: resource_identifier,
  authorization_servers: [issuer],
  scopes_supported: %w[openid email profile groups],
  bearer_methods_supported: ["header"],
  resource_name: "MyApp"
}
```

and on a JSON 401 emit:

```
WWW-Authenticate: Bearer resource_metadata="#{resource_base_url}/.well-known/oauth-protected-resource"
```

Build the pointer from `resource_base_url`, not `request.base_url`, for the same
proxy reason as step 1. Do this if you ever want an MCP connector; skip it if the CLI
is the only client.

---

## CLI side

Copy `c2a2/cli/` and change the command layer. `lib/clinch_cli/` needs no edits — point
it at your app:

```ruby
ClinchCli::Client.new(
  app:      "myapp",                        # names the token file
  issuer:   ENV.fetch("CLINCH_ISSUER", "https://auth.booko.info"),
  resource: ENV.fetch("MYAPP_API", "https://myapp.booko.info"),
  scopes:   %w[openid email profile groups offline_access]
)
```

`resource:` must equal the server's `resource_base_url` **exactly**. `offline_access`
is what gets you a refresh token; `email` and `groups` are what make introspection
disclose an identity.

What it does on `login`:

1. **Dynamic Client Registration (RFC 7591)** — registers itself with clinch on first
   run. No pre-shared client secret to distribute.
2. **Device authorization** with a PKCE challenge and `resource=`. A DCR-registered
   CLI is a *public* client, and clinch requires the `code_challenge` on the
   device-authorization request itself for those — not just at the token step —
   since PKCE is a public client's only proof of possession.
3. Prints the URL and code, and tries to open `verification_uri_complete` (which
   pre-fills the code):

   ```
   Authorize this machine:

     https://auth.booko.info/device?user_code=ABCD-1234

     (code: ABCD-1234)

   Waiting for approval… (Ctrl-C to cancel)
   ```

4. **Polls the token endpoint** with the PKCE verifier and `resource=` until you
   approve at `/device`, honouring `slow_down`.
5. Stores tokens at `$XDG_CONFIG_HOME/clinch-cli/<app>.json`, mode 0600, and refreshes
   transparently. `resource=` goes on the refresh request too, or the re-issued token
   loses its audience.

Access tokens live 1 hour, refresh tokens 30 days and rotate on use — so a tool in
regular use never logs in again. If yours does lapse too often, raise
`refresh_token_ttl` on that `Application` in clinch rather than changing anything else.

---

## Checklist

- [ ] `MYAPP_RESOURCE_URL` set to the external origin, no trailing slash
- [ ] `access_token_format` chosen on the clinch `Application` (jwt for a busy API)
- [ ] **opaque only:** `resource_identifiers` on the `Application` contains that exact string
- [ ] **opaque only:** `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` available to the API path, not just SSO
- [ ] **jwt only:** JWKS cached, and refetched on an unknown `kid`
- [ ] **jwt only:** `typ`, `iss`, `aud` and `exp` all checked, not just the signature
- [ ] **jwt only:** `access_token_ttl` set short — it is the revocation window
- [ ] CLI's `resource:` string is byte-identical to the server's
- [ ] CLI requests `email`, `groups`, `offline_access`
- [ ] a clinch group exists for API users, and your allow-list checks it
- [ ] `{"active": false}` on a token you believe is good ⇒ suspect
      `resource_identifiers`, not the token

## Debugging

`{"active": false}` is deliberately ambiguous — dead token, or a caller clinch will not
disclose to. To tell them apart, introspect by hand from the app's host:

```bash
curl -s -u "$OIDC_CLIENT_ID:$OIDC_CLIENT_SECRET" \
  -d "token=$(myapp token -p)" \
  https://auth.booko.info/oauth/introspect | jq
```

An active token that comes back inactive means your `resource_identifiers` and the
token's `aud` do not match. Compare them literally, character by character.
