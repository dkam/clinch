# OIDC Private Key Setup

Clinch signs ID tokens, JWT access tokens and logout tokens with an RSA private key. **This key must persist across deployments** or all existing tokens will become invalid.

## Default: let Clinch generate it

If neither `OIDC_PRIVATE_KEY` nor Rails credentials supply a key, Clinch generates a 2048-bit key the first time it needs one and keeps it in the `oidc_signing_keys` table. There is nothing to set up.

The key is encrypted with keys derived from `SECRET_KEY_BASE`, like TOTP secrets, so a copy of the database alone can't sign tokens. It also means a backup needs both: restore the database with a different `SECRET_KEY_BASE` and Clinch can't read its key (or anyone's TOTP secret).

Supply a key yourself, as below, if you'd rather manage it outside Clinch. A key in `OIDC_PRIVATE_KEY` or credentials always wins over the stored one.

## Option 1: Environment Variable (Recommended for Docker/Kamal)

### 1. Generate the key

```bash
# Generate a 2048-bit RSA key
openssl genrsa -out oidc_private_key.pem 2048

# View the key (you'll copy this)
cat oidc_private_key.pem
```

### 2. Store in your `.env` file

```bash
# .env (for local development)
OIDC_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyZ0qaICMiLVWSFs+ef9Xok3fzy0p6k/7D5TQzmxf7C2vQG7s
2Odmi8iAHLoaUBaFj70qTbaconWyMr8s+ah+qZwrwolTLUe23VrceVXvInU57hBL
...
-----END RSA PRIVATE KEY-----"
```

**Important:** Keep the quotes and include the full key with `-----BEGIN` and `-----END` lines.

### 3. For Kamal deployment

Add to your Kamal secrets:

```yaml
# config/deploy.yml
env:
  secret:
    - OIDC_PRIVATE_KEY
```

Then set it securely:

```bash
# Generate key
bin/generate_oidc_key > oidc_private_key.pem

# Add to .kamal/secrets
echo "OIDC_PRIVATE_KEY=$(cat oidc_private_key.pem)" >> .kamal/secrets
```

### 4. Verify it's loaded

```bash
# In Rails console
bin/rails runner "puts OidcJwtService.send(:private_key).present? ? 'Key loaded' : 'Key missing'"
```

---

## Comparison

| Feature | ENV Variable | Rails Credentials |
|---------|-------------|-------------------|
| **Best for** | Docker, Kamal, 12-factor | Simple deployments |
| **Key rotation** | Easy (just update ENV) | Medium (re-encrypt) |
| **Per-environment** | Yes (dev/staging/prod can differ) | No (same key everywhere) |
| **Secrets manager** | Compatible (AWS Secrets, etc.) | Needs RAILS_MASTER_KEY |
| **Setup complexity** | Low | Medium |

**Recommendation:** Use ENV variable (`OIDC_PRIVATE_KEY`) for production with Kamal.

---

## Security Best Practices

### DO:
- ✅ Generate the key once and keep it forever
- ✅ Store in secret manager (AWS Secrets Manager, 1Password, etc.)
- ✅ Use strong key (2048-bit RSA minimum)
- ✅ Backup the key securely
- ✅ Restrict access (only ops team)

### DON'T:
- ❌ Commit the key to git (except encrypted credentials)
- ❌ Share the key in Slack/email
- ❌ Regenerate the key (invalidates all tokens)
- ❌ Store in `.env` if it's committed to git
- ❌ Use the same key for multiple environments

---

## Key Rotation (Advanced)

Todo

---

## Troubleshooting

### Checking which key is loaded

Check your setup:

```bash
# Is ENV set?
echo $OIDC_PRIVATE_KEY

# Can Rails load it?
bin/rails runner "puts ENV['OIDC_PRIVATE_KEY'].present? ? 'ENV set' : 'ENV missing'"

# Which key is in use? (prints the key ID, never the key)
bin/rails runner "puts OidcJwtService.jwks[:keys].first[:kid]"
```

### "invalid RSA key" error

- Make sure you include `-----BEGIN RSA PRIVATE KEY-----` header
- Ensure newlines are preserved (use quotes in ENV)
- Check for extra spaces or characters

### Different JWKS key ID on each restart

The key is changing between boots. Check that `OIDC_PRIVATE_KEY` isn't being set to different values, and that the database (the `storage/` volume) is persisted rather than recreated with the container.

### All tokens invalid after deployment

The key changed. You either:
- Regenerated the key (don't do this!)
- Removed `OIDC_PRIVATE_KEY`, so Clinch fell back to its stored key (or generated one)
- Restored the database with a different `SECRET_KEY_BASE`
- The key wasn't loaded correctly

Check logs for warnings and verify key is loaded:

```bash
kamal app logs --grep "OIDC"
```
