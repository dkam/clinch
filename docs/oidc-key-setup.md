# OIDC Private Key Setup

Your OIDC provider needs an RSA private key to sign ID tokens. **This key must persist across deployments** or all existing tokens will become invalid.

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

# Option A: Using kamal env push (Kamal 2.0+)
kamal env push OIDC_PRIVATE_KEY="$(cat oidc_private_key.pem)"

# Option B: Add to .kamal/secrets
echo "OIDC_PRIVATE_KEY=$(cat oidc_private_key.pem)" >> .kamal/secrets
```

### 4. Verify it's loaded

```bash
# In Rails console
bin/rails runner "puts OidcJwtService.send(:private_key).present? ? 'Key loaded' : 'Key missing'"
```

---

## Option 2: Rails Credentials (Simpler but less flexible)

### 1. Generate the key

```bash
openssl genrsa -out oidc_private_key.pem 2048
```

### 2. Add to Rails credentials

```bash
EDITOR="nano" bin/rails credentials:edit
```

Add this section:

```yaml
oidc_private_key: |
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAyZ0qaICMiLVWSFs+ef9Xok3fzy0p6k/7D5TQzmxf7C2vQG7s
  2Odmi8iAHLoaUBaFj70qTbaconWyMr8s+ah+qZwrwolTLUe23VrceVXvInU57hBL
  ...
  -----END RSA PRIVATE KEY-----
```

**Important:** Use the `|` pipe character for multi-line, and indent the key content with 2 spaces.

### 3. Save and verify

```bash
# Verify credentials file
cat config/credentials.yml.enc  # Should show encrypted data

# Test in console
bin/rails runner "puts OidcJwtService.send(:private_key).present? ? 'Key loaded' : 'Key missing'"
```

### 4. For deployment

The `config/credentials.yml.enc` file is committed to git. You need to:

1. **Set RAILS_MASTER_KEY** env variable in production
2. Get the key from `config/master.key` (don't commit this!)

```bash
# In Kamal
kamal env push RAILS_MASTER_KEY="$(cat config/master.key)"
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

If you need to rotate keys (security incident, etc.):

### 1. Generate new key

```bash
openssl genrsa -out oidc_private_key_new.pem 2048
```

### 2. Add NEW key alongside old (dual-key setup)

This requires code changes to support multiple keys in JWKS. For now, rotation means:

**Warning:** Rotating the key will **invalidate all existing OIDC sessions**. Users will need to log in again.

### 3. Update OIDC_PRIVATE_KEY

```bash
kamal env push OIDC_PRIVATE_KEY="$(cat oidc_private_key_new.pem)"
```

### 4. Restart application

```bash
kamal deploy
```

---

## Troubleshooting

### "No private key found" warning

Check your setup:

```bash
# Is ENV set?
echo $OIDC_PRIVATE_KEY

# Can Rails load it?
bin/rails runner "puts ENV['OIDC_PRIVATE_KEY'].present? ? 'ENV set' : 'ENV missing'"

# Does it load correctly?
bin/rails runner "puts OidcJwtService.send(:private_key).to_s[0..50]"
```

### "invalid RSA key" error

- Make sure you include `-----BEGIN RSA PRIVATE KEY-----` header
- Ensure newlines are preserved (use quotes in ENV)
- Check for extra spaces or characters

### Different JWKS key ID on each restart

This means the key is being regenerated. You need to set `OIDC_PRIVATE_KEY` or add to credentials.

### All tokens invalid after deployment

The key changed. You either:
- Regenerated the key (don't do this!)
- Forgot to set ENV variable in production
- The key wasn't loaded correctly

Check logs for warnings and verify key is loaded:

```bash
kamal app logs --grep "OIDC"
```
