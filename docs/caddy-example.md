# Caddy ForwardAuth Configuration Examples

Use Caddy 2.11.2 or later. From 2.10.0 to 2.11.1, `copy_headers` passes on a
client's own copy of a header whenever Clinch's response leaves it out
(CVE-2026-30851), so a user could hand an app a forged identity. List every
header the app reads in `copy_headers`; any you leave out pass through from
the client untouched. See [Response Headers](forward-auth.md#response-headers).

## Basic Configuration (Protecting MEtube)

Assuming Caddy and Clinch are running in a docker compose, and we can use the sevice name `clinch`. Exterally, assume you're connecting to https://clinch.example.com/ 

```caddyfile
# Clinch SSO (main authentication server)
clinch.yourdomain.com {
    reverse_proxy clinch:3000
}

# MEtube (protected by Clinch)
metube.yourdomain.com {
    # Forward authentication to Clinch
    forward_auth clinch:3000 {
        uri /api/verify
        # uri /api/verify?rd=https://clinch.yourdomain.com # Shouldn't need this, the rd value should be sent via headers
        copy_headers X-Remote-User X-Remote-Email X-Remote-Name X-Remote-Username X-Remote-Groups X-Remote-Admin
    }

    # If authentication succeeds, proxy to MEtube
    handle {
        reverse_proxy * {
            to http://<ip-address-of-metube>:8081
            header_up X-Real-IP {remote_host}
        }
    }
}
```

## How It Works

1. User visits `https://metube.yourdomain.com`
2. Caddy makes request to `http://clinch:3000/api/verify passing in the url destination for metueb
3. Clinch checks if user is authenticated and authorized:
   - If **200**: Caddy forwards request to MEtube with user headers
   - If **302**: User is redirected to clinch.yourdomain.com to login
   - If **403**: Access denied
4. User signs into Clinch (with TOTP if enabled or Passkey)
5. Clinch redirects back to MEtube
6. User can now access MEtube!

## Protecting Multiple Applications

```caddyfile
# Clinch SSO
clinch.yourdomain.com {
    reverse_proxy clinch:3000
}

# MEtube - Anyone can access (no groups required)
metube.yourdomain.com {
    forward_auth clinch:3000 {
        uri /api/verify
        copy_headers X-Remote-User X-Remote-Email X-Remote-Name X-Remote-Username X-Remote-Groups X-Remote-Admin
    }

    handle {
        reverse_proxy * {
            to http://metube:8081
            header_up X-Real-IP {remote_host}
        }
    }
}

# Sonarr - Only "media-managers" group
sonarr.yourdomain.com {
    forward_auth clinch:3000 {
        uri /api/verify
        copy_headers X-Remote-User X-Remote-Email X-Remote-Name X-Remote-Username X-Remote-Groups X-Remote-Admin
    }

    handle {
        reverse_proxy * {
            to http://sonarr:8989
            header_up X-Real-IP {remote_host}
        }
    }
}

# Grafana - Only "admins" group
grafana.yourdomain.com {
    forward_auth clinch:3000 {
        uri /api/verify
        copy_headers X-Remote-User X-Remote-Email X-Remote-Name X-Remote-Username X-Remote-Groups X-Remote-Admin
    }

    handle {
        reverse_proxy * {
            to http://grafana:3001
            header_up X-Real-IP {remote_host}
        }
    }
}
```

## Setup Steps

### 1. Create Applications in Clinch

Create the Application within Clinch, making sure to set Forward Auth application type

### 2. Update Caddyfile

Add the forward_auth directives shown above.

### 3. Reload Caddy

```bash
caddy reload
```

### 4. Test

Visit https://metube.yourdomain.com - you should be redirected to Clinch login!

## Advanced: Passing Headers to Application

Some applications can use the forwarded headers for user identification:

```caddyfile
metube.yourdomain.com {
    forward_auth clinch:3000 {
        uri /api/verify
        copy_headers X-Remote-User X-Remote-Email X-Remote-Name X-Remote-Username X-Remote-Groups X-Remote-Admin
    }

    # The headers are automatically passed to the backend
    handle {
        reverse_proxy * {
            to http://metube:8081
            header_up X-Real-IP {remote_host}
        }
    }
}
```

Now MEtube receives these headers with every request:
- `X-Remote-User`: user@example.com
- `X-Remote-Email`: user@example.com
- `X-Remote-Groups`: media-managers,users
- `X-Remote-Admin`: false

## Troubleshooting

### Users not staying logged in

Ensure your Caddy configuration preserves cookies:

```caddyfile
clinch.yourdomain.com {
    reverse_proxy localhost:3000 {
        header_up X-Forwarded-Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

### Authentication loop

Check that the `/api/verify` endpoint is not itself protected:
- `/api/verify` must be accessible without authentication
- It returns 401/403 for unauthenticated users (this is expected)

### Check Clinch logs

```bash
tail -f log/production.log
```

You'll see ForwardAuth log messages like:
```
ForwardAuth: User user@example.com granted access to metube
ForwardAuth: Unauthorized - No session cookie
```
