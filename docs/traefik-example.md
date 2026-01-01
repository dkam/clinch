# Traefik ForwardAuth Configuration Examples

## Basic Configuration (Protecting MEtube)

### docker-compose.yml with Traefik Labels

```yaml
version: '3'

services:
  # Clinch SSO
  clinch:
    image: your-clinch-image
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.clinch.rule=Host(`clinch.yourdomain.com`)"
      - "traefik.http.routers.clinch.entrypoints=websecure"
      - "traefik.http.routers.clinch.tls.certresolver=letsencrypt"
      - "traefik.http.services.clinch.loadbalancer.server.port=3000"

  # MEtube - Protected by Clinch
  metube:
    image: ghcr.io/alexta69/metube
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.metube.rule=Host(`metube.yourdomain.com`)"
      - "traefik.http.routers.metube.entrypoints=websecure"
      - "traefik.http.routers.metube.tls.certresolver=letsencrypt"

      # ForwardAuth middleware
      - "traefik.http.routers.metube.middlewares=metube-auth"
      - "traefik.http.middlewares.metube-auth.forwardauth.address=http://clinch:3000/api/verify?app=metube"
      - "traefik.http.middlewares.metube-auth.forwardauth.authResponseHeaders=Remote-User,Remote-Email,Remote-Groups,Remote-Admin"

      - "traefik.http.services.metube.loadbalancer.server.port=8081"
```

## Traefik Static Configuration (File)

### traefik.yml

```yaml
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https

  websecure:
    address: ":443"

certificatesResolvers:
  letsencrypt:
    acme:
      email: your-email@example.com
      storage: /letsencrypt/acme.json
      tlsChallenge: {}

providers:
  docker:
    exposedByDefault: false
  file:
    filename: /config/dynamic.yml
    watch: true
```

## Traefik Dynamic Configuration (File)

### dynamic.yml

```yaml
http:
  middlewares:
    # Clinch ForwardAuth middleware for MEtube
    metube-auth:
      forwardAuth:
        address: "http://clinch:3000/api/verify?app=metube"
        authResponseHeaders:
          - "Remote-User"
          - "Remote-Email"
          - "Remote-Groups"
          - "Remote-Admin"

    # Clinch ForwardAuth for Sonarr (with group restriction)
    sonarr-auth:
      forwardAuth:
        address: "http://clinch:3000/api/verify?app=sonarr"
        authResponseHeaders:
          - "Remote-User"
          - "Remote-Email"
          - "Remote-Groups"
          - "Remote-Admin"

  routers:
    clinch:
      rule: "Host(`clinch.yourdomain.com`)"
      service: clinch
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

    metube:
      rule: "Host(`metube.yourdomain.com`)"
      service: metube
      middlewares:
        - metube-auth
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

    sonarr:
      rule: "Host(`sonarr.yourdomain.com`)"
      service: sonarr
      middlewares:
        - sonarr-auth
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

  services:
    clinch:
      loadBalancer:
        servers:
          - url: "http://clinch:3000"

    metube:
      loadBalancer:
        servers:
          - url: "http://metube:8081"

    sonarr:
      loadBalancer:
        servers:
          - url: "http://sonarr:8989"
```

## How It Works

1. User visits `https://metube.yourdomain.com`
2. Traefik intercepts and applies the `metube-auth` middleware
3. Traefik makes request to `http://clinch:3000/api/verify?app=metube`
4. Clinch checks if user is authenticated and authorized:
   - If **200**: Traefik forwards request to MEtube with user headers
   - If **401/403**: Traefik redirects to Clinch login page
5. User signs into Clinch (with TOTP if enabled)
6. Clinch redirects back to MEtube
7. User can now access MEtube!

## Setup Steps

### 1. Create Applications in Clinch

Via Rails console:

```ruby
# MEtube - No groups = everyone can access
Application.create!(
  name: "MEtube",
  slug: "metube",
  app_type: "trusted_header",
  active: true
)

# Sonarr - Restricted to media-managers group
media_group = Group.find_by(name: "media-managers")
sonarr = Application.create!(
  name: "Sonarr",
  slug: "sonarr",
  app_type: "trusted_header",
  active: true
)
ApplicationGroup.create!(application: sonarr, group: media_group)
```

### 2. Update Traefik Configuration

Add the ForwardAuth middlewares and labels shown above.

### 3. Restart Traefik

```bash
docker-compose restart traefik
```

### 4. Test

Visit https://metube.yourdomain.com - you should be redirected to Clinch login!

## Advanced: Custom Error Pages

```yaml
http:
  middlewares:
    clinch-errors:
      errors:
        status:
          - "401-403"
        service: clinch
        query: "/signin?redirect={url}"

    metube-auth:
      forwardAuth:
        address: "http://clinch:3000/api/verify?app=metube"
        authResponseHeaders:
          - "Remote-User"
          - "Remote-Email"
          - "Remote-Groups"
          - "Remote-Admin"

  routers:
    metube:
      rule: "Host(`metube.yourdomain.com`)"
      service: metube
      middlewares:
        - metube-auth
        - clinch-errors  # Add custom error handling
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
```

## Kubernetes Ingress Example

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind:  Middleware
metadata:
  name: clinch-metube-auth
spec:
  forwardAuth:
    address: http://clinch.clinch-system.svc.cluster.local:3000/api/verify?app=metube
    authResponseHeaders:
      - Remote-User
      - Remote-Email
      - Remote-Groups
      - Remote-Admin

---

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: metube
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: default-clinch-metube-auth@kubernetescrd
spec:
  rules:
  - host: metube.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: metube
            port:
              number: 8081
```

## Troubleshooting

### Users not staying logged in

Ensure Traefik preserves cookies and sets correct headers:

```yaml
http:
  routers:
    clinch:
      middlewares:
        - clinch-headers

  middlewares:
    clinch-headers:
      headers:
        customRequestHeaders:
          X-Forwarded-Host: "clinch.yourdomain.com"
          X-Forwarded-Proto: "https"
```

### Authentication loop

1. Check that `/api/verify` is accessible from Traefik
2. Verify the ForwardAuth middleware address is correct
3. Check Clinch logs for errors

### Check Clinch logs

```bash
docker-compose logs -f clinch
```

You'll see ForwardAuth log messages like:
```
ForwardAuth: User user@example.com granted access to metube
ForwardAuth: Unauthorized - No session cookie
```

### Debug Traefik

Enable access logs in `traefik.yml`:

```yaml
accessLog:
  filePath: "/var/log/traefik/access.log"
  format: json
```

## Comparison: Traefik vs. Caddy

### Traefik
- ✅ Better for Docker/Kubernetes environments
- ✅ Automatic service discovery
- ✅ Rich middleware system
- ❌ More complex configuration

### Caddy
- ✅ Simpler configuration
- ✅ Automatic HTTPS by default
- ✅ Better for static configurations
- ❌ Less dynamic than Traefik

Both work great with Clinch ForwardAuth!
