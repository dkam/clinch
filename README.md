# README

Clinch is a lightweight, self-hosted identity & SSO portal for home-labs.
It gives you one place to manage people and lets any web app authenticate against it without keeping its own user table.

Core behaviour

First-run wizard → initial user becomes admin.

Admin dashboard → create / disable / delete users.

SMTP integration → send:
– invitation links (one-time token)
– password-reset links
– 2FA back-up codes

Optional per-user TOTP (QR code + scratch codes).

Auth mechanisms exposed to client apps

OpenID Connect (OIDC)
Standard OAuth2/OIDC provider endpoints (/.well-known/openid-configuration, /authorize, /token, /userinfo).
Client apps (Audiobookshelf, Kavita, Grafana, …) redirect to Clinch for login; Clinch returns ID- and access-tokens.

Trusted-Header SSO (a.k.a. ForwardAuth)
Reverse-proxy (Caddy, Traefik, Nginx) sends every request to clinch:9000/api/verify.

200 → proxy injects headers Remote-User, Remote-Groups, Remote-Email and forwards to the app.
401/403 → proxy redirects browser to Clinch login page; after login user is bounced back to the original URL.
Apps that speak OIDC use method 1; apps that only need “who is it?” headers behind a proxy use method 2.

* Configuration
ENV files

* Database creation
SQLite only

* How to run the test suite

* Services (job queues, cache servers, search engines, etc.)

* Deployment instructions
Docker

