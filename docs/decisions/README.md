# Architecture Decision Records

Short, dated records of non-obvious technical decisions in Clinch. They live in the
repo (rather than a wiki) so they version with the code and travel with a checkout.

Each file is one decision. Newest decisions get the next number.

| # | Decision |
|---|----------|
| [0001](0001-opaque-vs-jwt-access-tokens.md) | Access tokens are opaque (not JWT); resource servers use introspection |
| [0002](0002-device-authorization-grant.md) | CLI/agent auth uses the OAuth 2.0 Device Authorization Grant (RFC 8628) |
| [0003](0003-dynamic-client-registration.md) | Dynamic Client Registration (RFC 7591), runtime-gated + default-deny |
| [0004](0004-resource-indicators.md) | Resource Indicators (RFC 8707) bind token audience; pass-through validation |
| [0005](0005-introspection-authorization.md) | Introspection restricted to authorized callers + claim scope-gating |
| [0006](0006-no-client-credentials-grant.md) | No `client_credentials` grant; machine access is user-delegated via device flow |
| [0007](0007-jwt-access-tokens.md) | Per-client access token format; RFC 9068 JWTs as an opt-in for high-throughput APIs |
