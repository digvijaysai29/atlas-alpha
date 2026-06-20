# Authentication & Authorization (atlas)

How atlas authenticates HTTP callers, how to configure a real OIDC provider, and what is
**deliberately deferred** to later milestones. Companion to [`CLAUDE.md`](./CLAUDE.md) and
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

> **Authentication** (who are you?) is resolved at the edge in `src/atlas/interface/security.py`.
> **Authorization** (what may you do?) is unchanged from M2: RBAC `can()` in `governance/rbac.py`,
> enforced deny-early in the planner and re-checked late in the executor, plus the M3.2 resume-time
> **owner-binding** (`verify_thread_owner`). M3.3 only changed *how identity is established*.

## Two modes (chosen at startup)

`create_app` builds an `OidcAuthenticator` when OIDC is fully configured (`settings.oidc_enabled`);
otherwise identity falls back to the dev header shim.

| Mode | When | Identity source |
|---|---|---|
| **OIDC (production)** | `ATLAS_OIDC_ISSUER` **and** `ATLAS_OIDC_AUDIENCE` **and** `ATLAS_OIDC_JWKS_URI` all set | Verified `Authorization: Bearer <JWT>` |
| **Dev header shim** | any of those unset | `X-Atlas-User-Id` / `X-Atlas-Roles` / `X-Atlas-Org` headers (trusted blindly) |

⚠️ **The header shim is TRUSTED-NETWORK / DEV-ONLY.** It trusts request headers, so it is safe only
behind a reverse proxy that authenticates the caller and *sets* those headers (stripping
client-supplied copies). Never expose it directly to the internet. Configure OIDC for any real
deployment.

## Response semantics (OIDC mode)

| Scenario | Response |
|---|---|
| Valid token + sufficient permission | `200` |
| Valid token + insufficient permission | `403` (RBAC) |
| Valid token, but not the thread owner (`/approve`, `/threads/{id}`) | `403` (owner-binding) |
| Missing / malformed `Authorization` header | `401` (`WWW-Authenticate: Bearer`) |
| Invalid / expired / wrong-`iss` / wrong-`aud` / bad-signature token | `401` |
| `/healthz` | `200` (public, no token) |

All errors use the structured `ErrorResponse` envelope (`{"ok": false, "error": {code, message}}`);
token internals are never returned or logged.

## Token validation (what is checked)

In `src/atlas/interface/auth.py` (`OidcAuthenticator`):

- **Signature** against the issuer's JWKS (`PyJWKClient`, keys cached across requests).
- **Algorithm pinned to `RS256`** — `none`/HS256 are rejected, blocking alg-/key-confusion.
- **Required + verified claims:** `exp` (within `oidc_leeway`), `iss` (== `ATLAS_OIDC_ISSUER`), `aud`
  (== `ATLAS_OIDC_AUDIENCE`).
- **Claim → `Principal` mapping:** `sub`→`user_id`, roles claim→`roles` (accepts a JSON array *or* a
  comma/space-delimited string), org claim→`org_id`. The reserved `anonymous` subject is rejected.
- Roles are still only meaningful via `ROLE_PERMISSIONS` — a token cannot grant a permission the
  policy doesn't map to its role.

**`ATLAS_OIDC_LEEWAY` (default 60s):** clock-skew tolerance for `exp`/`nbf`. 60s is the common
default — large enough to absorb normal client/IdP NTP drift, small enough not to meaningfully
extend an expired token.

## Configuration

Environment variables (see [`.env.example`](./.env.example)):

```bash
ATLAS_OIDC_ISSUER=https://<tenant>/           # token `iss`
ATLAS_OIDC_AUDIENCE=atlas-api                  # token `aud` (your API identifier)
ATLAS_OIDC_JWKS_URI=https://<tenant>/.well-known/jwks.json
# Optional claim-name overrides (defaults shown):
ATLAS_OIDC_USER_CLAIM=sub
ATLAS_OIDC_ROLES_CLAIM=roles
ATLAS_OIDC_ORG_CLAIM=org_id
ATLAS_OIDC_LEEWAY=60
```

Use **HTTPS** issuer/JWKS URLs in production. Provider examples:

- **Auth0:** issuer `https://<tenant>.auth0.com/`, JWKS `https://<tenant>.auth0.com/.well-known/jwks.json`,
  audience = the API identifier. Roles typically arrive via a custom namespaced claim (set
  `ATLAS_OIDC_ROLES_CLAIM` to e.g. `https://atlas/roles`) added by an Auth0 Action.
- **Okta:** issuer `https://<tenant>.okta.com/oauth2/<authzServerId>`, JWKS at that issuer's
  `/v1/keys`, audience = the configured audience; map a `groups`/`roles` claim.
- **Clerk:** issuer `https://<subdomain>.clerk.accounts.dev`, JWKS at the issuer's
  `/.well-known/jwks.json`; map roles from a custom JWT template claim.

Roles emitted by the IdP must match atlas role names in `ROLE_PERMISSIONS` (`admin` / `member` /
`guest`) until the policy store lands (see below).

## Deferred / future work (NOT in M3.3)

Scoped out to keep M3.3 a single, green, security-focused milestone. Tracked here so they are not
forgotten:

| Item | Why deferred | Suggested milestone |
|---|---|---|
| **Policy store (replace `ROLE_PERMISSIONS`)** | M3.3 maps IdP roles onto the existing static dict; a DB/external policy store is a separate concern with its own data model + tests | M3.4 |
| **Fine-grained RBAC** (richer `ToolPermission`, resource scoping) | current string permissions are a deliberate placeholder; needs design | M3.4 / M4 |
| **Per-principal rate limiting** | needs a shared counter store (Redis/DB) + policy; orthogonal to identity | M3.4 |
| **Sessions / refresh tokens** | bearer JWTs are stateless; refresh/rotation belongs with a login flow | M4 |
| **User / org provisioning** | JIT/SCIM provisioning + an org model is a backend feature, not edge auth | M4 |
| **Admin UI for roles** | front-end + provisioning dependency | M4+ |
| **OAuth *login* flows** (Authlib) | atlas validates bearer tokens; it does not *initiate* login. Add Authlib only if a first-party login is needed | M4+ |
| **Org-level thread delegation / role-based thread access** | M3.2 binding is strict creator-only (`verify_thread_owner` TODO) | M3.4 / M4 |

## Testing

`tests/test_interface_auth.py` is fully hermetic: it generates an in-test RSA keypair, signs JWTs
with PyJWT, and injects an `OidcAuthenticator` whose signing-key lookup returns the local public key
— no network, no real provider. It covers happy-path claim mapping, every `401` rejection
(missing/expired/wrong-aud/wrong-iss/bad-sig/`alg=none`/HS256-forgery/reserved-subject), roles
list-vs-string parsing, org-in-owner-binding, and that the header shim is ignored under OIDC.
