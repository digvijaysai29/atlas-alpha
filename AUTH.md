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
| Valid token + insufficient permission on `/chat` | `200` — planner drops unauthorized actions; response shows `completed` with no gated `pending_actions` (RBAC is enforced in-graph, not as HTTP 403) |
| Valid token, but not the thread owner (`/approve`, `/threads/{id}`) | `403` (owner-binding) |
| Missing / malformed `Authorization` header | `401` (`WWW-Authenticate: Bearer`) |
| Invalid / expired / wrong-`iss` / wrong-`aud` / bad-signature token | `401` |
| JWKS / identity-provider unavailable (cannot fetch signing keys) | `503` |
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
- Roles are only meaningful via the **policy store** (below) — a token cannot grant a permission the
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

Roles emitted by the IdP must match atlas role names known to the **policy store** (`admin` /
`member` / `guest` by default; see below) — the IdP authenticates *who you are*; the policy store
decides *what a role may do*.

## Authorization / Policy store (M3.4)

Role→permission mappings live behind `governance/policy.py:PolicyStore` (ABC), injected via
`build_graph` into the planner, executor, and KG backends — so authorization can change without a
code deploy. Two backends, selected by `make_policy_store` like the audit/KG factories:

| Backend | When | Notes |
|---|---|---|
| `InMemoryPolicyStore` | `DATABASE_URL` unset (dev/tests) | seeded from the built-in `ROLE_PERMISSIONS` defaults |
| `PostgresPolicyStore` | `DATABASE_URL` set | durable `atlas_role_permissions` table; runtime-editable |

**A fresh Postgres policy table is empty = deny-all (fail-closed).** The factory never auto-seeds on
connect (consistent with the KG); seeding is explicit and idempotent. A startup warning is logged
when the table is empty. Manage it with the CLI (requires `DATABASE_URL`):

```bash
uv run python scripts/manage_policy.py seed       # idempotently load config/default_policies.json
uv run python scripts/manage_policy.py list        # show role -> permissions
uv run python scripts/manage_policy.py grant member tool:send
uv run python scripts/manage_policy.py revoke guest kg:read:personal
uv run python scripts/manage_policy.py export      # dump current policy as JSON
```

`config/default_policies.json` mirrors `ROLE_PERMISSIONS` (a unit test asserts they match, so they
can't drift during the transition). Semantics are unchanged: default-deny, the `"*"` admin wildcard
grants all, and the LLM can never self-grant.

### Wildcard permissions (M3.5)

Permission strings are colon-segmented (`tool:send`, `kg:read:org`, `kg:read:personal`). A role can be
granted a **hierarchical wildcard** so it covers a whole prefix instead of every leaf. Matching
(`governance/rbac.py:permission_satisfied`, the single source of truth shared by the in-memory store,
the Postgres store, the Postgres KG SQL filter, and `can_read`): a **granted** `g` satisfies a
**required** `r` iff

1. `g == "*"` — the global admin wildcard (grants everything), **or**
2. `g == r` — exact match, **or**
3. `g` ends with `":*"` **and** `r` starts with `g`'s prefix (the part before `*`, including the
   trailing colon). So `kg:read:*` satisfies `kg:read:org` and `kg:read:personal`; `tool:*` satisfies
   `tool:send`; `kg:*` satisfies `kg:read:org`.

Wildcards are interpreted **only on the granted side** — a tool's `required_permission` is always a
concrete string, never a pattern. A bare `kg:read` (no trailing `:*`) does **not** cover `kg:read:org`
(no silent hierarchy; only the explicit `:*` suffix expands). Default-deny is unchanged. Grant one via
the CLI:

```bash
uv run python scripts/manage_policy.py grant member kg:read:*   # one grant covers org + personal
```

## Rate limiting (M3.6)

The two graph-invoking endpoints — **`/chat`** and **`/approve`** — are rate limited **per principal**
to cap cost and resist DoS. `/threads/{id}` reads and `/healthz` are not limited.

- **Backend: Upstash** (managed serverless Redis) via the `upstash-ratelimit` SDK
  (`interface/rate_limit.py`). A fixed window of `ATLAS_RATE_LIMIT_REQUESTS` per
  `ATLAS_RATE_LIMIT_WINDOW_SECONDS` (default 60/60). Keys carry a Redis TTL, so there is no in-process
  state to grow.
- **Keying:** identified callers by `u|{org_id}|{user_id}`; the dev header-shim **anonymous** caller
  by `ip|{client_ip}` (so one anon source can't starve all anon callers).
- **Over budget → 429** with a `Retry-After` header, through the standard `ErrorResponse` envelope
  (`error.code == "too_many_requests"`).
- **Layered after authn/authz:** `enforce_rate_limit` depends on the resolved `Principal`, so an
  invalid token still 401s first; limiting never grants access.
- **Fail-open:** if Upstash is unreachable, the request is **allowed** (logged server-side) — a
  rate-limiter outage must not take down the API. Likewise, when the Upstash creds are unset the
  limiter is **disabled** (the dev/CI default; the suite runs unthrottled).

Config (env): `ATLAS_RATE_LIMIT_ENABLED` (default `true`), `ATLAS_RATE_LIMIT_REQUESTS`,
`ATLAS_RATE_LIMIT_WINDOW_SECONDS`, `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` (secret —
never logged). Limiting activates only when enabled **and** both Upstash creds are present.

## Deferred / future work

Scoped out to keep M3.3 a single, green, security-focused milestone. Tracked here so they are not
forgotten:

| Item | Why deferred | Suggested milestone |
|---|---|---|
| **Hierarchical wildcard permissions** (`kg:read:*` ⇒ `kg:read:org`) | usability of the string policy without a new data model | ✅ **done (M3.5)** — see *Wildcard permissions* above |
| **Resource/argument-aware RBAC** (richer `ToolPermission`, "only send to internal domains") | current string permissions are a deliberate placeholder; needs design | M4 |
| **Per-principal rate limiting** | Upstash-backed throttle on `/chat` + `/approve` | ✅ **done (M3.6)** — see *Rate limiting* above |
| **Per-route rate-limit tiers / anti-brute-force IP limiting on 401s** | finer-grained policy beyond a single per-principal budget | M4+ |
| **Policy versioning / history / admin UI / caching layer** | a runtime-editable store exists (M3.4); these are larger follow-ons | M4+ |
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
