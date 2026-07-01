# Custom Connectors — adding a tool with a JSON schema (M4.8a)

A **custom connector** is an outbound tool (e.g. "post a Slack message", "create a calendar event")
that the agent can propose. Instead of writing Python for each one, you drop a small **JSON schema**
into `src/atlas/tool_schemas/` and the **adapter engine** turns it into a real tool — with all the
security controls (approval gate, RBAC, audit, SSRF-safe egress) applied automatically.

> You write *what* the tool calls. The engine enforces *how* it is allowed to run.

## TL;DR

1. Add a `*.json` file under `src/atlas/tool_schemas/`.
2. Add the endpoint host to the egress allowlist (`ATLAS_ADAPTER_EGRESS_ALLOWLIST`).
3. Turn the engine on (`ATLAS_ADAPTER_ENGINE_ENABLED=true`).
4. Open a PR — schema files are **code** (CODEOWNERS-reviewed).

No Python, no redeploy logic, no hand-rolled HTTP.

## Example schema

This is the bundled `slack_post_as_user.json`:

```json
{
  "name": "slack_post_as_user",
  "description": "Post a Slack message as the authenticated user. Irreversible external action.",
  "schema_version": "1",
  "risk_tier": "send",
  "required_permission": "tool:slack:post_as_user",
  "provider": "slack",
  "required_scopes": ["chat:write"],
  "endpoint": "https://slack.com/api/chat.postMessage",
  "method": "POST",
  "args": [
    { "name": "channel", "type": "str", "required": true, "min_length": 1 },
    { "name": "text", "type": "str", "required": true, "min_length": 1, "max_length": 40000 }
  ],
  "payload": {
    "channel": { "arg": "channel" },
    "text": { "arg": "text" },
    "unfurl_links": { "value": false },
    "unfurl_media": { "value": false }
  },
  "response": {
    "ts": { "path": "ts" },
    "channel": { "path": "channel" },
    "provider": { "value": "slack_user" }
  },
  "ok_field": "ok"
}
```

## Field reference

| Field | Meaning |
|---|---|
| `name` | Tool name the planner calls. Unique. |
| `description` | Shown to the planner; explain side effects plainly. |
| `schema_version` | Bump when you change the schema (logged in the audit trail). |
| `risk_tier` | `read` / `write` / `send` / `delete` / `pay`. Defaults to `send`. A schema **cannot** declare an auto-run `read` (that needs a code change), so every connector is human-approval-gated. |
| `required_permission` | RBAC permission a caller must hold (e.g. `tool:slack:post_as_user`). **Required** for any non-`read` tool. |
| `provider` | OAuth provider whose per-user token is used (`google`, `slack`). |
| `required_scopes` | OAuth scopes the token must carry, else the call fails closed. |
| `endpoint` | Full `https://` URL. Its **host must be on the egress allowlist** and its host+port+path become the only route this tool may hit. |
| `args[]` | Inputs the planner fills: `name`, `type` (`str`/`int`/`bool`), `required`, optional `min_length`/`max_length`. Names must be simple lowercase identifiers. |
| `payload{}` | Builds the outbound JSON body. Each field is either `{ "arg": "<argname>" }` (copy an input) or `{ "value": <constant> }`. No code/templating. |
| `response{}` | Shapes the result. Each field is `{ "path": "<key>" }` (read a top-level response key) or `{ "value": <constant> }`. |
| `ok_field` | If set, the provider response must have a truthy value at this key, else the call is treated as an error. |

## What the engine gives you for free

Every schema-built tool runs through the **unchanged** execution gate:

- **Human approval** — anything that isn't a known-safe `read` is paused for approval before it runs.
- **RBAC** — the caller must hold `required_permission` (default-deny).
- **Per-user OAuth** — the access token is resolved server-side from the caller's identity (never from
  arguments, never logged).
- **SSRF-safe egress** — the URL is parsed once; it must be `https`, on the host allowlist, and match
  the exact route; the host is resolved and the IP is rejected if it's internal/private/cloud-metadata;
  the connection is pinned to that validated IP; redirects are never followed.
- **Idempotency + tamper-evident audit** — re-runs are de-duplicated, and every action is recorded with
  its schema id/version, destination host, provider, and correlation id (no secrets).

## Adding one — step by step

1. **Write the schema** under `src/atlas/tool_schemas/<name>.json` (copy the example above).
2. **Allowlist the host:** add the endpoint host to `ATLAS_ADAPTER_EGRESS_ALLOWLIST` (comma-separated).
3. **Connect the provider:** the caller must have linked the `provider` via OAuth (see
   [`AUTH.md`](./AUTH.md)) with the `required_scopes`.
4. **Enable the engine:** set `ATLAS_ADAPTER_ENGINE_ENABLED=true` (see [`.env.example`](../../.env.example)).
5. **Test it:** `uv run pytest -k adapter` and the eval gate (`uv run python evals/run_gate.py`).
6. **Open a PR.** `tool_schemas/**` is CODEOWNERS-gated — schemas are reviewed like code.

## Enterprise features (optional)

- **Forward-proxy egress** — set `ATLAS_ADAPTER_EGRESS_PROXY_URL` (and optional static proxy auth) when
  corporate policy requires a central gateway. Direct IP-pinned egress remains the default. See
  [`RUNBOOK.md`](./RUNBOOK.md#adapter-engine--egress-proxy-m48a--m48b).

## Limits today (M4.8a)

- `POST` + JSON bodies only; payload/response mapping is top-level field copy or constants (no nested
  JSONPath yet).
- The schema directory is a trusted, in-repo build artifact — it is **never** loaded from user input,
  the network, or the model.
- New OAuth providers (beyond Google/Slack) still need a one-time client/Vault wiring in code.

See [`docs/plans/M4.8a_PLAN.md`](../plans/M4.8a_PLAN.md) for the design and the upcoming phases.
