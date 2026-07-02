# Tool Schemas — layout, naming, and discovery

Trusted JSON **tool schemas** are the adapter engine's build artifacts: each file describes one
outbound integration tool (endpoint, args, RBAC permission, OAuth provider) and is compiled at
startup into a registry-ready `BaseTool`. Schemas are **never** loaded from user input, the network,
or the model.

For how to author a schema and what each field means, see [`CUSTOM_CONNECTORS.md`](./CUSTOM_CONNECTORS.md).
This guide covers **where files live**, **how they are named**, and **how the loader finds them**.

## Directory layout

```
src/atlas/tool_schemas/
├── slack/
│   ├── slack_post_as_user.json
│   └── slack_delete_message.json
├── google/          # future Gmail / Calendar schema-driven tools
│   └── (empty until added)
└── _internal/     # optional — non-OAuth or cross-provider schemas
```

### Subfolder rules

| Subfolder | Use when |
|---|---|
| **`slack/`** | `provider` is `"slack"` (`OAuthProvider.SLACK`) |
| **`google/`** | `provider` is `"google"` (`OAuthProvider.GOOGLE`) — Gmail, Calendar, etc. |
| **`_internal/`** | No OAuth provider, shared utilities, or experimental schemas not tied to one integration |

The subfolder name should match the schema's `provider` field whenever that field is set. This
keeps discovery predictable for humans and agents: *"add a Slack tool → look in `slack/`."*

Do **not** place loose `*.json` files at the root of `tool_schemas/` — always use a subfolder.

## File naming

- **Filename** = the tool's `name` field + `.json` (e.g. `slack_post_as_user.json`).
- **`name` must be unique** across the entire tree (the registry keys tools by `name`, not path).
- Use lowercase identifiers with underscores, matching existing hand-written tool names.
- Bump `schema_version` inside the JSON when you change a schema (audit trail).

Example path for a new Slack delete variant:

```
src/atlas/tool_schemas/slack/slack_delete_message.json
```

## How schemas are loaded

At startup (when `ATLAS_ADAPTER_ENGINE_ENABLED=true`), `load_schema_dir()` in
`adapter_engine.py`:

1. Resolves the directory — packaged `src/atlas/tool_schemas/` by default, or
   `ATLAS_ADAPTER_SCHEMA_DIR` if set.
2. Recursively globs `**/*.json` under that directory (sorted for deterministic order).
3. Validates each file with Pydantic (`ToolSchema`, `extra="forbid"`).
4. Runs security checks (risk tier, `required_permission`, egress host allowlist).
5. Registers built tools, replacing any hand-written twin with the same `name`.

Fail-closed: if the directory is missing or contains no `*.json` files, startup raises
`ToolSchemaError` — the engine cannot silently run with zero schemas.

Relevant code:

- `iter_schema_paths()` — recursive discovery
- `load_schema()` / `load_schema_dir()` — load + validate
- `AdapterEngine.build_tools_from_dir()` — compile to `BaseTool`
- `orchestration/graph.py` → `_apply_adapter_engine()` — wires into the graph

## Adding a new schema (checklist)

1. Pick the subfolder from the `provider` field (`slack/`, `google/`, or `_internal/`).
2. Create `<tool_name>.json` (filename = `name` field).
3. Follow the field reference in [`CUSTOM_CONNECTORS.md`](./CUSTOM_CONNECTORS.md).
4. Add the endpoint host to `ATLAS_ADAPTER_EGRESS_ALLOWLIST`.
5. Run `uv run pytest -k adapter` and `uv run pytest tests/test_tools.py`.
6. Open a PR — `tool_schemas/**` is CODEOWNERS-gated (reviewed like code).

## Discovery tips for agents

- **List bundled schemas:** `find src/atlas/tool_schemas -name '*.json'`
- **Find loader code:** `grep -r load_schema_dir src/`
- **See registered tool names:** inspect `name` in each JSON, or run adapter tests
  (`test_load_schema_dir_includes_both_bundled_schemas`).
- **Hand-written vs schema-driven:** some tools (e.g. `slack_post_as_user`) have both; when the
  adapter engine is enabled, the schema-built `_SchemaTool` replaces the hand-written class.

## Related docs

- [`CUSTOM_CONNECTORS.md`](./CUSTOM_CONNECTORS.md) — authoring schemas, field reference, examples
- [`AUTH.md`](./AUTH.md) — OAuth providers and permissions
- [`RUNBOOK.md`](./RUNBOOK.md) — egress proxy and engine ops
- [`docs/CODEMAPS/backend.md`](../CODEMAPS/backend.md) — adapter engine in the backend map
