# Fork Ops

<p align="center">
  <img src="plugins/fork-ops/assets/logo.svg" alt="Fork Ops" width="420">
</p>

Fork Ops helps Codex agents operate long-lived repository forks without
guessing.

It gives each fork a checked-in map of what matters: upstream release channels,
durable upstream tracks, local divergence, safe baselines, and migration state.
The current foundation can assess a fork, propose config, plan and preview a
migration, and execute the first guarded config-creation migration slice.

> [!IMPORTANT]
> Fork Ops is an early work in progress.
>
> **Done:** Codex plugin foundation, `.agents/fork-ops.toml` schema, Python
> core library, CLI, MCP server, capability reporting, live Git diagnostics,
> plugin health diagnostics, workflow migration inventory, read-only migration
> assessment, non-mutating config proposal generation, and migration plan
> generation, migration dry run, and guarded migration execution.
>
> **Planned:** Lemonade onboarding, broader migration edits, source-material
> removal, and later mutation-capable sync, review, and publication workflows.

## Who this is for

Fork Ops fits when a fork needs deliberate, repeatable agent support.

- Your fork follows upstream branches, tags, or release channels.
- Agents should respect checked-in fork policy instead of chat memory.
- Scattered fork guidance needs to become reusable operations and reviewable
  config.

## Why forks need ops

Long-lived forks collect operating knowledge: which upstream refs matter, which
release tracks are safe, what local divergence is intentional, when upstreaming
is allowed, and which checks must pass before a branch moves.

That knowledge often ends up scattered across `AGENTS.md`, repo-local skills,
handoffs, scripts, and chat history. Fork Ops moves the reusable parts into a
plugin while each fork keeps its own authority in checked-in files. The main
config file is `.agents/fork-ops.toml`; it points agents toward the fork-local
docs, policies, and refs that are authoritative for that fork.

## What it can do now

| User need | Current support |
| --- | --- |
| Check plugin readiness | The plugin health report independently checks readiness paths for registration, skill discovery, CLI, MCP, and UI visibility. |
| Map reusable workflow material | Workflow migration inventory scans source roots and groups evidence by catalog target or backlog candidate without editing files. |
| Understand existing fork materials | Migration assessment scans fork-related docs, configs, skills, and agent instructions. |
| Plan a reviewed migration | Migration plan generation combines evidence, config patch, retained source material, blockers, and validation requirements without editing files. |
| Preview a migration plan | Migration dry run reports file edits, config changes, retained materials, blocked steps, and expected verification commands without editing files. |
| Apply a migration plan | Guarded migration execution creates `.agents/fork-ops.toml` from a blocker-free plan, preserves retained source materials, and verifies capability. |
| Draft a starting config | Config proposal generation emits review-required TOML without editing the fork. |
| Validate fork authority | The schema and CLI validate `.agents/fork-ops.toml` for defined capability levels. |
| See supported operations | Capability reporting combines config state with live Git remote and ref checks. |
| Expose fork config to agents | The CLI, MCP server, and Codex skill provide discoverable access paths. |

The current operational target is `track-aware`: enough structure to understand
upstream release tracks and reason about a fork safely. Fork Ops does not yet
perform broad sync mutations, PR publication closeout, arbitrary migration
edits, or source-material removal.

## Try it locally

Fork Ops is managed with `uv` and Python 3.11+.

```bash
git clone https://github.com/nisavid/fork-ops.git
cd fork-ops

export UV_CACHE_DIR=/tmp/fork-ops-uv-cache
uv run --package fork-ops fork-ops plugin health
uv run --package fork-ops fork-ops schema print
```

### Inventory workflow material

Use this when improving the reusable Fork Ops workflow catalog from existing
skills, policies, gates, procedures, or handoff examples.

```bash
uv run --package fork-ops fork-ops workflow inventory --source-root /path/to/source-root
```

### Assess an unconfigured fork

Start here when a fork does not yet have `.agents/fork-ops.toml`.

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
uv run --package fork-ops fork-ops migration dry-run --repo /path/to/fork
uv run --package fork-ops fork-ops migration execute --repo /path/to/fork
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
```

### Inspect a configured fork

Use these commands after a fork has checked in `.agents/fork-ops.toml`.

```bash
uv run --package fork-ops fork-ops config validate --repo /path/to/configured-fork --required-level track-aware
uv run --package fork-ops fork-ops capability report --repo /path/to/configured-fork
```

## Where to go next

- [Operation guide](plugins/fork-ops/docs/operation-guide.md): how agents and
  operators use the current tools.
- [Config schema guide](plugins/fork-ops/docs/config-schema.md): config sections,
  capability levels, and what each part means.
- [Migration guide](plugins/fork-ops/docs/migration.md): assessment, config
  proposals, dry run, execution, and migration boundaries.
- [Plugin README](plugins/fork-ops/README.md): plugin package surfaces and local
  development checks.
- [Foundation specs](specs/fork-ops-foundation/): design rationale, capability
  model, and pressure cases.
- [Project vocabulary](CONTEXT.md): canonical terms such as maintained fork,
  upstream track, migration assessment, and portability hint.

## Roadmap

Next, Fork Ops uses the guarded migration execution workflow for Lemonade
onboarding and tracks post-foundation review hardening.

- [#6](https://github.com/nisavid/fork-ops/issues/6): Onboard Lemonade through the Fork Ops migration flow.
- [#8](https://github.com/nisavid/fork-ops/issues/8): Track post-foundation review hardening follow-ups.

For portability hints and future Repo Ops extraction notes, see the
[config schema guide](plugins/fork-ops/docs/config-schema.md) and
[project vocabulary](CONTEXT.md).
