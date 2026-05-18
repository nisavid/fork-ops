# Fork Ops

<p align="center">
  <img src="plugins/fork-ops/assets/logo.svg" alt="Fork Ops" width="420">
</p>

Fork Ops helps Codex agents operate long-lived repository forks without
guessing.

It gives each fork a checked-in map of what matters: upstream release channels,
durable upstream tracks, local divergence, safe baselines, and migration state.
The current foundation is read-oriented: it can assess a fork and propose
config, but it does not mutate the fork.

> [!IMPORTANT]
> Fork Ops is an early work in progress.
>
> **Done:** Codex plugin foundation, `.agents/fork-ops.toml` schema, Python
> core library, CLI, MCP server, capability reporting, live Git diagnostics,
> read-only migration assessment, and non-mutating config proposal generation.
>
> **Planned:** migration plan generation, migration dry run, guarded migration
> execution, Lemonade onboarding, and later mutation-capable sync, review, and
> publication workflows.

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
| Understand existing fork materials | Migration assessment scans fork-related docs, configs, skills, and agent instructions. |
| Draft a starting config | Config proposal generation emits review-required TOML without editing the fork. |
| Validate fork authority | The schema and CLI validate `.agents/fork-ops.toml` for defined capability levels. |
| See supported operations | Capability reporting combines config state with live Git remote and ref checks. |
| Expose fork config to agents | The CLI, MCP server, and Codex skill provide discoverable access paths. |

The current operational target is `track-aware`: enough structure to understand
upstream release tracks and reason about a fork safely. Fork Ops does not yet
perform broad sync mutations, PR publication closeout, or migration execution.

## Try it locally

Fork Ops is managed with `uv` and Python 3.11+.

```bash
git clone https://github.com/nisavid/fork-ops.git
cd fork-ops

export UV_CACHE_DIR=/tmp/fork-ops-uv-cache
uv run --package fork-ops fork-ops schema print
```

### Assess an unconfigured fork

Start here when a fork does not yet have `.agents/fork-ops.toml`.

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
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
  proposals, and the planned migration lifecycle.
- [Plugin README](plugins/fork-ops/README.md): plugin package surfaces and local
  development checks.
- [Foundation specs](specs/fork-ops-foundation/): design rationale, capability
  model, and pressure cases.
- [Project vocabulary](CONTEXT.md): canonical terms such as maintained fork,
  upstream track, migration assessment, and portability hint.

## Roadmap

Next, Fork Ops turns assessment into a reviewed migration workflow: plan, dry
run, guarded execution, then Lemonade onboarding.

- [#3](https://github.com/nisavid/fork-ops/issues/3): Implement migration plan generation.
- [#4](https://github.com/nisavid/fork-ops/issues/4): Implement migration dry run.
- [#5](https://github.com/nisavid/fork-ops/issues/5): Implement guarded migration execution.
- [#6](https://github.com/nisavid/fork-ops/issues/6): Onboard Lemonade through the Fork Ops migration flow.
- [#8](https://github.com/nisavid/fork-ops/issues/8): Track post-foundation review hardening follow-ups.

For portability hints and future Repo Ops extraction notes, see the
[config schema guide](plugins/fork-ops/docs/config-schema.md) and
[project vocabulary](CONTEXT.md).
