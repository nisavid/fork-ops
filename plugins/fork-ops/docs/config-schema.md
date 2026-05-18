# Fork Ops Config Schema

Fork Ops Config lives at `.agents/fork-ops.toml` in a Maintained Fork. The machine-readable schema is `schema/fork-ops.schema.json`.

The schema defines the parsed TOML shape. Unknown keys are allowed so a fork can carry local extensions while Fork Ops grows. Tools should still validate all known fields and report unknown extension behavior as inferred when it affects an operation.

The packaged runtime schema and the documented schema are expected to match the
canonical runtime serialization. Check both artifacts with:

```bash
# From the repository root:
uv run --package fork-ops fork-ops schema check --plugin-root plugins/fork-ops
```

## Required Foundation Sections

`schema_version` identifies the config schema family. The foundation version is `0.1`.

`[repository]` is a Descriptive Fork Fact block. It names the hosted repository and its default branch. Fields such as `protected_branches` should be populated from verified repo policy, not inferred from a default branch name.

`[[fork_remotes]]` lists fork-owned remotes and push targets.

`[[upstreams]]` lists upstream projects and remotes. Upstream remotes should not be push targets unless fork-local authority explicitly says otherwise.

`[authority]` records source order, upstream canon rules, inference labeling, required context paths, pre-change requirements, durable discovery destinations, and escalation policy.

`[change_targets]` records the default target for local changes and the policy for upstream contribution exceptions.

## Track-aware Sections

`[[release_channels]]` defines live upstream selectors such as `stable`, `preview`, or `latest-prerelease`. Release channels are not durable refs and are resolved live by operations that need fresh upstream evidence.

`[[upstream_tracks]]` defines durable ref roles consumed or maintained by the fork. An Upstream Track can be sourced from a release channel, upstream ref, or manual policy. Durable baseline state belongs here. Track update policies should capture local branch usage, non-fast-forward handling, and evidence checks when the fork already has such rules.

`[[local_surfaces]]` points agents to fork-local authority, docs, skills, scripts, hooks, and migration inputs. Use `domains` for the full non-normative domain classification and `domain` only as a primary routing hint. Use `portability_hints` and `repo_ops_candidate_scope` when only part of a surface is a plausible future Repo Ops migration candidate.

## Sync-ready Sections

`[sync_policy]` defines the Default Sync Baseline, default sync ref, fork sync start ref, commit identity requirements, merge methods, track update methods, ancestry checks, and history rewrite boundaries. Migration proposals map detected `origin/upstream-*` default baseline refs to matching `upstream_tracks` entries instead of relying on a single hard-coded baseline name.

`[divergence_policy]` records local contracts, preservation checks, and the uncertainty destination for ambiguous sync work.

These sections are represented in the foundation schema so existing fork policy can be modeled. Broad sync mutation workflows are not enabled by the foundation implementation.

## Later Sections

`[review_policy]`, `[publication_policy]`, and `[local_gates]` describe review, PR, merge, cleanup, and verification behavior. These domains are strong candidates for future Repo Ops extraction when generic Repo Ops exists.

`[portability]` stores non-normative Portability Hints. These hints do not block Fork Ops behavior and do not decide the future Repo Ops boundary.
