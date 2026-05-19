# Migration Pressure Cases

Status: Draft

## Lemonade Upstream Refs

Source materials:

- `.agents/skills/working-with-upstream-refs/SKILL.md`
- `docs/agents/fork-stewardship.md`

This pressure case exercises the first migration target because it contains fork-specific upstream ref policy, stable-release selection, default sync baseline policy, forbidden sync flows, and closeout evidence.

Expected migration assessment signals:

- `upstream/main`, `upstream-main`, `origin/upstream-stable`, and `upstream-stable` appear as candidate ref roles for `upstream_tracks`.
- GitHub Releases appears as the release-channel source for the stable channel.
- `origin/upstream-stable` appears as a candidate Default Sync Baseline.
- Disabled upstream push appears as upstream remote policy.
- `merge-base --is-ancestor` appears as an ancestry check.
- Force-push avoidance appears as a forbidden history rewrite policy.

The assessment should not mutate Lemonade. It should preserve these facts as evidence for the migration plan.

Expected migration plan sections:

- evidence for the upstream-ref source material and extracted facts
- migration map entries with source material dispositions and target surfaces
- proposed migration review artifact entries for durable decisions outside config
- proposed config patch for `.agents/fork-ops.toml`
- retained source material with removal deferred outside this migration slice
- required review for the config proposal and retained source material
- validation requirements for config validation and capability reporting
