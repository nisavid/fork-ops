# Migration Pressure Cases

Status: Draft

## Lemonade Upstream Refs

Source materials:

- `/home/nisavid/src/nisavid/lemonade/.agents/skills/working-with-upstream-refs/SKILL.md`
- `/home/nisavid/src/nisavid/lemonade/docs/agents/fork-stewardship.md`

This pressure case exercises the first migration target because it contains fork-specific upstream ref policy, stable-release selection, default sync baseline policy, forbidden sync flows, and closeout evidence.

Expected Migration Assessment signals:

- `upstream/main`, `upstream-main`, `origin/upstream-stable`, and `upstream-stable` appear as candidate ref roles for `upstream_tracks`.
- GitHub Releases appears as the release-channel source for the stable channel.
- `origin/upstream-stable` appears as a candidate Default Sync Baseline.
- Disabled upstream push appears as upstream remote policy.
- `merge-base --is-ancestor` appears as an ancestry check.
- Force-push avoidance appears as a forbidden history rewrite policy.

The assessment should not mutate Lemonade. It should preserve these facts as evidence for a later Migration Plan.
