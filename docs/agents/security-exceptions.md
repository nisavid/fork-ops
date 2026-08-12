# Security Exceptions

This guide is generated from the package-owned canonical contract. Edit
`plugins/fork-ops/src/fork_ops/security-exception-contract-1.0.json`, then run:

```bash
uv run --package fork-ops python scripts/security_exception_projections.py
uv run --package fork-ops python scripts/security_exception_projections.py --check
```

Contract version: `1.0`

Contract SHA-256: `b060b477b1fdcc9155a34939e607a7794ccb82f5d544816cfb95a3f6392f34f4`

## Purpose and boundary

Contract 1.0 records exception inventory, decisions, lineage, and lifecycle.
It is pure governance evidence. It has no gate, merge, repository-control,
assurance, baseline, release, product, or dogfood effect, and it never clears
the underlying failure. Future effects require an unsupported contract 2.0.

The public ledger is `docs/agents/security-exceptions.toml`. It contains flat
`[[exceptions]]` records and starts empty. Public records contain bounded,
structured, confidentiality-safe metadata and credential-free HTTPS references
using the contract's closed per-host public resource paths only.
Private proposals, commands, and evidence remain in a private advisory adapter;
the validator accepts only its versioned sanitized projection and fails the
whole ledger when that projection is unavailable.

An Unscanned Equipment Exception is separate equipment governance. It is not a
Security Exception and cannot affect Security Posture without a separate record
under this contract.

## Closed kind and subject matrix

| Kind | Permitted subjects |
| --- | --- |
| `finding_exception` | `dependency_advisory`, `first_party_finding` |
| `control_bypass` | `repository_control`, `assurance_gate` |
| `control_unavailability` | `repository_control`, `assurance_gate` |
| `policy_deviation` | `security_invariant`, `repository_control`, `package_source`, `assurance_gate` |

## Total effects

Always true: `inventory_recorded`, `decision_recorded`, `lifecycle_recorded`, `underlying_failure_remains_blocking`.

Always false: `security_posture_green`, `admission_or_merge_authorized`, `repository_control_relaxed_disabled_or_mutated`, `assurance_validated`, `baseline_or_release_eligible`, `product_or_dogfood_authorized`, `underlying_failure_cleared`.

## Authority and lineage

The sole authority is GitHub login `nisavid`,
database ID `576874`, node ID
`MDQ6VXNlcjU3Njg3NA==`. Login and immutable IDs
must all match the structural observation. Contract 1.0 refuses an authority
mismatch or an observation older than 15 minutes; explicit migration
requires a future contract. The pure validator
cannot authenticate a caller mapping: it returns only an inventory with
`authority_status = "structural_unverified"`, and its authenticated-inventory
predicate remains false until a live verification adapter exists.

Lineage uses a coordinator-issued random UUIDv4 and an append-only index across
current and terminal states. Every lineage starts in `approved`; later entries
must follow a closed state-machine action and cannot be future-dated. The
`last_approval_or_renewal` anchor remains the most recent `approved` or
`renewed` event. The initial record gets a fresh globally history-unique
exception ID. Each renewal rotates to another fresh ID; every other transition
retains the current ID, and the current record ID equals the lineage head.
Dependency identity includes lineage, normalized package,
locked version, exact scopes, an exact nonempty Python 3.11-3.14 subset, and
Linux. Alias and evidence revisions are separate. The current record must equal
the lineage head and current revisions exactly. Branch,
overlap, split, merge, cross-visibility reuse, unlinked reuse, and anchor reset
are rejected. Evidence, proposal, event, result, and record digests are
recomputed from domain-separated canonical projections. Each lineage head binds
the record's canonical result digest so the head identity changes with any
security-relevant record content. Subject identity is derived rather than
caller-selected. Dependency identity remains package, locked version, exact
scopes, exact Python subset, and Linux. Other identities bind the exact ASCII
subject key under the closed subject kind:

- `first_party_finding`: `first_party_finding:{subject_key}`
- `repository_control`: `repository_control:{subject_key}`
- `assurance_gate`: `assurance_gate:{subject_key}`
- `security_invariant`: `security_invariant:{subject_key}`
- `package_source`: `package_source:{subject_key}`

Aliases do not participate in identity, so alias revisions remain in the same
lineage. Lineage issuance accepts only the closed canonical identity grammar,
refuses current or historical exception-ID reuse, and requires
`issued_at <= evaluated_at`. Collection and persistence are adapter
responsibilities; this implementation validates projections only.

## Public request commands

Commands use the exact ASCII whitespace-separated tokens below, lowercase
literals, and no extra text. They are requests only. Transition projections
bind immutable authority IDs, the exact request, producer and persistence
receipts, a canonical result digest, and monotonic timestamps, but remain
`structural_unverified`. Contract 1.0 has no authenticated command or
persistence adapter, so no transition projection takes authoritative effect.
Transition persistence evidence must be less than 15 minutes old at
evaluation. Public commands govern public records only, and edited comments are
rejected. Every transition binds a structural current whole-ledger inventory.
Approval requires a globally history-unique exception ID; renewal requires a
fresh successor ID; other transitions retain the current ID.

| Action | Exact grammar |
| --- | --- |
| `approve` | `/security-exception approve 1.0 {exception_id} {proposal_sha256} none` |
| `renew` | `/security-exception renew 1.0 {successor_exception_id} {successor_proposal_sha256} {predecessor_effective_event_sha256}` |
| `revoke` | `/security-exception revoke 1.0 {exception_id} {current_proposal_sha256} {predecessor_effective_event_sha256}` |
| `withdraw-invalid` | `/security-exception withdraw-invalid 1.0 {exception_id} {pending_transition_sha256} {predecessor_effective_event_sha256} {malformed_comment_node_id} {malformed_raw_sha256}` |

A malformed command with the exact revoke prefix can only request a
`revocation_pending` transition. `withdraw-invalid` binds that pending
transition, predecessor effective-event digest, malformed comment node ID, and
raw comment digest. It requires the current head, clears only the pending
transition, never restores a snapshot, and forces fresh recomputation.

## Provider and response clocks

Provider projections require 2 complete, semantic-identical
structural passes with one terminal manifest for every required source.
Request, semantic, response, receipt, and aggregate digests are recomputed;
producer provenance remains `unverified_projection`. The strict window is
`observation_completed_at <= evaluated_at < valid_until`.
Validity is at most 15 minutes and ends earlier when the provider or
authentication bound does. Projected provider time is monotonic with at most
120 seconds of skew. Repository, governance issue, and account identities are
pinned.

A positive zero response-clock inventory is structurally complete only when
every required source is present in one epoch, pagination is terminal,
reconciliation is complete, and entries are empty. It cannot become an
authoritative positive-zero claim until a live authenticated provider adapter
exists. The earliest authenticated source publication or private validation
would start the clock. If source time is missing, retain the first-observed upper
bound, but triage and disposition remain `uncertain` and do not prove an SLA.
The highest credible severity only tightens deadlines.

- Critical: triage in 24 elapsed hours; disposition in 72 elapsed hours.
- High: triage in 2 Monday-Friday UTC weekdays with no holiday calendar;
  disposition in 14 calendar days.
- Medium: disposition in 30 calendar days.
- Low: disposition in 90 calendar days.

## Record lifecycle

Review is due within 30 days; expiry is due within 90 days.
Control bypass and control unavailability records expire within 7 days.
Critical and high records cannot pass their response disposition cap.

`last_approval_or_renewal < review_after <= min(last_approval_or_renewal+30d, expires_at)`

`review_after <= expires_at <= absolute_cap`

Anchors never reset. Equality at review or expiry is inactive. Revoked and
resolved states are terminal. Lifecycle projections remain
`structural_unverified` and cannot report `active = true` without an
authenticated authority adapter. Lifecycle validity records state only and
never changes the contract's total effects.
