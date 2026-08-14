# Merge admission for fresh Security Posture

## Status and scope

This record resolves the read-only mechanism research in
[#69](https://github.com/nisavid/fork-ops/issues/69). GitHub's documented
surfaces support taking one composite candidate to disposable proof: a
dedicated admission GitHub App would be the only actor able to update the
default branch, a separate Security Posture producer App would publish an
exact-candidate result, and an independently administered witness would bind
the fresh observation. The candidate is designed to promote the checked pull
request head by an exact, non-force fast-forward only after reevaluating every
admission condition. #69 establishes documented support for researching this
shape; it does not establish operational viability or satisfaction of the
admission contract.

This is a design decision, not a deployed control. It creates no GitHub App,
installation, credential, check, ruleset, repository, bypass, or live canary.
It does not change the current merge paths or grant Security Exception 1.0 any
gate, merge, assurance, repository-control, release, product, or dogfood
effect. Provisioning belongs to
[#70](https://github.com/nisavid/fork-ops/issues/70), and disposable live proof
belongs to [#71](https://github.com/nisavid/fork-ops/issues/71).

## Decision

Take a dedicated-admission-App and `restrict updates` composite to #70 and #71
for proof. Production use is not selected by #69 and remains blocked until the
proof and governance prerequisites in this record are satisfied:

1. A **Security Posture producer App** would own the selected
   `Security Posture` result. Its exact result type and write permission remain
   a #71 proof question. It cannot write repository contents, administer
   rulesets, bypass admission, or update the default branch.
2. A **merge admission App** would own the admission decision and default-branch
   update. It has repository-contents write permission and only the read
   permissions needed for pull requests, checks, rules, and witnessed proof.
   It cannot write Security Posture results or administer rulesets.
3. A dedicated active ruleset targets the default branch, contains only
   `restrict updates`, and names the admission App as its sole `always` bypass
   actor. Its `update_allows_fetch_and_merge` parameter is false. Do not use
   `exempt`, which would skip rule execution and omit the bypass audit entry.
4. The existing repository ruleset remains a separate, active layer. The
   admission App does not bypass it. Its required pull request review,
   Validation, code scanning, code quality, Copilot review, deletion, and
   non-fast-forward protections therefore remain cumulative constraints.
5. Put the required `Security Posture` check in its own active ruleset, pinned
   to the producer App as the expected source. Neither App bypasses this rule
   under the Security Exception 1.0 design.

GitHub documents that rulesets layer rather than choosing one winning rule,
that `restrict updates` allows only bypass actors to update the target, and
that a GitHub App can be selected as a bypass actor or required-check source.
See [About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
and [Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

The selected path changes the admitted Git shape. The final candidate is the
pull request head itself, so admission is an exact fast-forward promotion. A
GitHub-generated merge commit, squash merge, or rebase merge creates a
different commit and is not an admission path under this contract.
If the default branch advances, `B` changes and the attempt is invalid. The
pull request must be updated so its new `H` descends from the new base, after
which reviews, Validation, Security Posture, and the witness are reevaluated.

## Required admission contract

Let:

- `R` be the immutable repository ID and node ID;
- `B` be the exact default-branch head observed for this admission attempt;
- `H` be the exact open pull request head SHA;
- `C` be the future digest of the complete canonical admission-control state
  produced by the versioned schema that Issue #71 must implement and prove;
- `G_control` be the independently witnessed monotonic generation for events
  that may change any input to `C`;
- `E_control` be the independently witnessed append-only event high-water
  commitment at `G_control`;
- `G_result` be the independently witnessed monotonic generation for Security
  Posture result events that may change the selected result for `H`;
- `E_result` be the independently witnessed append-only result-event
  high-water commitment at `G_result`;
- `T_observed` be the independently witnessed time assigned to the exact
  authoritative Security Posture result;
- `T_decided` be the independently witnessed time assigned to the admission
  App's signed authorization decision immediately before the proposed ref
  update;
- `T_admitted` be the independently witnessed time assigned when the
  post-update read verifies that the default ref is exactly `H`; and
- `T_valid_until` be the witnessed expiry bound.

Issue #69 does not define an executable control-state schema. It records the
minimum closed-schema requirements that Issue #71 must implement, version,
test, and prove before any `C` bytes, digest, or eligibility claim exists:

```text
[control_state_schema_requirements]
schema_authority = Issue #71
current_schema_status = requirements only
required_schema = closed and versioned; missing required fields and unknown fields are rejected
required_encoding = canonical UTF-8 JSON; no BOM, trailing whitespace, or trailing LF
required_object_key_order = lexicographic by UTF-8 byte sequence
required_array_order = schema-defined, significant, and preserved
required_set_like_array_order = sorted by each schema-declared stable key
required_absent_null_semantics = absent != null; null is allowed only where declared
required_number_domain = base-10 integers only; floats forbidden
required_digest = lowercase SHA-256 hexadecimal over the exact encoded bytes
ruleset_response_snapshot_digest != C
canonical_C_bytes = unavailable from this record
C_digest = unavailable from this record
eligibility = blocked until Issue #71 implements, versions, and proves the schema
repository_id
repository_node_id
repository_full_name
repository_owner_login
repository_owner_type
repository_owner_database_id
repository_owner_node_id
repository_visibility
default_branch_name
default_branch_ref
default_branch_ref_format = refs/heads/{default_branch_name}
default_branch_head = B
pull_request_id
pull_request_node_id
pull_request_number
pull_request_state
pull_request_base_repository_id
pull_request_base_repository_node_id
pull_request_base_repository_name
pull_request_base_ref
pull_request_base_ref_format = refs/heads/{base.ref}
pull_request_base_sha = B
pull_request_head_repository_id
pull_request_head_repository_node_id
pull_request_head_repository_name
pull_request_head_ref
pull_request_head_ref_format = refs/heads/{head.ref}
pull_request_head_sha = H
ruleset_id
ruleset_node_id
ruleset_source
ruleset_source_type
ruleset_enforcement
ruleset_rules
ruleset_bypass_actors
ruleset_target_type
ruleset_target_include
ruleset_target_exclude
repository_merge_settings
repository_actions_settings
repository_branch_settings
repository_tag_settings
repository_deletion_settings
repository_force_update_settings
producer_identity
evaluator_identity
admission_app_identity
installation_identity
permission_set
immutable_versions
```

Issue #71's versioned schema must define the complete key set and types, every
array's ordering or stable sort key, the fields where JSON `null` is valid, and
test vectors that reproduce the exact bytes and digest. An unavailable
required field, unknown enum or key, unclassified applicable ruleset, invalid
null, non-integer number, or non-canonical ordering must be an error rather
than an omitted input. No canonical `C` bytes or digest are producible from
this record alone, and no admission may rely on one until Issue #71 implements
and proves the schema. A repository transfer must invalidate the future
pending envelope, even when GitHub preserves the immutable repository ID.

Issue #70 binds the future opaque `C` value together with its Issue #71 schema
identity, version, and digest algorithm in the transport-neutral signed
envelope. Issue #70 does not define its mechanism-specific schema or
canonicalization. The witness transports what Issue #71 produces and must not
infer canonical bytes from this record.

The future witnessed pending envelope has these minimum bindings. This list is
not a present serialization schema or canonical field order:

```text
[pending_fields]
R
B
H
C
control_state_schema_identity
control_state_schema_version
control_state_digest_algorithm
control_state_generation = G_control
control_state_event_high_water = E_control
all_control_state_fields
repository_id
repository_node_id
repository_full_name
repository_owner_login
repository_owner_type
repository_owner_database_id
repository_owner_node_id
repository_visibility
default_branch_name
default_branch_ref
pull_request_id
pull_request_node_id
pull_request_number
pull_request_state
pull_request_base_repository_id
pull_request_base_repository_node_id
pull_request_base_repository_name
pull_request_base_ref
pull_request_base_sha
pull_request_head_repository_id
pull_request_head_repository_node_id
pull_request_head_repository_name
pull_request_head_ref
pull_request_head_sha
ruleset_id
ruleset_node_id
ruleset_source
ruleset_source_type
ruleset_target_type
ruleset_target_include
ruleset_target_exclude
result_type
result_id
check_run_id
attempt
result_event_generation = G_result
result_event_high_water = E_result
app_id
installation_id
conclusion
completed_at
T_observed
O_lower
O_upper
T_valid_until
result_digest
evaluator_version
```

Result identity uses this closed projection because the Check Run and Commit
Status REST objects do not expose identical fields. See
[Get a check run](https://docs.github.com/en/rest/checks/runs?apiVersion=2026-03-10#get-a-check-run)
and
[List commit statuses for a reference](https://docs.github.com/en/rest/commits/statuses?apiVersion=2026-03-10#list-commit-statuses-for-a-reference).

```text
[result_identity]
schema_version = "fork-ops.security-posture-result/v1"
result_type = check_run | commit_status
result_id = exact immutable endpoint object ID
check_run_id = result_id for check_run; null for commit_status
attempt = signed nonnegative integer or null
attempt_null_semantics = chosen result contract has no attempt concept
result_event_generation = G_result
result_event_high_water = E_result
app_id = exact expected-source GitHub App ID
installation_id = authenticated witnessed installation ID
missing installation_id => reject result type
completed_at = check_run.completed_at or immutable commit_status.created_at
endpoint absence != inferred value
canonical values are signed and included in result_digest
```

`G_result` and `E_result` are outside `C`: they bind the independently
witnessed event history for the mutable Security Posture result stream, not
admission-control state. The result witness must advance them for every event
that creates, updates, reruns, supersedes, or otherwise changes a result that
could satisfy the required Security Posture context for `H`.

An authenticated producer statement and witness observation supply `attempt`
and `installation_id` when the selected REST result does not. `attempt` is JSON
`null` only when the chosen result contract explicitly has no attempt semantic;
the pending signature and final digest then bind that exact null. Installation
identity remains required and non-null because the contract pins one producer
installation. If authenticated witness context cannot establish it, that
result type is ineligible. The evaluator never derives either field from ID
sequence, timestamps, or repository state.

The independently administered witness clock is the sole freshness clock. App,
runner, producer, and GitHub wall clocks cannot extend authority. Canonical
times and interval bounds use whole-second UTC RFC 3339 with a literal `Z` and
no fractional seconds. Each witnessed event records its measured uncertainty
and the sources used to derive it. The maximum admitted absolute uncertainty
is `U_max = 120 seconds`, including clock skew, synchronization error,
observation and transport delay, and outward rounding to canonical precision.
That uncertainty consumes the 15-minute budget; it is not added afterward.

Let `O = [O_lower, O_upper]`, `D = [D_lower, D_upper]`, and
`A = [A_lower, A_upper]` be conservative true-time intervals around
`T_observed`, `T_decided`, and `T_admitted`. The signed witness record carries
each canonical center, its uncertainty `u`, and both outward-rounded bounds,
where `lower = T - u`, `upper = T + u`, and `0 <= u <= U_max`. Every ordering
and age decision uses the worst-case bounds:

```text
[time_predicates]
time_authority = independently administered witness clock
timestamp_format = whole-second UTC RFC 3339
U_max = 120 seconds
O_upper <= D_lower
D_upper <= A_lower
A_upper - O_lower < 900 seconds
O_lower <= security_posture.completed_at
security_posture.completed_at <= O_upper
T_valid_until == O_lower + 900 seconds
A_upper < T_valid_until
time_quality = Unknown, missing, or out-of-bound time quality fails closed
```

The `completed_at` bounds reject a producer or GitHub result dated in the
future of its witnessed observation and prevent a result first noticed late
from acquiring a fresh window. Any other source timestamp used by the
evaluator must also fall inside its independently witnessed interval. Unknown,
missing, or out-of-bound time quality fails closed, as does uncertainty above
`U_max` or a timestamp that cannot be represented canonically.

After implementing and proving that schema, Issue #71 may claim an admission
valid only when all of the following remain true in one final evaluation:

```text
[admission_predicates]
repository == R
default_branch_head == B
pull_request_head == H
H is a descendant of B
pull_request.id == pending.pull_request_id
pull_request.node_id == pending.pull_request_node_id
pull_request.number == pending.pull_request_number
pull_request.state == open
pull_request.state == pending.pull_request_state
pull_request.base.repository_id == pending.pull_request_base_repository_id
pull_request.base.repository_node_id == pending.pull_request_base_repository_node_id
pull_request.base.repository_name == pending.pull_request_base_repository_name
pull_request.base.ref == pending.pull_request_base_ref
pull_request.base.ref == pending.default_branch_ref
pull_request.base.sha == pending.pull_request_base_sha
pull_request.base.sha == pending.B
pull_request.head.repository_id == pending.pull_request_head_repository_id
pull_request.head.repository_node_id == pending.pull_request_head_repository_node_id
pull_request.head.repository_name == pending.pull_request_head_repository_name
pull_request.head.ref == pending.pull_request_head_ref
pull_request.head.sha == pending.pull_request_head_sha
pull_request.head.sha == pending.H
security_posture.head_sha == H
security_posture.producer == pinned producer App
security_posture.conclusion == success
security_posture.result_type == pending.result_type
security_posture.result_id == pending.result_id
security_posture.check_run_id == pending.check_run_id
security_posture.attempt == pending.attempt
security_posture.app_id == pending.app_id
security_posture.installation_id == pending.installation_id
security_posture.completed_at == pending.completed_at
security_posture.observed_at == pending.T_observed
security_posture.result_digest == pending.result_digest
result_witness.generation == pending.result_event_generation
result_witness.event_high_water == pending.result_event_high_water
result event change => reject even if pending result identity still matches
admission_control_state_digest == pending.C
pending.C == C
control_state.generation == pending.control_state_generation
control_state.event_high_water == pending.control_state_event_high_water
generation change => reject even if current digest == C
O_upper <= D_lower
D_upper <= A_lower
A_upper - O_lower < 900 seconds
```

Before the effect, a signed, independently witnessed pending envelope must bind
`R`, `B`, `H`, every input to `C`, and `C`. It must also bind the closed result
type, exact result ID, exact check-run ID or canonical null for a commit status,
attempt, result-event generation and high-water, producer App ID, App
installation ID, literal `success` conclusion, `completed_at`, `T_observed`,
the `O` bounds, `T_valid_until`, canonical result digest, and immutable
evaluator version. The result digest covers the complete canonical result
projection, including every field named by the predicates above. An
unavailable immutable result identifier or required witnessed binding fails
this contract; a schema-defined null is an explicit signed value, not an
inferred endpoint value.

The signed pending envelope binds the exact pull request context named above,
including its identity, open state, base repository and ref, head repository
and ref, `B`, and `H`. The final reread must reproduce every pull request
predicate before the admission decision remains eligible. The canonical pull
request projection expands GitHub's short `base.ref` and `head.ref` values to
fully qualified `refs/heads/` names before comparing them with the bound refs.

The final Security Posture reread must reconstruct that projection from GitHub
and witness evidence, recompute its digest, and satisfy every `pending`
predicate above. Matching only `H`, producer, and `success` is insufficient.
The final reread must also match the pending result-event generation and
high-water before the exclusion mechanism permits the ref update. After the
effect, a witnessed active receipt must bind the pending digest, the final
matched `G_result` and `E_result`, `T_decided`, `T_admitted`, the `D` and `A`
bounds, the GitHub response, and the exact post-update ref observation. Since
the update precedes a verification whose worst-case upper bound remains before
`T_valid_until`, `A_upper` is a conservative freshness bound for the actual
ref effect. Missing, malformed, future-dated, expired, unwitnessed,
rolled-back, equivocated, or mismatched data fails closed.

The control witness must advance `G_control` and `E_control` for every owner,
transfer, visibility, default-branch, ruleset, bypass, repository-setting, App,
installation, permission, or version event that may change an input to `C`.
The pending control generation is invalid after any advance, including a
change that is later reverted to the same value and digest. Unknown event
coverage, a gap in the append-only history, or a final high-water mismatch
fails closed. Issue #70 and Issue #71 must prove that event coverage and
independent administration; if they cannot, the candidate remains ineligible
for production.

The result witness must likewise advance `G_result` and `E_result` for every
relevant Security Posture result event. Any advance after the pending envelope
was witnessed invalidates the attempt, even when the original exact result ID
remains addressable and still reports success. Unknown result-event coverage,
an append-only-history gap, or a final result high-water mismatch fails closed.

Immediately before a proposed branch update, the admission App must re-read the
default ref, pull request head, required reviews and conversations, all
required checks, the complete Security Posture result projection, every input
to `C`, and both control and result witness high-water states. GitHub's
[Update a reference](https://docs.github.com/en/rest/git/refs?apiVersion=2026-03-10#update-a-reference)
endpoint accepts a destination ref, new SHA, and `force` flag, but has no
documented atomic compare-and-swap precondition over the previously read pull
request head `H`, default-branch head `B`, control state `C`, or Security
Posture result-event state. `force=false` is not compare-and-swap: it prevents
a non-fast-forward ref loss, but it does not make the preceding reads and the
update one atomic admission decision.
This is why broker-local serialization alone is insufficient: repository
owners, GitHub control-plane operations, and other admitted actors do not
participate in that lock.

```text
[ref_update_constraints]
documented_atomicity = no documented atomic compare-and-swap precondition
force_semantics = `force=false` is not compare-and-swap
broker_lock = broker-local serialization alone is insufficient
required_proof = equivalent exclusion, lease, or freeze
proof_scope = spans `H`, `B`, and `C`, plus control-state generation and event high-water and Security Posture result event generation and event high-water
fallback = #71 must reject the candidate if result mutation cannot be excluded
```

The candidate's future installation token must be constrained by this broker
contract, not by a GitHub protocol scope:

```text
[broker_token_constraints]
scope_enforcement = broker, not GitHub installation token
repository_ids = [repository_id]
permissions = exact least-permission subset
token_isolation = broker-only memory; never caller-visible
revocation = after each attempt and on ambiguity
negative_tests = other refs and all other permitted Contents endpoints
github_token_capability != closed protocol
```

The composite therefore remains unproven. Issue #71 must demonstrate a
supported equivalent exclusion, lease, or freeze that starts before the final
rereads; spans `H`, `B`, `C`, and the bound control-state generation and event
high-water plus the bound Security Posture result event generation and
high-water; remains effective through the ref update and post-update read; and
cannot be bypassed by any alternate update, result-publication, or
control-plane path. If result mutation cannot be excluded for that full
interval, #71 must reject the candidate. If no such mechanism exists, #71 must
reject the candidate
rather than treating a narrow broker lock or `force=false` as sufficient. The
proof must also establish and enforce a request-and-verification safety margin
inside `T_valid_until`; the App may not begin the update inside that margin.

Only after that proof may the App update the exact `default_branch_ref` to `H`
with `force=false` and verify the result. The endpoint requires repository
Contents write permission and refuses a non-fast-forward update when `force`
is false. A failed request, ambiguous response, post-update mismatch, or
concurrent state change enters a witnessed crash-pending state that blocks
later admissions until high-water recovery resolves the exact ref and
result-event state, including whether `H` was installed and whether
`G_result` or `E_result` advanced. It is never converted into a force push.

GitHub documents that up-to-date pull requests with passing checks can be
merged locally and pushed to a protected branch. It also distinguishes a
pull-request-associated update from a locally created merge commit that does
not exactly match GitHub's expected merge. These statements support the
exact-promotion candidate, but do not close the cross-resource stale-state race
or document this repository's complete ruleset and App/ref-API combination.
Issue #71 must therefore canary the exact non-force update and its exclusion
mechanism before any production claim. See
[Troubleshooting required status checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
and
[About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

## Why a native required check is insufficient

GitHub's required-check rule does not express a maximum age for a successful
result. The ruleset API accepts the check context, optional integration ID,
strictness, and creation behavior, but no success TTL. GitHub considers a
required check eligible when it succeeded within the preceding seven days,
and treats `success`, `skipped`, and `neutral` as successful conclusions for
required-check purposes. An incomplete check run is only marked stale after
14 days. See the
[repository rules REST schema](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10),
[required-check troubleshooting guidance](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks),
and the
[checks REST guide](https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-checks).

Consequently, a producer or watchdog outage after one success can leave that
success merge-eligible long after 15 minutes. Strict branch updating only
controls whether the candidate includes the latest base; it does not shorten
the success lifetime. A required check is still useful for source binding and
defense in depth, but it cannot enforce this freshness contract by itself.

The composite candidate is designed to supply the missing
repository-enforced decision point: `restrict updates` would refuse every
other updater, and the only updater would refuse evidence at or beyond the
witnessed expiry. #71 must prove that producer, witness, or broker
unavailability leaves no permitted merge path and fails closed.

## Mechanism comparison

| Mechanism | Exact final candidate | At-most-15-minute freshness | Outage behavior | Disposition |
| --- | --- | --- | --- | --- |
| Required check or commit status alone | Can bind a head SHA, but GitHub merge methods may create another SHA | No success TTL; native window is up to seven days | A prior success can remain mergeable | Reject as sole admission control |
| GitHub UI, CLI, REST, or GraphQL merge | Merge API can require the current head SHA, but merge, squash, and rebase construct the final commit afterward | Consumes native check state without a 15-minute TTL | A prior success can remain mergeable | Block as alternate paths |
| Auto-merge | Uses a GitHub merge method after requirements pass | Same native freshness gap | A prior success can complete later | Disable or make unreachable |
| Merge queue | Tests a synthetic merge group SHA | Check response timeout limits how long a check may take, not how long success remains valid | Does not close the success-TTL gap | Not sufficient; also unavailable for this personal repository |
| Environment deployment protection | Gates a deployment job, not the branch-ref update | Does not make the observation the merge admission decision | Merge can precede the deployment decision | Not an admission mechanism |
| Workflow token, deploy key, or general-purpose bot push | Could update a ref if granted authority | No single constrained evaluator or required witness | Extra credentials create bypass paths | Prohibit |
| Dedicated admission App plus `restrict updates` | Designed to promote exactly `H` and verify the resulting ref | Designed to enforce the witnessed strict expiry across decision and post-update verification | Intended to prevent updates during producer, witness, or App outage | Advance to #70/#71 proof |

GitHub's pull-request merge REST endpoint accepts an expected pull request head
SHA but then performs the requested merge method; it does not accept an
already evaluated final commit as the value to install. See
[Merge a pull request](https://docs.github.com/en/rest/pulls/pulls?apiVersion=2026-03-10#merge-a-pull-request).
The asynchronous REST endpoint has the same expected-head and merge-method
shape and defers the effect. Read-only GraphQL schema introspection likewise
found `pullRequestId`, `expectedHeadOid`, and `mergeMethod` but no
caller-selected final OID in `MergePullRequestInput`; see the
[GraphQL reference](https://docs.github.com/en/graphql/reference).

Merge queue is currently available for public repositories owned by an
organization and repositories owned by organizations using GitHub Enterprise
Cloud, not this user-owned repository. Its check response timeout is a
time-to-report bound rather than a result TTL. See
[Managing a merge queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)
and the `merge_queue` parameters in the
[repository rules REST schema](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10).

## Alternate merge paths

The proof in #71 must enumerate and canary every path below. Production is not
eligible until each non-admission path is rejected by GitHub rather than merely
discouraged by documentation or UI convention.

| Path | Required treatment |
| --- | --- |
| Web merge button: merge commit, squash, or rebase | GitHub denies the default-branch update because the web actor is not the `restrict updates` bypass actor. |
| `gh pr merge`, REST merge, GraphQL merge, and auto-merge | Same denial; no API merge actor bypasses the update rule. Auto-merge is disabled or proven unable to update. |
| Local Git fast-forward, merge, rebase, squash, force push, and deletion | Denied for every human credential, token, SSH key, and deploy key. Existing non-fast-forward and deletion rules remain active. |
| REST or GraphQL ref update | Denied for every actor except the admission App; the App accepts no caller-selected destination or SHA outside the closed protocol. |
| Fork upstream synchronization | The update rule keeps `update_allows_fetch_and_merge` false, and #71 proves no sync path can update the default branch. |
| Actions `GITHUB_TOKEN` | Contents permission is read-only unless a workflow needs a narrower write; even a write token is not a bypass actor. |
| Other GitHub Apps, OAuth Apps, personal access tokens, and fine-grained tokens | No actor is admitted to the update-rule bypass list. |
| Repository administrators and the repository owner | No bypass role is configured. Their ordinary Git writes are denied, subject to the control-plane caveat below. |
| Ruleset disablement, edit, deletion, or actor-list change | Drift changes `C`; the App refuses admission. Independent administration and witnessed control state must make rollback detectable. |
| Default-branch rename, repository transfer, visibility change, or merge-setting change | Repository or control identity no longer matches `R` and `C`; the App refuses admission pending a reviewed reprovisioning. |
| Admission App direct update without an eligible pull request | The App refuses absent exact PR, review, conversation, check, ancestry, envelope, and witness bindings; #71 must prove this negative case. |
| Concurrent or repeated App request | Broker-local serialization handles duplicate App calls only. Issue #71 must prove an equivalent exclusion, lease, or freeze across `H`, `B`, `C`, both control and result-event high-waters, the effect, and verification; otherwise the candidate is rejected. |

The admission App must expose no generic ref-update endpoint. At mint time, the
broker requests `repository_ids` containing only the bound repository ID and
the least permission subset proven for the selected endpoints. It keeps the
short-lived installation token isolated from callers and other workloads, then
revokes it after every attempt and whenever the outcome is ambiguous. GitHub
does not make that token protocol-scoped: within its repository and permission
scope, it can call every compatible endpoint. The broker's closed request
grammar, destination checks, process isolation, and revocation enforce the
narrower invariant. See
[Create an installation access token for an app](https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app)
and
[Revoke an installation access token](https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#revoke-an-installation-access-token).

Issue #71 must negatively test requests for every other ref and for other
Contents-permitted surfaces, including file-content and Git object writes. The
broker must reject them before a GitHub request and must prove token revocation;
unknown isolation or revocation state fails closed. GitHub's normal audit and
ruleset insights remain corroborating evidence, not the witness or freshness
authority.

## Repository snapshot and capability boundary

Read-only API observations at `2026-08-14T03:54:45Z` established this research
baseline:

| Property | Observed value |
| --- | --- |
| Repository | public, non-fork `nisavid/fork-ops`; repository ID `1241799725`; node ID `R_kgDOSgRcLQ`; owner type `User`; default branch `main` |
| Default branch head | `ffba90196f0ee6f381fd800a0e923e31800410c3` |
| Active repository ruleset | name `main`; ID `16509377`; node ID `RRS_lACqUmVwb3NpdG9yec5KBFwtzgD76cE`; created `2026-05-17T16:51:34.755-04:00`; updated `2026-08-13T23:50:07.524-04:00`; no bypass actors |
| Active rule families | deletion; non-fast-forward; one-review pull request with stale-review dismissal, last-push approval, and resolved-conversation requirements; CodeQL; code quality; Copilot review; required `Validation` check |
| Required Validation source | integration ID `15368`; strict updating disabled |
| Ruleset-response snapshot digest | `de0651867da9dbde53a52656cd71aebd1a63fba5d98209c5c259ddd901b595d2` |
| Repository merge settings | merge commit, squash, rebase, and auto-merge enabled |
| Actions token default | read-only; cannot approve pull requests |
| Environments | none |
| Collaborators | `nisavid` only |

The snapshot used authenticated read-only `GET` requests with
`X-GitHub-Api-Version: 2026-03-10` for the repository, default ref, repository
rulesets and exact ruleset, Actions workflow permissions, environments,
collaborators, pull request #84, and the two compared commits. The ruleset
digest is reproducible while that version remains current with:

```bash
gh api \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/nisavid/fork-ops/rulesets/16509377 \
  | jq -cS \
  | sha256sum
```

This ruleset-response snapshot digest is not `C`. It is SHA-256 over one REST
ruleset response after `jq -cS` encoding, including its terminal LF. Object
keys are sorted and array order is preserved, but it does not use the future
closed merge-admission schema that Issue #71 must implement or cover the other
control inputs. It therefore cannot produce `C`. The snapshot is evidence for the
mechanism choice, not a perpetual statement of current state. Issue #71 must
take a new snapshot and treat any identity, plan, permission, ruleset,
merge-setting, or API-semantics change as a revision trigger.

The existing `Validation` workflow runs from `pull_request_target` and checks
the exact pull request head under base-owned orchestration. It does not prove
that a GitHub-generated rebase result is the same commit. The observed rebase
merge for pull request #84 illustrates the distinction: pull request head
`1144f949b478df758def0ff57507df69865f64af` became default-branch commit
`ffba90196f0ee6f381fd800a0e923e31800410c3`. The commits have the same tree and
parent but different identities. Exact-candidate admission cannot equate them.

## Plans, permissions, and administration

Repository rulesets are available for public repositories on GitHub Free, and
GitHub Apps can be installed on repositories owned by a personal account. The
selected composite candidate therefore does not require a plan change for
disposable proof in this public repository. See
[Rulesets availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#about-rulesets)
and
[Reviewing and modifying installed GitHub Apps](https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps).

The endpoint-level permission split is provisional. GitHub's check-run guide
requires Checks: write to create check runs, while the ruleset expected-source
guidance says that the selected App must have Statuses: write. The rules REST
schema represents source binding with `integration_id`, but the documentation
does not resolve whether an App-produced check run needs Checks: write,
Statuses: write, or both for that binding. See the
[checks REST guide](https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-checks),
[available rules guidance](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets),
and [repository rules REST schema](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10).

| Principal | Provisional permissions and boundary | Required #71 resolution |
| --- | --- | --- |
| Security Posture producer App | Metadata: read; Checks: write for a check-run producer; Statuses: write is an unresolved expected-source possibility; only evidence-specific reads; no Contents write, Administration write, or update-rule bypass | Prove the exact `integration_id` binding with the chosen result type, identify the permissions GitHub actually requires, and remove every permission not needed by the proven path. |
| Merge admission App | Contents: write; Metadata: read; Pull requests: read; Checks or Statuses: read as required by the selected result; only rules/witness reads proven necessary; no result write, Administration write, or Security Posture bypass under contract 1.0 | Prove every endpoint and permission. Add Workflows: write only if promotion of workflow-changing candidates requires it and that authority is accepted. |
| Independent witness | Transport-specific append/read candidate outside both App installations; no repository contents, result, ruleset-administration, or admission authority | #70 must establish the independent administration, exact capabilities, and failure domain. |
| Ruleset administrator | Administration authority required to configure the controls; operationally separate from both Apps | Prove the accepted administrator and separation for the intended topology. |

The
[GitHub App permissions reference](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps?apiVersion=2026-03-10)
must be rechecked when #71 chooses exact endpoints. No production credential
or integration may be provisioned until this ambiguity is resolved. No
implementation may use a personal access token as a substitute for either App
identity.

A personal repository has one owner with full administrative control. Native
repository rules cannot prevent that owner from changing or disabling the
control plane. The composite can fail closed for Git write paths and detect
witnessed drift, but it cannot make the repository owner independent of their
own administrative authority. See
[Permission levels for a personal account repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/permission-levels-for-a-personal-account-repository).

The
[#54 accepted supersession](https://github.com/nisavid/fork-ops/issues/54#issuecomment-5263724011)
requires independently administered append-only history **and** admission
authority for every effect-bearing Security Exception 2.0 design. The current
personal-owner topology cannot meet that production requirement: the same
owner can administer repository rules, App installations, and the admission
path. Independent witnessing alone is insufficient.

Production Security Exception 2.0 therefore remains blocked unless the
repository is transferred to an organization and the ruleset administration,
admission App ownership and runtime credentials, and append-only witness are
placed under accepted separate administration that the risk-acceptance
authority cannot unilaterally alter. Organization-level rulesets require
GitHub Team or GitHub Enterprise Cloud. See
[Creating rulesets for repositories in your organization](https://docs.github.com/en/organizations/managing-organization-settings/creating-rulesets-for-repositories-in-your-organization).
An organization transfer alone is not enough; the administrative separation
must be proven. The only alternative is an explicit revision of #54. Until one
of those routes is accepted and proven, the personal-account owner remains an
explicit trusted control-plane root and effect-bearing Security Exception 2.0
is prohibited.

## Outage and compromise behavior

- **Producer outage:** no fresh `Security Posture` success or witnessed
  envelope exists, so the admission App refuses the update even if GitHub still
  displays an older successful required check.
- **Witness outage:** freshness, control and result-event generations,
  high-waters, and rollback resistance cannot be established, so admission
  stops.
- **Admission App outage:** no other actor can update the default branch, so
  admission stops.
- **GitHub API ambiguity, timeout, or rate limit:** the App cannot complete the
  final read set or verify the update, so it enters witnessed crash-pending and
  admits nothing else until high-water recovery resolves the exact ref and
  result-event state.
- **Producer compromise:** the producer still cannot update contents or bypass
  admission. Independent witnessing, control-state binding, and separation
  from the evaluator limit but do not erase producer risk. Any result
  publication advances the witnessed result-event state and invalidates the
  attempt; #71 must canary unauthorized and mismatched production.
- **Admission App compromise:** Contents write plus sole-update authority is a
  high-impact capability. Closed input grammar, absence of check/ruleset write,
  witnessed immutable evaluator identity, repository scoping, short-lived
  tokens, and comprehensive negative canaries are production gates.
- **Owner or ruleset-administrator compromise:** the owner can change the
  personal repository control plane. Witnessed drift supports detection and
  recovery, but only independent organization administration can remove this
  trusted-root assumption.

No failure mode may fall back to a human merge, stale success, unsigned local
judgment, direct push, force push, alternate token, or temporary ruleset
disablement.

## Future remediation-only Security Exception 2.0 proof

GitHub has no native conditional or path-scoped ruleset bypass that means
"bypass only Security Posture, only for this exact remediation." A GitHub App
bypass actor bypasses the ruleset in which it is configured. This is why
Security Posture must be isolated in its own ruleset and all existing review,
Validation, scanning, quality, deletion, non-fast-forward, and update controls
must remain in other rulesets.

Issue #71 may test a future remediation-only path only as a disposable proof
for a future separately accepted Security Exception 2.0 contract. Because the
actor that updates the branch is the actor whose bypass GitHub evaluates, a
separate non-updating remediation actor cannot waive Security Posture for the
admission App. The narrow supported candidate is for the admission App, already
the sole updater, to receive a temporary bypass on the Security Posture-only
ruleset.
GitHub cannot natively constrain that bypass to one remediation; the witnessed
evaluator must supply that narrower decision. The proof is acceptable only if:

- the admission App remains the only default-branch updater through its
  existing `restrict updates` bypass;
- it gains no bypass on review, Validation, scanning, quality, deletion,
  non-fast-forward, or any other non-Security-Posture rule;
- the request binds the exact repository, base, candidate, failed posture,
  remediation scope, diff, authority, expiry, contract and evaluator versions,
  and witnessed generation;
- the App independently proves the candidate is limited to the accepted
  remediation and all unaffected controls pass;
- the proof is pending and fail-closed before any side effect, and the
  temporary Security Posture bypass plus every test credential is revoked and
  removed afterward; and
- no experimental resource is retained as production authority.

No Security Posture bypass is configured or authorized by contract 1.0 or this
decision record. That canary does not accept contract 2.0, make an exception
effective, or alter the total false effects of Security Exception 1.0.
The #71 remediation exercise remains disposable and effectless with respect to
Security Exception governance: it grants no accepted exception, admission
authority, or retained production capability. Production remediation
authority additionally requires a new accepted contract, threat model,
implementation, review, independently administered append-only history,
independently administered admission authority, and live proof. The current
personal-owner topology is ineligible. It must establish the separate
organization administration described above or explicitly revise #54; a
future GitHub capability change cannot broaden an exception implicitly.

## Downstream proof handoff

### Issue #70: independent proof-status witnessing

Issue #70 must define the transport-neutral signed envelope and independently
administered monotonic witness used above. Its proof must cover pending,
active, revoked, append-only, compare-and-swap, inclusion, consistency,
rollback, equivocation, crash-pending, high-water recovery, retention, and
unavailable-witness failure. It must not depend on GitHub's admission mechanism
or grant either GitHub App witness administration. Its generic envelope must
bind the future opaque `C` value and the associated schema identity, schema
version, and digest algorithm supplied by Issue #71. It must not define,
canonicalize, or interpret the mechanism-specific control state.

### Issue #71: disposable live mechanism proof

Before any live control effect, Issue #71 must refresh the repository snapshot,
revalidate GitHub plan and API support, implement and version the closed
control-state schema, publish canonicalization test vectors, and prove that
independent observers reproduce its exact bytes and digest. Only then may it
publish and observe a witnessed pending generation or make an eligibility
claim. Prefer a dedicated equivalent test repository. The harness must
exercise exact-H success plus stale, future-dated, neutral, skipped, wrong-SHA,
wrong-App, wrong-repository, wrong-base, control-drift, witness-outage,
producer-outage, broker-outage, rate-limit, concurrency, replay, rollback,
equivocation, and every alternate merge path. It must also prove complete
restoration and credential revocation.
The disposable personal-repository exercise cannot establish effect-bearing
Security Exception 2.0 eligibility; that additionally requires the independent
admission authority and append-only history described above.

For ordinary admission without an effect-bearing Security Exception, candidate
production eligibility requires evidence that the default branch changed to
exactly the admitted `H`, post-update verification completed within the
15-minute observation window, every other update path was denied, all
cumulative rules remained enforced, and recovery did not reuse stale
authority.

## Research disposition

The selected shape is a supported composite candidate designed to meet the
exact-candidate, at-most-15-minute, and fail-closed contract. Operational
viability and contract satisfaction remain unproven until #71 succeeds. #69
may close because the read-only research found a supported candidate and
defined the proof obligations; #70 and #71 remain the independent-witness and
live-proof gates. This record does not deploy production admission or grant
Security Exception 1.0 authority. Disposable proof can proceed without a #54
revision, but effect-bearing Security Exception 2.0 is blocked on independent
admission authority and append-only history unless #54 is explicitly revised.
