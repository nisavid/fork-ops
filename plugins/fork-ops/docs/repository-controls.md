# Repository control observation reference

The `fork_ops.repository_controls` and
`fork_ops.repository_control_adapters` modules provide the internal library
surface for first-party repository-security evaluation. They do not add a CLI
or MCP operation.

## Observation contract

`repository_control_observation` supports schema version `1.0` only. The
canonical contract is packaged as
`repository-control-observation-contract-1.0.json`. The parser verifies the
contract file digest, refuses unsupported versions, requires the complete
closed control set in canonical order, verifies each `projection_sha256` over
its complete safe control projection, and verifies `observation_sha256` over
the complete observation without that digest field.

The root observation binds:

- exact repository database, node, full-name, and default-branch identity;
- exact candidate commit;
- producer kind, opaque identity, workflow commit, and evaluator digest;
- one operation epoch, start, completion, and deadline; and
- one normalized record for every required control.

An operation deadline and every control validity window are at most 900
seconds. Evidence is stale when evaluation time equals `valid_until`.

## Required controls

| Control ID | Source |
| --- | --- |
| `main_ruleset` | GitHub |
| `human_review` | GitHub |
| `stale_approval_dismissal` | GitHub |
| `last_push_approval` | GitHub |
| `resolved_review_threads` | GitHub |
| `validation_required` | GitHub |
| `codeql_required` | GitHub |
| `code_quality_required` | GitHub |
| `copilot_review_required` | GitHub |
| `approved_producer_identities` | GitHub |
| `dependabot_grouped_updates` | Package |
| `dependabot_security_updates` | GitHub |
| `dependency_auto_merge_disabled` | GitHub |
| `dependency_review` | Package |
| `immutable_action_pins` | Package |
| `code_scanning` | GitHub |
| `secret_scanning` | GitHub |
| `push_protection` | GitHub |
| `private_vulnerability_reporting` | GitHub |
| `codeql_alerts` | GitHub |
| `dependabot_alerts` | GitHub |
| `secret_scanning_alerts` | GitHub |
| `public_security_exception_state` | Package |
| `private_security_exception_state` | GitHub |

Each control record contains only `control_id`, `source`, `status`,
`observed_at`, `valid_until`, `projection_sha256`, and sorted opaque
identifiers. The digest covers the safe normalized projection, not raw provider
evidence. An unavailable record also contains one closed `failure_class`.
Valid classes are `unauthorized`, `forbidden`, `not_found_or_inaccessible`,
`rate_limited`, `timeout`, `malformed`, `pagination_incomplete`,
`identity_mismatch`, `stale`, and `adapter_error`.

## Adapter interface

`GitHubControlAdapter` and `PackageControlAdapter` each own one control. A
reader receives an immutable `ControlReadContext` containing the exact target,
producer, operation epoch, UTC interval, and monotonic deadline. Its response
must bind the same repository, candidate, and epoch. A mismatch projects as
`unavailable` with `identity_mismatch`.

Before each provider request, an injected GitHub reader must call
`context.remaining_seconds()` and pass that value as the transport's hard
timeout. A reader must not start a request when the value is zero. The adapter
checks the deadline before and after the reader call, and the coordinator
ignores any worker result that remains late. Python cannot preempt an arbitrary
reader that disregards its transport timeout. Such a reader can remain in a
daemon worker after the observation returns and repeated non-cooperative custom
readers can accumulate in a long-lived process. First-party readers must
therefore retain hard transport timeouts.

`build_github_control_adapters` requires one read-only reader for every
GitHub-owned control. The transport remains injected so authentication and API
selection stay outside the pure library. Each injected reader is the trusted
provider-specific semantic adapter for its named control; it may return
`passed` only after reading the exact repository and operation-bound state for
that control. A generic repository setting or a neighboring control is not a
substitute. In particular, `main_ruleset` covers the active default-branch
ruleset, the named review and required-check controls cover their exact rules,
and `dependency_auto_merge_disabled` requires evidence that dependency changes
cannot be auto-merged rather than merely observing a repository-wide feature
flag. Missing or inaccessible proof returns `unavailable`, not an inferred
pass.

Alert controls require complete pagination and derive status from the open-item
count. Private exception state requires two complete, semantically identical
provider passes. The remaining GitHub setting readers attest the exact enabled,
disabled, required, or allowlisted state named by their control ID.

`build_package_control_adapters` supplies bounded no-follow readers for the
package-owned controls on Linux, where `/proc` descriptor paths and
descriptor-relative opens provide the required root anchor. Other platforms
fail closed before observation. The repository path must be a Git
materialization at the request's exact candidate commit. Before and after a
control read, its scoped index and worktree paths must match that exact commit;
skip-worktree and assume-unchanged index entries are refused. Workflow paths
are enumerated from the exact candidate tree and matched to the materialized
path set. Every inspected file is compared with the blob addressed by the
candidate SHA.
Git runs through a trusted system executable with repository-configurable
hooks, monitors, external diffs, credentials, and protocols disabled. Git
pathspecs are forced to literal interpretation. Operations that interpret
candidate clean filters are not used, and command output is consumed within the
caller's byte and time bounds. The readers then inspect:

- `.github/dependabot.yml` or `.github/dependabot.yaml` plus the authoritative
  `uv.lock` for exactly one effective root-directory `uv` update record on the
  default branch. It must run weekly and contain exactly one version-update
  group covering all dependencies and only compatible minor and patch updates.
  Multi-ecosystem assignment, lockfile-only versioning, allow, ignore, group
  exclusions, cooldown overrides, and dependency-type filters are refused;
- workflow files for a full-SHA-pinned dependency-review action on pull
  requests without narrowing event filters, prerequisite jobs, conditional
  execution, or failure tolerance, on a runnable job with
  effective workflow/job `contents: read` permission, `fail-on-severity: low`,
  and explicit
  `runtime`, `development`, and `unknown` scope coverage. `warn-only: false`
  and `vulnerability-check: true` must also be explicit; advisory allowlists,
  external config files, ref overrides, implicit, empty, or write-only
  permissions, warn-only mode, and disabled vulnerability checks are refused;
- every workflow `uses` reference for a full 40-character action commit or
  full container-image SHA-256 digest; local reusable workflows remain in the
  checked workflow set, while local action manifests are traversed recursively
  under closed count, depth, path, and cycle bounds. A local Docker action's
  Dockerfile is resolved relative to its action manifest, read from the exact
  candidate through the same no-follow boundary, and included in evidence.
  Every external `FROM` image, `COPY --from` source, `RUN --mount` `from`
  source, and active frontend declaration must use a SHA-256 digest. Parser
  preambles account for one UTF-8 BOM, an initial shebang, recognized `check`
  and `escape` directives, and BuildKit's slash-comment and JSON frontend forms
  before stage parsing. Completed prior stage names are accepted for all three
  materialization paths; `COPY --from` also accepts completed prior numeric
  stage indices, while `scratch` remains valid for `FROM` and `COPY --from`.
  A current or forward stage is not a materialization source.
  Unmatched sources are treated as external image or named-context references;
  the standard runner supplies no named contexts, so they require a literal
  SHA-256 digest. Variables, platform options, URLs, forward stage references,
  mutable tags, and incomplete source flags are refused. The accepted subset
  contains only single-physical-line instructions: any non-comment line ending
  in the configured escape character, including repeated escapes, and every
  heredoc-bearing instruction are refused rather than approximating BuildKit's
  continuation and shell lexers. Leading `COPY` and `RUN` flag tokens containing
  quote segments or inline configured escape characters are also refused; JSON
  operand and command forms remain allowed after unambiguous flags. Every
  repository-visible `ADD` instruction is refused rather than distinguishing
  its local, URL, Git, checksum, and argument-expanded input forms.
  Repository-visible `ONBUILD` instructions are refused because their deferred
  effects cannot be bound at this boundary. Arbitrary network access from an
  ordinary `RUN` and inherited metadata or effects inside a digest-pinned base
  are outside the static direct-reference evidence. Dockerfile count and stage
  traversal are bounded;
- `docs/agents/security-exceptions.toml` for standalone public-ledger schema,
  confidentiality, semantic, and public digest validation. Whole-ledger event
  and record digest reconciliation remains owned by
  `private_security_exception_state`, because contract 1.0 exposes lineage
  entries only in the sanitized private projection.

Package files must be stable regular files beneath non-symlink parents and are
limited to 1 MiB each. Workflow files, local-action manifests, and Dockerfiles
share an 8 MiB cumulative budget. Directory-descriptor-relative opens keep each
read anchored beneath the repository root. Workflow YAML, local action
manifests, and Dependabot policy are parsed structurally with duplicate mapping
keys rejected. Workflow, local-action, and Dockerfile evidence exposes one
deterministic aggregate digest over sorted path-and-file-digest records.
Dependabot evidence binds both the candidate policy and lock digests; other
package evidence exposes the candidate file digest. No package content survives
projection.

## Coordinator

`collect_repository_control_observation` accepts one
`RepositoryObservationRequest` and the exact adapter set. It fans out reads
under one epoch and monotonic deadline with one explicit daemon worker per
adapter, records each adapter's completion time centrally, ignores results
completed at or after the deadline, and returns without joining a reader that
does not cooperate with its timeout. It maps exceptions to closed failure
classes, orders results by the contract, and returns an immutable parsed
observation. The coordinator performs no provider or package mutation.

## First-party result

`evaluate_first_party_security` is pure over a parsed observation, a typed
Security Exception 1.0 inventory, and an explicit evaluation time. It returns
`first_party_security_result` `1.0`.

The result is failed when any required control is failed, unavailable, stale,
or from the future, or when the Security Exception inventory is not the typed
whole-ledger projection. Security Exception 1.0 remains inventory-only: its
records never clear a control, make the result green, authorize merge or
admission, or establish baseline or release eligibility.

Raw private advisory and exception responses are not retained. Adapter errors
are reduced to a closed failure class; serialized observations and results
contain only safe state, UTC times, digests, opaque identifiers, and fixed
diagnostic text.
