# Validation evidence contract

`scripts/produce_validation_evidence.py` is the repository-owned validation
entrypoint. Every invocation requires an explicit mode and interpreter. The
producer resolves that interpreter once before mode execution, records its
absolute executable identity, and uses only that resolved path for every check.
It emits one terminal `validation_evidence_result` with schema version `1.0`.
`--execution-boundary container` is the fail-closed hosted boundary.
`--execution-boundary local-observational` is the default for usable local
diagnostics. Its candidate-facing subprocesses receive an explicit minimal
environment with no inherited GitHub, Actions, or credential variables, but
the result never carries security authority.

The modes are:

- `locked-source`: checks the lock, Ruff, pytest with coverage.py collection,
  Pyrefly strict, both schema copies, runtime schema output, and diff hygiene
  with locked `uv` execution. In the container boundary, every candidate
  import, CLI discovery, test, lint, type, coverage, and schema process runs in
  the isolated container.
- `fresh-source`: copies the verified repository into a private temporary
  snapshot, rejects candidate index, direct-source, dynamic-metadata, and build
  controls, then resolves with the exact hashed uv executable in a digest-pinned
  networked container. The resolver has a fixed PyPI-only policy, no host
  credentials, no Docker socket, a non-root user, and explicit process, CPU,
  memory, and output bounds. Trusted host code validates the generated lock and
  collects a closed four-minor audit matrix without importing candidate Python.
  The refreshed lock never replaces the checked-in lock.
- `build`: exports the exact `build` dependency group with hashes, audits that
  build-only scope, installs only those binary dependencies, and executes the
  PEP 517 backend in a private writable source copy inside the isolated
  container. Only the explicit output directory is writable from the host.
  The build must produce exactly one wheel and one source distribution; any
  additional file, directory, or symlink makes the candidate fail closed.
- `release-preflight`: uses a read-only Actions token in a repository verifier
  process to bind an exact successful main Validation run, its two artifacts,
  the candidate commit, and the immutable verifier revision. This mode never
  executes candidate code.
- `installed`: exports the locked `fork-ops[mcp]` runtime graph without default
  development groups or workspace packages, requires hashes while syncing it
  into a clean environment, and installs the candidate wheel with dependency
  resolution and source builds disabled. Explicit local-observational
  validation exercises that environment directly. Hosted validation mounts only the prepared
  site-packages tree and expected schema into a digest-pinned Python container,
  where it records the installed distribution graph, checks the installed CLI
  and packaged schema, and uses an MCP client over stdio to initialize, list
  tools, call `fork_ops_schema`, and close the server cleanly.

The `build` dependency group contains exact setuptools and wheel inputs. The
`test` group contains pytest and coverage.py, while `development` contains
Ruff, Pyrefly, and the type-stub tooling. The root uv configuration selects the
test and development groups by default so ordinary local commands retain the
full developer environment. The build group remains opt-in. It is
an auditable constraint source for PEP 517 isolation, not a claim that build
dependencies are runtime or development dependencies. The runtime export is
similarly limited to the candidate's published `mcp` extra. Evidence records
the export digest and scope, the uv version and executable digest, and the
normalized installed distribution graph digest.

Source evidence derives `package_scopes_by_python` from locked, hash-bearing uv
exports for each supported minor, 3.11 through 3.14. It filters every export
through uv's Linux resolver for the matching Python minor before inventorying
package names, and records both the locked export and resolved-scope digests.
Every minor has runtime, optional, build, test, and development graphs; the
optional scope is the `mcp` extra delta over the base runtime graph. Names are
normalized and marker-dependent membership remains per minor. Fresh-source
validation passes this exact map to a verifier-owned collector, fails closed if
any request, result, package tuple, scope, version, provider status, or Python
minor is missing or ambiguous, and binds the raw response and normalized matrix
digests. Full bounded JSON is parsed privately; display tails never become
authority. The local uv/OSV transport is explicitly unauthenticated and the
result remains observational. Candidate objects, serialized JSON, and `to_dict`
projections cannot acquire the collector's in-process capability. These are
observed graph memberships, not claims that one scope is another. An
authenticated Dependabot provider adapter remains follow-up work; until it
exists, unverified collector output must fail the dependency evaluator's trust
boundary.

Source evidence also discovers the public argparse leaf commands and the
workflow catalog from the running package. The CLI inventory is an exact
parser-surface contract. Workflow IDs, implementation status, and availability
are recorded as catalog contract discovery; they do not claim that planned or
current workflows executed. Installed MCP evidence requires the exact
advertised tool-name inventory while continuing to call only the non-mutating
`fork_ops_schema` tool.

The evidence identity binds the commit, a deterministic source snapshot digest,
lock digest, candidate artifact hashes, interpreter, platform, and validation
test contract. The source snapshot covers tracked and non-ignored untracked
files while excluding declared evidence and candidate outputs plus standard
caches. Regular files contribute their bytes and executable state. Candidate
symlinks and special files fail before execution, so the source digest describes
the exact executable tree. The producer walks a bound repository descriptor,
opens every parent and file without following symlinks, and creates the private
snapshot from the same bounded reads that feed its digest. It enforces per-file,
aggregate-byte, file-count, subprocess
output, subprocess time, and overall-work limits before candidate execution.
This lets unchanged dirty local source build and validate exactly.
The producer reads `uv.lock` as a regular non-symlink with no-follow semantics,
binds those exact bytes into the source and lock digests, and creates a private
verified project snapshot from them. Every uv command consumes that private
snapshot, never the checkout-controlled lock path. Workflow uv caches are
disabled so setup cannot follow the checkout lock before verification.
`reuse_key` is present only for a complete, clean identity. Reuse is valid only
for an identical key; mutable repository controls are outside this evidence
family and must be observed afresh.

Producer metadata identifies the GitHub repository, workflow reference and
revision, run, attempt, event, and candidate SHA in Actions. Local runs record
the local producer identity and entrypoint path. Installed lanes verify the
downloaded build evidence against the checked-out commit, exact source
snapshot, lock, test contract, and wheel and source-distribution hashes before
executing candidate code.

Pull requests use `pull_request_target`, so GitHub loads the orchestration from
the base branch. Each required job checks out the exact base SHA as
`trusted-verifier` and the exact pull-request head in a separate `candidate`
directory. Pinned setup and checkout actions run first; the host invokes only
`trusted-verifier/scripts/produce_validation_evidence.py` and passes
`--repo candidate`. No candidate-owned workflow, producer, build backend,
Python module, test, or installed entrypoint runs on the host. Locked
dependency preparation uses an explicit minimal environment. Candidate source
and dependencies are mounted read-only, while coverage scratch and build
output are the only writable bind mounts. Candidate processes have no network,
host credentials, Actions or OIDC tokens, checkout credentials, Docker socket,
or access to the trusted verifier and final evidence paths.

Every host-side repository query uses one absolute, hash-stable Git executable
under a minimal environment. Repository and global configuration cannot enable
fsmonitor, hooks, credential helpers, pagers, external diffs, textconv,
attributes, or user-supplied protocols. Diff commands explicitly disable
external diff and text conversion.

This event has an intentional bootstrap boundary: a newly added or changed
`pull_request_target` workflow does not run from the pull request head. The
secure pull-request orchestration activates only after that workflow exists on
the default branch. Local contract tests and actionlint can validate the
proposed shape before merge; the first post-merge pull request is the required
hosted activation checkpoint. The introducing pull request must not claim a
green hosted run from this new workflow.

Release lanes add a provenance gate before wheel execution. Using an `actions: read`
token, a preflight process from a verifier checkout pinned to the immutable
release workflow revision reads the GitHub Actions run and artifact metadata.
It requires a completed, successful `Validation` run for the exact checked-out
head of `main`, the `push` event, the expected workflow path, run ID, and run
attempt. It also requires the candidate commit to equal the current Release
Validation run SHA and binds the verifier checkout commit to the workflow SHA.
Both downloaded artifact names must be unique, unexpired products of that same
run and head and must carry GitHub's SHA-256 artifact digest. The run and
artifacts must be no more than 24 hours old, must not be future-dated, and must
have ordered authoritative creation, start, update, and expiry timestamps. A
complete successful-run listing must show the selected run as the latest
successful Validation run for the exact candidate, workflow, branch, and event.
An incomplete run or artifact API page fails closed. The build
evidence's producer repository, workflow reference and revision, run, attempt,
event, candidate SHA, and test contract must match the API result. The
candidate checkout never supplies the verifier.

The caller-associated run identity stays distinct from the called release
workflow identity. `github.repository`, `github.sha`, the run ID, and the run
attempt identify the caller repository, candidate, and artifacts. GitHub's
`job.workflow_repository`, `job.workflow_file_path`, `job.workflow_ref`, and
`job.workflow_sha` identify the workflow that defines the release job. The
workflow uses the latter repository and immutable SHA for the verifier checkout
and binds all four values into preflight and installed evidence. Release
validation therefore requires GitHub.com or GitHub Enterprise Cloud; GitHub
Enterprise Server does not expose these `job.workflow_*` identity fields and
fails closed.

Successful release preflight creates a random one-time key at an exact
no-follow path under runner temporary trusted state, outside the candidate
checkout. The terminal preflight evidence carries an HMAC-SHA-256 receipt over
the complete canonical evidence document, including the full API-derived
release provenance. The installed producer opens that exact regular key,
checks its filesystem identity, and unlinks it before it reads or validates the
serialized handoff and before any candidate process can run. It then
recomputes the receipt and the 24-hour run and artifact freshness constraints.
Missing, forged, stale, future-dated, or replayed evidence fails closed. The
key, token, and key path are never mounted or passed into a candidate
container.

Local actionlint 1.7.12 does not yet model those four documented job-context
properties. Local advisory lint may ignore only diagnostics matching
`workflow_ref`, `workflow_sha`, `workflow_repository`, or
`workflow_file_path` as missing job properties. The focused test rejects any
other diagnostic before applying that filter. GitHub.com accepting the
workflow and starting its branch or pull-request run is the authoritative
orchestration syntax checkpoint.

This repository-owned result is observational Validation evidence. Every result
includes an `assurance_boundary` that explicitly denies security authority and
`security_evidence_envelope` status. The provenance gate does not establish a
Security Posture check or satisfy a separate security assurance consumer.
Base-owned pull-request orchestration, isolated candidate execution, and an
authenticated release handoff protect this evidence family, but do not grant
it gate, merge, release, product, or assurance authority. It can be an input to
later authority, never a substitute for it.

A direct `workflow_dispatch` release is valid only when the defining release
workflow SHA is the same exact main candidate already proven by the successful
main Validation run. Dispatching a different branch or workflow revision fails
the provenance check. Cross-repository reusable invocation may bind a distinct
SHA-pinned verifier, but remains observational evidence and does not acquire
security authority.

The token-bearing preflight process writes terminal evidence and exits before
candidate execution. A new producer process consumes the one-time key and
verifies that preflight evidence and the same immutable verifier revision
before it prepares dependencies. It passes every host subprocess an explicit
minimal environment and refuses any sdist or build requirement. Candidate
Python runs only in a digest-pinned official Python image with no network, a
read-only root, bounded CPU, memory, and process counts, all capabilities
dropped, no-new-privileges, a private PID namespace, a numeric non-root user,
private size-bounded tmpfs paths, and an explicit environment. Installed
validation mounts only the prepared site-packages tree and expected schema
read-only. Source validation additionally mounts the verified candidate source
read-only and an explicit coverage scratch directory. Build validation mounts
only a private writable source copy, read-only build dependencies, and the
explicit artifact output. No lane mounts the trusted verifier, final evidence,
runner temporary root, Docker socket, key, token, or host secret. The artifact
directory is a closed set containing only the one recorded wheel and one
recorded source distribution. A run ID alone is not release provenance.

Containers with writable bind mounts use UID 65532 and the runner's numeric
non-root primary group. The producer first verifies each private mount tree is
symlink-free and runner-owned, then grants that group access without granting
world access. Candidate Python disables automatic site hooks, omits the current
working directory from module search, and searches trusted tool dependencies
before candidate source. Host-side reads of candidate outputs retain no-follow
semantics after the container exits.

Each result ends in `passed`, `failed`, or `cancelled`. Subprocesses have
individual bounds, and long source hashing and snapshot-copy operations check
the producer's overall validation-work deadline between bounded chunks.
Workflow-specific producer budgets leave several minutes inside the job's hard
timeout for evidence finalization, upload, and aggregation. Deadline expiry is
a failed check with terminal evidence; the small final serialization step can
finish after the validation-work deadline. Command failures do not prevent
terminal evidence from being written. Each behavior class lists
the explicit required IDs that its check addresses. `plugin_test_suite` means
the checked-in plugin test path ran; it does not assert that every cataloged
workflow was executed. Planned workflow contracts are catalog coverage, not
implemented-workflow execution.

Evidence finalization resolves every parent component through no-follow
directory handles, rejects parent and destination symlinks, accepts only an
absent or regular destination, and creates a mode-0600 temporary file in the
exact destination directory. It fsyncs the complete payload, atomically
replaces the destination relative to that already-open parent, and fsyncs the
directory. A failed replacement removes the temporary file. Release key files
use the same exact-parent discipline and exclusive creation.

Python 3.11 on Windows does not expose the descriptor-relative primitives used
by the authoritative POSIX writer. The nonblocking scheduled Windows advisory
therefore rejects every observable parent and destination symlink or reparse
boundary, writes an exclusive temporary file, and uses a native-path atomic
replace. It fails closed, but it is not race-resistant against a concurrent
parent swap. Pull-request, main, build, installed, and release authority never
depends on this advisory lane.

This contract sets no numeric coverage threshold. A successful pytest process
without coverage data, valid coverage JSON, positive statement totals, and at
least one measured production `fork_ops` file is a failure. The pytest check
records measured production paths, totals, and a normalized summary digest;
its temporary data and JSON files are removed when the run ends. Installed MCP
evidence claims only the observed initialize, `tools/list`,
`tools/call(fork_ops_schema)`, and clean shutdown exchange. The returned tool
names remain available as discovery evidence without claiming that every tool
was invoked.

Every source run checks unstaged changes, staged changes, and trailing
whitespace in nonignored untracked regular files. Pull-request runs also pass
the fetched base commit through `--diff-base` and check the committed
`base...HEAD` candidate range. The selected base is part of the evidence
identity.

`.github/workflows/validation.yml` is the pull-request, exact-main, and
scheduled orchestrator. It builds a candidate once and exposes the stable
aggregate check `Validation`. Scheduled supported lanes use Python 3.11 through
3.14. Scheduled macOS, Windows, and Python 3.15 lanes are advisory: each
publishes its own producer outcome, the aggregate reports those outcomes, and
their job-level failures remain nonblocking. Missing advisory output is
reported as `not_observed`, never as success. All jobs have bounded timeouts,
and the aggregate runs after failed, skipped, or cancelled children.

`.github/workflows/release-validation.yml` accepts an exact candidate commit
and the exact successful main Validation run and attempt containing its
once-built distributions. Each lane runs the token-bearing repository preflight,
ends that process, then runs the installed contract with candidate execution
confined to the pinned container on Python 3.11 through 3.14. Candidate uploads name only the wheel and source
distribution rather than an open directory. The workflow never rebuilds the
candidate. Its aggregate check is named `Release Validation`, so it cannot
satisfy or obscure the normal `Validation` context.

The workflows only orchestrate the repository-owned producer. Focused tests
use a strict fake uv/process boundary to assert critical arguments and failure
semantics; unexpected uv commands fail those tests. That fixture is not the MCP
integration. In an installed producer run, `MCP_PROTOCOL_CLIENT` imports the
installed MCP client, starts the installed `fork-ops-mcp` executable over real
stdio, performs the protocol exchange, and observes process shutdown. The
GitHub provenance gate has a deterministic local HTTP-boundary test, but promotion
still requires observing one real main Validation run and one release
validation run in GitHub Actions.
