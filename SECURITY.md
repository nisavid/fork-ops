# Security Policy

## Boundary and trust model

Fork Ops exposes a local CLI and a stdio MCP adapter. The caller is trusted only
when it is a locally authorized operator or harness. Repository content, fork
configuration, filesystem paths, MCP parameters, discovered command metadata,
and scanned source material are untrusted inputs. Scanned material can be
sensitive even when it is not itself a security finding.

Process launches must use provenance-bound, reviewed commands rather than
repository-controlled executable metadata. Writes must stay inside the intended
repository, require the workflow's authorization and guards, preserve unrelated
work, and verify the resulting state. A parser, inventory record, or Security
Exception does not authorize a launch, write, bypass, merge, release, or other
effect.

## Reporting

Report vulnerabilities through GitHub private vulnerability reporting for this
repository. Include the affected boundary, realistic impact, reproduction or
supporting evidence, and a safe way to validate a fix. Do not place secrets,
confidential finding evidence, or unnecessary exploit detail in public issues,
pull requests, or the public Security Exception ledger. Public ledger references
must be credential-free HTTPS URLs using the contract's closed per-host public
resource paths; arbitrary paths, query strings, fragments, userinfo, local
addresses, and lookalike hosts are refused.

## Supported versions

No released version is supported yet. Reports against `main` are welcome. After
releases begin, the default support policy is `main` plus the newest release
line unless another line is explicitly declared.

## Security Exceptions

Ivan D Vasin is the sole risk-acceptance authority under contract 1.0, bound to
GitHub login `nisavid`, account database ID `576874`, and node ID
`MDQ6VXNlcjU3Njg3NA==`. Contract 1.0 records inventory, decisions, lineage, and
lifecycle only. It cannot make Security Posture pass; authorize admission or
merge; relax, disable, bypass, or mutate a repository control; validate
assurance; confer baseline or release eligibility; or authorize product or
dogfood work. The underlying finding, failed control, or unavailable evidence
remains present and blocking wherever otherwise required.

The package-owned
[`security-exception-contract-1.0.json`](plugins/fork-ops/src/fork_ops/security-exception-contract-1.0.json)
is the sole exact source for Security Exception artifact schemas, enums,
canonicalization, transitions, time formulas, and effects. The public ledger is
[`docs/agents/security-exceptions.toml`](docs/agents/security-exceptions.toml),
and the mechanically checked guide is
[`docs/agents/security-exceptions.md`](docs/agents/security-exceptions.md).
Private proposals, commands, and evidence remain in the private advisory
adapter; only its versioned sanitized projection is accepted by the pure
validator. Pure validation establishes structural conformance only. It cannot
authenticate caller-provided authority, command, persistence, or provider
claims. Typed inventories and transition/provider projections therefore carry
an explicit `structural_unverified` status, and response-clock positive-zero
claims fail closed until a live authenticated adapter exists. Lifecycle
projections preserve that structural trust status and cannot claim active
authority.

An Unscanned Equipment Exception is a separate equipment-governance concept.
It is not a Security Exception and cannot affect Security Posture unless the
same condition is separately represented and validated under the closed
Security Exception contract.

## Known limitations

Contract 1.0 provides pure local validation only. It does not collect or persist
GitHub observations, publish commands or comments, administer append-only
history, provide live admission proof, roll back remote history, enforce gates
or rulesets, authenticate producer provenance, or implement a bootstrap path.
No exception has gate, merge, assurance, release, product, or dogfood effect.
Any future effect-bearing design requires a separately accepted and unsupported
contract 2.0.
