# Dependency refresh paths

Date: 2026-08-11

## Question

Which supported dependency combination clears the current Dependabot alerts without
breaking Fork Ops's CLI, MCP adapter, packaging, or Python 3.11+ contract?

## Answer

Use MCP Python SDK 1.29 for the immediate security refresh and declare the maintenance
line explicitly as `mcp>=1.29,<2`. Refresh the six alerted packages together. The tested
combination was:

| Package | Current lock | Tested secure version | Highest patched floor in current alerts |
| --- | ---: | ---: | ---: |
| `mcp` | 1.27.1 | [1.29.0](https://pypi.org/project/mcp/1.29.0/) | 1.28.1 |
| `cryptography` | 48.0.0 | [50.0.0](https://pypi.org/project/cryptography/50.0.0/) | 50.0.0 |
| `PyJWT` | 2.12.1 | [2.13.0](https://pypi.org/project/PyJWT/2.13.0/) | 2.13.0 |
| `pydantic-settings` | 2.14.1 | [2.15.0](https://pypi.org/project/pydantic-settings/2.15.0/) | 2.14.2 |
| `python-multipart` | 0.0.29 | [0.0.32](https://pypi.org/project/python-multipart/0.0.32/) | 0.0.31 |
| `starlette` | 1.0.0 | [1.6.0](https://pypi.org/project/starlette/1.6.0/) | 1.3.1 |

The current package requirement has no upper bound, so a full lock refresh selects MCP
2.0.0 rather than a compatible v1 release. The MCP project says v2 is the current stable
line, v1 is maintained for critical and security fixes, and packages remaining on v1 must
declare `<2` until migrated. The current v1 maintenance release is 1.29.0. See the
[SDK README](https://github.com/modelcontextprotocol/python-sdk/blob/main/README.md) and
[v1.29.0 release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v1.29.0).

MCP 2.0 is not a lock-only alternative. Its migration guide says `FastMCP` became
`MCPServer` and identifies `No module named 'mcp.server.fastmcp'` as the expected first
failure. Fork Ops imports exactly that removed module, catches the failure, and reports the
optional dependency as unavailable. See the
[v2 migration guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/migration.md),
[`mcp_server.py`](../../../plugins/fork-ops/src/fork_ops/mcp_server.py), and the
[v2.0.0 release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0).

## Alert evidence

The 22 open general Dependabot alerts all point at versions present in
[`uv.lock`](../../../uv.lock). The root workspace installs `fork-ops[mcp]`, so these are
not dormant lock entries. Every alerted transitive package comes through MCP 1.27.1; Fork
Ops imports none of the five transitive packages directly.

| Package | Alerts | Current alert boundary |
| --- | --- | --- |
| `mcp` | [17](https://github.com/nisavid/fork-ops/security/dependabot/17), [18](https://github.com/nisavid/fork-ops/security/dependabot/18), [19](https://github.com/nisavid/fork-ops/security/dependabot/19) | All current direct SDK alerts clear at 1.28.1. |
| `cryptography` | [11](https://github.com/nisavid/fork-ops/security/dependabot/11), [22](https://github.com/nisavid/fork-ops/security/dependabot/22), [23](https://github.com/nisavid/fork-ops/security/dependabot/23), [24](https://github.com/nisavid/fork-ops/security/dependabot/24) | Alert 22 requires 50.0.0; 48.0.1 or 49.0.0 alone is insufficient. |
| `PyJWT` | [3](https://github.com/nisavid/fork-ops/security/dependabot/3), [4](https://github.com/nisavid/fork-ops/security/dependabot/4), [6](https://github.com/nisavid/fork-ops/security/dependabot/6), [20](https://github.com/nisavid/fork-ops/security/dependabot/20), [21](https://github.com/nisavid/fork-ops/security/dependabot/21) | All five clear at 2.13.0. |
| `pydantic-settings` | [16](https://github.com/nisavid/fork-ops/security/dependabot/16) | Clears at 2.14.2. |
| `python-multipart` | [7](https://github.com/nisavid/fork-ops/security/dependabot/7), [8](https://github.com/nisavid/fork-ops/security/dependabot/8), [9](https://github.com/nisavid/fork-ops/security/dependabot/9), [10](https://github.com/nisavid/fork-ops/security/dependabot/10) | Alert 9 requires 0.0.31; 0.0.30 alone is insufficient. |
| `starlette` | [1](https://github.com/nisavid/fork-ops/security/dependabot/1), [12](https://github.com/nisavid/fork-ops/security/dependabot/12), [13](https://github.com/nisavid/fork-ops/security/dependabot/13), [14](https://github.com/nisavid/fork-ops/security/dependabot/14), [15](https://github.com/nisavid/fork-ops/security/dependabot/15) | Alert 15 requires 1.3.1; 1.0.1 alone is insufficient. |

Static impact triage found a shipped MCP/tooling surface but no repository security policy
that defines its trust boundary. The only shipped server entrypoint calls v1 `FastMCP.run()`
without a transport argument, whose documented default is stdio. The code does not select
the HTTP, WebSocket, task, auth, multipart, secrets-directory, or PKI paths named by the
alerts. See the
[v1.29 `FastMCP.run()` source](https://github.com/modelcontextprotocol/python-sdk/blob/v1.29.0/src/mcp/server/fastmcp/server.py#L282-L303)
and [`mcp_server.py`](../../../plugins/fork-ops/src/fork_ops/mcp_server.py).
This does not prove that every advisory is exploitable in Fork Ops, but it also does not
justify retaining vulnerable supply-chain inputs. Clearing the lock is the bounded,
auditable action.

## Candidate validation

The secure v1 combination installed as a wheel-backed package and passed the following
checks on CPython 3.11.15, 3.12.13, 3.13.15, and 3.14.6:

- 137 tests passed on each interpreter.
- `fork-ops-mcp --health-check` reported the dependency available and all 14 tools on each
  interpreter.
- A real stdio client initialized the server and listed all 14 tools on Python 3.13.
- `fork-ops schema print` matched the packaged schema on Python 3.11 and 3.14.
- Package build and installation succeeded on every interpreter.

The v1 runs emitted an upstream `pydantic-settings` warning about an unresolved `lifespan`
forward reference. It did not prevent startup, initialization, tool listing, or the test
suite, but the refresh should retain that warning as a known compatibility observation.

MCP 2.0.0 also resolved with secure transitive versions and all 137 tests passed on Python
3.13 and 3.14. That result is a false positive for MCP compatibility:
`fork-ops-mcp --health-check` reported `mcp_dependency_available: false` and
`No module named 'mcp.server.fastmcp'` on both interpreters. The current tests assert tool
names even when MCP is absent and do not require an installed MCP dependency to register
the server. See [`test_core.py`](../../../plugins/fork-ops/tests/test_core.py).

## Viable paths

### 1. Security refresh on MCP 1.x — recommended now

Change the package requirement to `mcp>=1.29,<2`, then refresh MCP and all five alerted
transitive packages in one lock update. This is the smallest supported path, clears every
current alert range, preserves the current adapter, and keeps the Python 3.11+ contract.

The execution change should also add a regression gate that installs the MCP extra and
requires `mcp_dependency_available: true`, followed by an actual stdio initialization and
tool-list assertion. The existing repository checks remain necessary but are not sufficient
for this boundary.

### 2. MCP 2.x migration — viable follow-up, not an immediate refresh

Move to `mcp>=2,<3` only as explicit migration work. At minimum, replace `FastMCP` with
`MCPServer`, update the adapter's registration and run surfaces, and validate the breaking
changes called out by the official guide. The dependency graph also swaps `httpx` for
`httpx2`, adds `mcp-types`, OpenTelemetry, and `truststore`, and removes
`pydantic-settings` from MCP's required dependencies.

This path reaches the current stable SDK and current protocol, but it expands the change
surface and must not be inferred from a green unit suite.

### 3. Partial transitive-only refresh — not viable

Updating Starlette or other transitives without MCP leaves the three direct MCP alerts
open. Updating Starlette only to 1.0.1 also leaves four newer Starlette alerts open. A
partial refresh cannot produce a trustworthy baseline.

## Remaining uncertainties

- The repository has no declared `SECURITY.md` boundary, so this research does not claim
  advisory-by-advisory runtime exploitability or absence.
- The v1 `pydantic-settings` warning should be tracked during execution; current evidence
  shows working stdio behavior, not every possible settings source.
- Windows packaging was resolved by package metadata but not executed locally. MCP 1.29,
  the six tested packages, and Fork Ops all declare Python support that includes 3.11–3.14;
  platform-specific Windows execution still needs CI evidence.
- Context7 was unavailable in the harness and its CLI fallback was not installed. All
  external claims above therefore use the MCP SDK's official repository, release notes,
  documentation, PyPI metadata, and GitHub's Dependabot alert records directly.
