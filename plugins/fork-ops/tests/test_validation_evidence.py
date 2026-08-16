from __future__ import annotations

import hashlib
import http.server
import json
import os
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import tomllib
import unittest
import venv
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from typing_extensions import override

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VALIDATION_ENTRYPOINT = REPOSITORY_ROOT / "scripts" / "produce_validation_evidence.py"
MCP_TOOL_NAMES = [
    "fork_ops_capability_report",
    "fork_ops_config_read",
    "fork_ops_config_validate",
    "fork_ops_equipment_migration_preflight",
    "fork_ops_migration_assessment",
    "fork_ops_migration_blocker_resolution",
    "fork_ops_migration_config_patch",
    "fork_ops_migration_dry_run",
    "fork_ops_migration_execute",
    "fork_ops_migration_plan",
    "fork_ops_plugin_health",
    "fork_ops_schema",
    "fork_ops_workflow_catalog",
    "fork_ops_workflow_migration_inventory",
]


class ValidationEvidenceEntrypointTests(unittest.TestCase):
    def test_workflow_catalog_check_accepts_canonical_contracts(self) -> None:
        namespace = runpy.run_path(str(VALIDATION_ENTRYPOINT))
        workflow_catalog_check = namespace["_workflow_catalog_check"]
        contract_ids = namespace["WORKFLOW_CONTRACT_IDS"]
        payload: dict[str, Any] = {
            "artifact_kind": "workflow_catalog",
            "schema_version": "1.0",
            "contracts": [
                {
                    "available_operation_ids": list[str](),
                    "id": contract_id,
                    "implementation_extent": "planned",
                }
                for contract_id in contract_ids
            ],
        }

        def run_command(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "_stdout_complete": json.dumps(payload),
                "exit_code": 0,
                "status": "passed",
            }

        with mock.patch.dict(
            workflow_catalog_check.__globals__,
            {"_run_command": run_command},
        ):
            check = workflow_catalog_check(REPOSITORY_ROOT, ["uv", "run"])

        self.assertEqual(check["status"], "passed", check.get("stderr_tail"))
        self.assertEqual(
            check["contracts"]["guarded-sync-execution"],
            {
                "available_operation_ids": [],
                "implementation_extent": "planned",
            },
        )

        payload["contracts"][0]["available_operation_ids"] = [
            "duplicate-operation",
            "duplicate-operation",
        ]
        with mock.patch.dict(
            workflow_catalog_check.__globals__,
            {"_run_command": run_command},
        ):
            duplicate_check = workflow_catalog_check(REPOSITORY_ROOT, ["uv", "run"])

        self.assertEqual(duplicate_check["status"], "failed")
        self.assertIn("extent is invalid", duplicate_check["stderr_tail"])

    @unittest.skipIf(os.name == "nt", "This test requires POSIX process groups.")
    def test_bounded_process_caps_combined_output_and_terminates_pipe_holders(self) -> None:
        namespace = runpy.run_path(str(VALIDATION_ENTRYPOINT))
        run_bounded = namespace["_run_bounded_process"]
        limit_error = namespace["SubprocessOutputLimitExceeded"]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaises(limit_error):
                run_bounded(
                    [
                        sys.executable,
                        "-c",
                        "import os,threading; "
                        "threads=[threading.Thread(target=os.write,args=(fd,b'x'*70000)) "
                        "for fd in (1,2)]; "
                        "[t.start() for t in threads]; [t.join() for t in threads]",
                    ],
                    cwd=root,
                    env={"PATH": os.defpath},
                    timeout=2,
                    max_output_bytes=100_000,
                )
            started = time.monotonic()
            with self.assertRaises(limit_error):
                run_bounded(
                    [
                        sys.executable,
                        "-c",
                        "import subprocess,sys; "
                        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])",
                    ],
                    cwd=root,
                    env={"PATH": os.defpath},
                    timeout=2,
                    max_output_bytes=100_000,
                )
            self.assertLess(time.monotonic() - started, 2)

    def test_isolated_python_bootstrap_keeps_stdlib_and_trusted_tools_ahead_of_candidate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            trusted = root / "trusted"
            candidate = root / "candidate"
            trusted.mkdir()
            candidate.mkdir()
            (trusted / "verifier_tool.py").write_text("VALUE = 'trusted'\n", encoding="utf-8")
            (candidate / "verifier_tool.py").write_text("VALUE = 'candidate'\n", encoding="utf-8")
            (candidate / "json.py").write_text(
                "raise RuntimeError('candidate shadowed the standard library')\n",
                encoding="utf-8",
            )
            (candidate / "sitecustomize.py").write_text(
                "raise RuntimeError('candidate site hook executed')\n",
                encoding="utf-8",
            )
            namespace = runpy.run_path(str(VALIDATION_ENTRYPOINT))
            isolated_python_argv = namespace["_isolated_python_argv"]
            command = isolated_python_argv(
                [str(trusted), str(candidate)],
                [
                    "-c",
                    "import json, verifier_tool; "
                    "print(json.dumps({'value': verifier_tool.VALUE}))",
                ],
            )

            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout), {"value": "trusted"})

    @unittest.skipIf(os.name == "nt", "This test requires a POSIX virtual environment.")
    def test_isolated_child_projection_blocks_site_hooks_and_resolves_exact_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            environment = root / "environment"
            dependencies = root / "dependencies"
            source = root / "source"
            (dependencies / "jsonschema").mkdir(parents=True)
            (source / "fork_ops").mkdir(parents=True)
            (dependencies / "jsonschema" / "__init__.py").write_text("", encoding="utf-8")
            (source / "fork_ops" / "__init__.py").write_text("", encoding="utf-8")
            (source / "sitecustomize.py").write_text(
                "raise SystemExit('candidate site hook executed')\n",
                encoding="utf-8",
            )
            venv.EnvBuilder(with_pip=False).create(environment)
            python = environment / "bin" / "python"
            minor = f"{sys.version_info.major}.{sys.version_info.minor}"
            standard_site = environment / "lib" / f"python{minor}" / "site-packages"
            namespace = runpy.run_path(str(VALIDATION_ENTRYPOINT))
            projection_text = namespace["_isolated_child_projection_text"]
            target = namespace["ISOLATED_CHILD_TARGET"]
            (standard_site / "fork_ops_validation.pth").write_text(
                projection_text(str(dependencies), str(source)),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [str(python), "-I", "-c", target],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["fork_ops"], str(source / "fork_ops" / "__init__.py"))
            self.assertEqual(
                payload["jsonschema"],
                str(dependencies / "jsonschema" / "__init__.py"),
            )
            self.assertFalse(payload["fork_ops_distribution_installed"])
            self.assertTrue(payload["sitecustomize_is_verifier_placeholder"])
            self.assertEqual(payload["workspace_paths"], [])

    def test_windows_advisory_writer_uses_native_paths_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "evidence.json"
            outside = root / "outside.json"
            outside.write_text("outside\n", encoding="utf-8")
            namespace = runpy.run_path(str(VALIDATION_ENTRYPOINT))
            writer = namespace["_atomic_write_text_windows"]

            writer(output, ".evidence.tmp", b"trusted\n")

            self.assertEqual(output.read_bytes(), b"trusted\n")
            output.unlink()
            output.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                writer(output, ".evidence.tmp", b"untrusted\n")
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")

            output.unlink()
            original_lstat = Path.lstat

            def lstat_with_reparse_point(path: Path) -> os.stat_result | SimpleNamespace:
                metadata = original_lstat(path)
                if path == root:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                    )
                return metadata

            with (
                mock.patch.object(
                    Path,
                    "lstat",
                    autospec=True,
                    side_effect=lstat_with_reparse_point,
                ),
                self.assertRaisesRegex(ValueError, "reparse point"),
            ):
                writer(output, ".evidence.tmp", b"untrusted\n")

    def test_container_boundary_covers_source_build_backend_and_installed_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root, assert_clean_environment=True)
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
            env["GITHUB_TOKEN"] = "must-not-cross-candidate-boundary"
            env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "must-not-cross-candidate-boundary"
            common = [
                sys.executable,
                str(VALIDATION_ENTRYPOINT),
                "--interpreter",
                sys.executable,
                "--repo",
                str(repo),
                "--execution-boundary",
                "container",
            ]

            source_output = fixture_root / "source.json"
            source = subprocess.run(
                [*common, "--mode", "locked-source", "--output", str(source_output)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(
                source.returncode,
                0,
                source.stderr + source_output.read_text(encoding="utf-8"),
            )
            source_evidence = json.loads(source_output.read_text(encoding="utf-8"))
            self.assertEqual(source_evidence["execution_boundary"], "container")
            self.assertEqual(source_evidence["checks"][0]["id"], "candidate_isolation")
            source_image = {
                "3.11": "python:3.11@sha256:"
                "d0199e2a90bf7a206a485b115323a75bc946f30b463d704c5435a454aca084dd",
                "3.12": "python:3.12@sha256:"
                "dd4fe98ab39f91e936f8e7e7a65a3ce59ecfb11e32f9a125b3132779920ba7f7",
                "3.13": "python:3.13@sha256:"
                "79a441dc2306d79ea4350fbe3f75de38328dd9b74588d1a7f0b6bacb6e0a5e9c",
                "3.14": "python:3.14@sha256:"
                "297cf11d0b98b38ac26a56136f0279df845314bcd0347c1f6383fee6e75125ee",
            }[f"{sys.version_info.major}.{sys.version_info.minor}"]
            source_python_minor = f"{sys.version_info.major}.{sys.version_info.minor}"

            env.update(
                {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_WORKFLOW_REF": (
                        "owner/repo/.github/workflows/validation.yml@refs/heads/main"
                    ),
                    "GITHUB_WORKFLOW_SHA": self._git_commit(repo),
                    "GITHUB_RUN_ID": "12345",
                    "GITHUB_RUN_ATTEMPT": "1",
                }
            )
            fresh_output = fixture_root / "fresh-source.json"
            fresh = subprocess.run(
                [*common, "--mode", "fresh-source", "--output", str(fresh_output)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(
                fresh.returncode,
                0,
                fresh.stderr + fresh_output.read_text(encoding="utf-8"),
            )
            fresh_evidence = json.loads(fresh_output.read_text(encoding="utf-8"))
            resolver = fresh_evidence["checks"][0]
            self.assertEqual(resolver["id"], "fresh_resolution")
            self.assertEqual(
                resolver["environment_policy"],
                "networked_resolver_container_explicit_minimal",
            )
            self.assertIn("--network=bridge", resolver["command"])
            self.assertNotIn("--network=none", resolver["command"])

            artifact_dir = fixture_root / "candidate"
            build_output = fixture_root / "build.json"
            build = subprocess.run(
                [
                    *common,
                    "--mode",
                    "build",
                    "--artifact-dir",
                    str(artifact_dir),
                    "--output",
                    str(build_output),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(
                build.returncode,
                0,
                build.stderr + build_output.read_text(encoding="utf-8"),
            )
            build_evidence = json.loads(build_output.read_text(encoding="utf-8"))
            build_check = next(
                check for check in build_evidence["checks"] if check["id"] == "build_distributions"
            )
            self.assertEqual(build_check["command"][0:2], ["docker", "run"])
            build_workspace_mount = next(
                argument
                for argument in build_check["command"]
                if "dst=/workspace" in argument
            )
            self.assertTrue(build_workspace_mount.endswith(",readonly"))
            self.assertIn("shutil.copytree", build_check["command"][-1])
            self.assertIn("/tmp/candidate", build_check["command"][-1])

            installed_output = fixture_root / "installed.json"
            installed = subprocess.run(
                [
                    *common,
                    "--mode",
                    "installed",
                    "--artifact-dir",
                    str(artifact_dir),
                    "--build-evidence",
                    str(build_output),
                    "--output",
                    str(installed_output),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            installed_evidence = json.loads(installed_output.read_text(encoding="utf-8"))
            candidate_commands = [
                check["command"]
                for check in [*source_evidence["checks"], *installed_evidence["checks"]]
                if check["id"]
                in {
                    "cli_surface_inventory",
                    "workflow_catalog",
                    "ruff",
                    "pytest",
                    "pyrefly_strict",
                    "schema_parity",
                    "container_python_identity",
                    "installed_graph",
                    "installed_cli",
                    "installed_schema",
                    "mcp_protocol",
                }
            ]
            candidate_commands.append(build_check["command"])
            self.assertTrue(candidate_commands)
            for command in candidate_commands:
                self.assertEqual(command[0:2], ["docker", "run"])
                self.assertIn("--network=none", command)
                self.assertIn("--read-only", command)
                self.assertIn("--cap-drop=ALL", command)
                self.assertIn("--security-opt=no-new-privileges", command)
                self.assertIn("--pids-limit=256", command)
                self.assertFalse(
                    any(
                        argument == "--pid" or argument.startswith("--pid=") for argument in command
                    )
                )
                self.assertIn("--env=PYTHONSAFEPATH=1", command)
                self.assertFalse(any("GITHUB" in argument for argument in command))
                self.assertFalse(any("ACTIONS" in argument for argument in command))
            source_commands = {
                check["id"]: check["command"] for check in source_evidence["checks"]
            }
            source_container_commands = {
                check_id: command
                for check_id, command in source_commands.items()
                if command[0:2] == ["docker", "run"]
                and any(
                    argument.startswith("python:") and "@sha256:" in argument
                    for argument in command
                )
            }
            self.assertEqual(
                set(source_container_commands),
                {
                    "isolated_child_imports",
                    "cli_surface_inventory",
                    "workflow_catalog",
                    "ruff",
                    "pytest",
                    "pyrefly_strict",
                    "schema_parity",
                },
            )
            for command in source_container_commands.values():
                image = next(
                    argument
                    for argument in command
                    if argument.startswith("python:") and "@sha256:" in argument
                )
                self.assertEqual(image, source_image)
            for check_id in (
                "isolated_child_imports",
                "cli_surface_inventory",
                "workflow_catalog",
                "pytest",
                "schema_parity",
            ):
                isolated_site_mount = next(
                    argument
                    for argument in source_commands[check_id]
                    if "dst=/usr/local/lib/python" in argument
                    and argument.endswith("/site-packages,readonly")
                )
                self.assertIn(
                    f"dst=/usr/local/lib/python{source_python_minor}/site-packages,readonly",
                    isolated_site_mount,
                )
                workspace_mount = next(
                    argument
                    for argument in source_commands[check_id]
                    if "dst=/workspace" in argument
                )
                self.assertTrue(workspace_mount.endswith(",readonly"))
            for check_id, tool in (("ruff", "ruff"), ("pyrefly_strict", "pyrefly")):
                command = source_commands[check_id]
                tools_mount = next(
                    argument for argument in command if "dst=/opt/fork-ops/bin" in argument
                )
                self.assertTrue(tools_mount.endswith(",readonly"))
                image_index = next(
                    index
                    for index, argument in enumerate(command)
                    if argument.startswith("python:") and "@sha256:" in argument
                )
                self.assertEqual(command[image_index + 1], f"/opt/fork-ops/bin/{tool}")
            self.assertEqual(
                source_commands["pyrefly_strict"][-2:],
                ["--site-package-path", "/opt/fork-ops/site-packages"],
            )
            pyrefly_site_packages = next(
                argument
                for argument in source_commands["pyrefly_strict"]
                if "dst=/opt/fork-ops/site-packages" in argument
            )
            self.assertTrue(pyrefly_site_packages.endswith(",readonly"))
            pytest_command = source_commands["pytest"]
            self.assertIn(
                "--tmpfs=/test-tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
                pytest_command,
            )
            self.assertIn("--env=TMPDIR=/test-tmp", pytest_command)
            self.assertIn(
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
                pytest_command,
            )
            for check_id, command in source_container_commands.items():
                if check_id == "pytest":
                    continue
                self.assertNotIn(
                    "--tmpfs=/test-tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
                    command,
                )
                self.assertNotIn("--env=TMPDIR=/test-tmp", command)

    def test_hosted_locked_workspace_modes_keep_the_closed_source_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(
                fixture_root,
                reject_disabled_locked_workspace_sources=True,
            )
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
            artifact_dir = fixture_root / "candidate"
            for mode in ("locked-source", "build", "installed"):
                with self.subTest(mode=mode):
                    output = fixture_root / f"{mode}.json"
                    arguments = [
                        sys.executable,
                        str(VALIDATION_ENTRYPOINT),
                        "--mode",
                        mode,
                        "--interpreter",
                        sys.executable,
                        "--repo",
                        str(repo),
                        "--execution-boundary",
                        "container",
                        "--output",
                        str(output),
                    ]
                    if mode in {"build", "installed"}:
                        arguments.extend(("--artifact-dir", str(artifact_dir)))
                    completed = subprocess.run(
                        arguments,
                        check=False,
                        capture_output=True,
                        text=True,
                        env=env,
                    )
                    self.assertEqual(
                        completed.returncode,
                        0,
                        completed.stderr + output.read_text(encoding="utf-8"),
                    )

    def test_locked_workspace_modes_reject_unsafe_sources_before_uv(self) -> None:
        unsafe_project_replacements = {
            "package-mode": ("pyproject.toml", "package = false", "package = true"),
            "default-groups": (
                "pyproject.toml",
                'default-groups = ["test", "development"]',
                'default-groups = ["build"]',
            ),
            "tool-source": (
                "pyproject.toml",
                'fork-ops = { workspace = true }',
                'fork-ops = { git = "https://example.invalid/fork-ops" }',
            ),
            "direct-path": (
                "pyproject.toml",
                '"fork-ops[mcp]"',
                '"fork-ops[mcp]@../fork-ops"',
            ),
            "root-python-range": (
                "pyproject.toml",
                'requires-python = ">=3.11"',
                'requires-python = ">=3.12"',
            ),
            "package-python-range": (
                "plugins/fork-ops/pyproject.toml",
                'requires-python = ">=3.11"',
                'requires-python = ">=3.12"',
            ),
        }
        for source_kind, (project_path, before, after) in unsafe_project_replacements.items():
            for mode in ("locked-source", "build", "installed"):
                with (
                    self.subTest(source_kind=source_kind, mode=mode),
                    tempfile.TemporaryDirectory() as temp_dir,
                ):
                    fixture_root = Path(temp_dir)
                    repo = self._create_fixture_repository(fixture_root)
                    project = repo / project_path
                    project.write_text(
                        project.read_text(encoding="utf-8").replace(before, after),
                        encoding="utf-8",
                    )
                    sentinel = fixture_root / "uv-executed"
                    fake_bin = self._create_fake_uv(
                        fixture_root,
                        operation_sentinel=sentinel,
                    )
                    output = fixture_root / f"{mode}.json"
                    artifact_dir = fixture_root / "candidate"
                    arguments = [
                        sys.executable,
                        str(VALIDATION_ENTRYPOINT),
                        "--mode",
                        mode,
                        "--interpreter",
                        sys.executable,
                        "--repo",
                        str(repo),
                        "--execution-boundary",
                        "container",
                        "--output",
                        str(output),
                    ]
                    if mode in {"build", "installed"}:
                        artifact_dir.mkdir()
                        arguments.extend(("--artifact-dir", str(artifact_dir)))
                    if mode == "installed":
                        (artifact_dir / "fork_ops-0.1-py3-none-any.whl").write_bytes(b"wheel")
                        (artifact_dir / "fork_ops-0.1.tar.gz").write_bytes(b"sdist")
                    env = os.environ.copy()
                    env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

                    completed = subprocess.run(
                        arguments,
                        check=False,
                        capture_output=True,
                        text=True,
                        env=env,
                    )

                    self.assertEqual(completed.returncode, 1)
                    evidence = json.loads(output.read_text(encoding="utf-8"))
                    self.assertIn(
                        "closed workspace",
                        evidence["checks"][-1]["stderr_tail"].lower(),
                    )
                    self.assertFalse(sentinel.exists(), "uv executed after unsafe source policy")

    def test_locked_source_emits_reusable_terminal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root)
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr + output_path.read_text(encoding="utf-8"),
            )
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["artifact_kind"], "validation_evidence_result")
            self.assertEqual(evidence["schema_version"], "1.0")
            self.assertEqual(evidence["mode"], "locked-source")
            self.assertEqual(evidence["outcome"], "passed")
            self.assertEqual(
                evidence["assurance_boundary"],
                {
                    "security_authority": False,
                    "security_evidence_envelope": False,
                    "scope": "repository_owned_observational_validation",
                },
            )
            self.assertEqual(
                [check["id"] for check in evidence["checks"]],
                [
                    "lock_integrity",
                    "package_scope_inventory",
                    "cli_surface_inventory",
                    "workflow_catalog",
                    "ruff",
                    "pytest",
                    "pyrefly_strict",
                    "schema_parity",
                    "diff_hygiene",
                ],
            )
            self.assertTrue(all(check["status"] == "passed" for check in evidence["checks"]))
            scope_inventory = next(
                check for check in evidence["checks"] if check["id"] == "package_scope_inventory"
            )
            scope_exports = [
                command
                for command in scope_inventory["commands"]
                if command[:2] == ["uv", "export"]
            ]
            marker_projections = [
                command
                for command in scope_inventory["commands"]
                if command[:3] == ["uv", "pip", "compile"]
            ]
            self.assertEqual(len(scope_exports), 20)
            self.assertTrue(all("--python" not in command for command in scope_exports))
            self.assertEqual(len(marker_projections), 20)
            self.assertEqual(
                {
                    minor: sum(
                        command[command.index("--python-version") + 1] == minor
                        for command in marker_projections
                    )
                    for minor in ("3.11", "3.12", "3.13", "3.14")
                },
                {"3.11": 5, "3.12": 5, "3.13": 5, "3.14": 5},
            )
            self.assertTrue(
                all(check["required_ids"] for check in evidence["checks"]),
                "every behavior-class claim must name the contract IDs it checks",
            )
            pytest_check = next(check for check in evidence["checks"] if check["id"] == "pytest")
            self.assertEqual(
                pytest_check["required_ids"],
                ["pytest.plugins/fork-ops/tests", "coverage.production_modules"],
            )
            self.assertEqual(
                pytest_check["coverage"]["policy"],
                "collected_without_numeric_threshold",
            )
            self.assertEqual(pytest_check["coverage"]["totals"]["num_statements"], 8)
            self.assertEqual(pytest_check["coverage"]["totals"]["covered_lines"], 8)
            self.assertEqual(len(pytest_check["coverage"]["summary_sha256"]), 64)
            for check in evidence["checks"][2:6]:
                if check["id"] in {"ruff", "pytest", "pyrefly_strict", "schema_parity"}:
                    self.assertIn(
                        ["--group", "test", "--group", "development"],
                        [
                            check["command"][index : index + 4]
                            for index in range(len(check["command"]))
                        ],
                    )
            self.assertEqual(len(evidence["identity"]["commit_sha"]), 40)
            self.assertEqual(len(evidence["identity"]["lock_sha256"]), 64)
            self.assertEqual(len(evidence["reuse_key"]), 64)
            self.assertEqual(
                evidence["behavior_coverage"]["policy"],
                "collected_without_numeric_threshold",
            )
            self.assertTrue(evidence["behavior_coverage"]["claims"])
            inventories = evidence["dependency_provenance"]["package_scopes_by_python"]
            self.assertEqual(list(inventories), ["3.11", "3.12", "3.13", "3.14"])
            for inventory in inventories.values():
                self.assertTrue(all(name == name.lower() for name in inventory))
                self.assertEqual(
                    {scope for scopes in inventory.values() for scope in scopes},
                    {"runtime", "optional", "build", "test", "development"},
                )
                self.assertEqual(inventory["jsonschema"], ["runtime"])
                self.assertEqual(inventory["mcp"], ["optional"])
                self.assertEqual(inventory["setuptools"], ["build"])
                self.assertEqual(inventory["pytest"], ["test"])
                self.assertEqual(inventory["pyrefly"], ["development"])
            self.assertEqual(
                len(evidence["dependency_provenance"]["package_scope_inventory_sha256"]),
                64,
            )
            cli_inventory = next(
                check for check in evidence["checks"] if check["id"] == "cli_surface_inventory"
            )
            self.assertEqual(
                cli_inventory["leaves"],
                [
                    "capability report",
                    "config init",
                    "config show",
                    "config validate",
                    "migration assess",
                    "migration dry-run",
                    "migration execute",
                    "migration explain-blocker",
                    "migration plan",
                    "migration preflight",
                    "migration propose-config",
                    "plugin health",
                    "schema check",
                    "schema print",
                    "workflow catalog",
                    "workflow inventory",
                ],
            )
            workflow_catalog = next(
                check for check in evidence["checks"] if check["id"] == "workflow_catalog"
            )
            self.assertEqual(
                list(workflow_catalog["contracts"]),
                [
                    "authority-source-routing",
                    "blocker-resolution",
                    "carried-divergence-review",
                    "fork-authority-migration",
                    "guarded-sync-execution",
                    "operator-onboarding",
                    "publication-closeout",
                    "review-preparation",
                    "upstream-status-assessment",
                    "upstream-sync-planning",
                    "workflow-migration-inventory",
                ],
            )
            self.assertEqual(
                workflow_catalog["coverage_kind"],
                "catalog_contract_discovery_not_execution",
            )
            self.assertEqual(
                workflow_catalog["contracts"]["guarded-sync-execution"],
                {"available": False, "implementation_status": "planned"},
            )
            self.assertIn("runtime", inventories["3.11"]["typing-extensions"])
            self.assertNotIn(
                "runtime",
                inventories["3.14"].get("typing-extensions", []),
            )
            self.assertEqual(evidence["producer"]["identity"], "local")
            self.assertEqual(
                evidence["producer"]["test_contract"],
                evidence["identity"]["test_contract"],
            )

    def test_workflow_pinned_uv_projects_universal_lock_markers_per_minor(self) -> None:
        uv = shutil.which("uv")
        if uv is None:
            self.skipTest("The candidate container intentionally does not contain uv")
        version = subprocess.run(
            [uv, "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        if version.returncode != 0 or version.stdout.strip().split()[:2] != ["uv", "0.12.3"]:
            self.skipTest("This integration regression requires workflow-pinned uv 0.12.3")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            locked = root / "runtime-locked.txt"
            environment = {
                "HOME": str(root / "home"),
                "PATH": os.defpath,
                "UV_CACHE_DIR": str(root / "cache"),
                "UV_DEFAULT_INDEX": "https://pypi.org/simple",
                "UV_INDEX_STRATEGY": "first-index",
                "UV_KEYRING_PROVIDER": "disabled",
                "UV_NO_CONFIG": "1",
                "UV_NO_PROGRESS": "1",
                "UV_PYTHON_DOWNLOADS": "never",
            }
            export = subprocess.run(
                [
                    uv,
                    "export",
                    "--locked",
                    "--package",
                    "fork-ops",
                    "--no-dev",
                    "--no-default-groups",
                    "--no-emit-project",
                    "--no-emit-workspace",
                    "--no-annotate",
                    "--no-header",
                    "--output-file",
                    str(locked),
                ],
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(export.returncode, 0, export.stderr)
            for minor in ("3.11", "3.12", "3.13", "3.14"):
                with self.subTest(minor=minor):
                    projected = root / f"runtime-{minor}.txt"
                    compile_result = subprocess.run(
                        [
                            uv,
                            "pip",
                            "compile",
                            str(locked),
                            "--python-version",
                            minor,
                            "--python-platform",
                            "linux",
                            "--no-deps",
                            "--no-header",
                            "--no-annotate",
                            "--generate-hashes",
                            "--output-file",
                            str(projected),
                        ],
                        cwd=REPOSITORY_ROOT,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
                    includes_typing_extensions = "typing-extensions==" in projected.read_text(
                        encoding="utf-8"
                    )
                    self.assertEqual(includes_typing_extensions, minor in {"3.11", "3.12"})

    def test_workflow_pinned_uv_osv_service_url_is_a_base_url(self) -> None:
        uv = shutil.which("uv")
        if uv is None:
            self.skipTest("uv is not installed")
        version = subprocess.run(
            [uv, "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        if version.returncode != 0 or version.stdout.strip().split()[:2] != ["uv", "0.12.3"]:
            self.skipTest("This integration regression requires workflow-pinned uv 0.12.3")

        requested_paths: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                requested_paths.append(self.path)
                length = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(length))
                response = json.dumps(
                    {"results": [{} for _ in request.get("queries", [])]}
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            @override
            def log_message(self, format: str, *args: object) -> None:
                del format, args

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host = str(server.server_address[0])
            port = int(server.server_address[1])
            completed = subprocess.run(
                [
                    uv,
                    "audit",
                    "--locked",
                    "--no-config",
                    "--no-build",
                    "--service-url",
                    f"http://{host}:{port}",
                    "--output-format",
                    "json",
                    "--python-platform",
                    "linux",
                    "--python-version",
                    "3.11",
                ],
                cwd=REPOSITORY_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(requested_paths, ["/v1/querybatch"])

    def test_child_failure_still_emits_terminal_aggregate_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root, fail_when="ruff")
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
            env.update(
                {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_WORKFLOW_REF": (
                        "owner/repo/.github/workflows/validation.yml@refs/heads/main"
                    ),
                    "GITHUB_WORKFLOW_SHA": self._git_commit(repo),
                    "GITHUB_RUN_ID": "12345",
                    "GITHUB_RUN_ATTEMPT": "1",
                }
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "failed")
            ruff = next(check for check in evidence["checks"] if check["id"] == "ruff")
            self.assertEqual(ruff["status"], "failed")
            self.assertEqual(ruff["exit_code"], 7)
            self.assertEqual(evidence["checks"][-1]["id"], "diff_hygiene")
            self.assertEqual(evidence["checks"][-1]["status"], "passed")

    def test_invalid_interpreter_still_emits_terminal_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root)
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    str(fixture_root / "missing-python"),
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "failed")
            self.assertEqual(
                evidence["identity"]["interpreter"]["requested"],
                str(fixture_root / "missing-python"),
            )
            self.assertEqual(evidence["checks"][-1]["id"], "evidence_finalization")
            self.assertEqual(evidence["checks"][-1]["status"], "failed")

    def test_fresh_source_resolves_and_audits_only_a_temporary_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            original_lock = (repo / "uv.lock").read_text(encoding="utf-8")
            fake_bin = self._create_fake_uv(fixture_root, assert_clean_environment=True)
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
            env.update(
                {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_WORKFLOW_REF": (
                        "owner/repo/.github/workflows/validation.yml@refs/heads/main"
                    ),
                    "GITHUB_WORKFLOW_SHA": self._git_commit(repo),
                    "GITHUB_RUN_ID": "12345",
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_TOKEN": "must-not-cross-fresh-source-boundary",
                    "ACTIONS_RUNTIME_TOKEN": "must-not-cross-fresh-source-boundary",
                    "SERVICE_SECRET": "must-not-cross-fresh-source-boundary",
                }
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "fresh-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr + output_path.read_text(encoding="utf-8"),
            )
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(
                [check["id"] for check in evidence["checks"]],
                [
                    "fresh_resolution",
                    "dependency_audit_matrix",
                    "lock_integrity",
                    "package_scope_inventory",
                    "cli_surface_inventory",
                    "workflow_catalog",
                    "ruff",
                    "pytest",
                    "pyrefly_strict",
                    "schema_parity",
                    "diff_hygiene",
                ],
            )
            audit = evidence["checks"][1]
            self.assertEqual(audit["status"], "passed")
            self.assertEqual(
                audit["required_ids"],
                [
                    "audit.osv.python.3.11",
                    "audit.osv.python.3.12",
                    "audit.osv.python.3.13",
                    "audit.osv.python.3.14",
                ],
            )
            self.assertEqual(audit["evidence"]["status"], "available")
            self.assertEqual(audit["evidence"]["advisories"], [])
            self.assertEqual(len(audit["evidence_sha256"]), 64)
            self.assertEqual(
                [
                    check["id"]
                    for check in evidence["checks"]
                    if check["id"] != "diff_hygiene"
                    and check.get("environment_policy") != "explicit_minimal"
                ],
                [],
            )
            self.assertEqual((repo / "uv.lock").read_text(encoding="utf-8"), original_lock)
            self.assertNotEqual(
                evidence["identity"]["lock_sha256"],
                self._sha256(repo / "uv.lock"),
            )

    def test_candidate_git_configuration_cannot_execute_host_fsmonitor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            sentinel = fixture_root / "candidate-fsmonitor-executed"
            fsmonitor = fixture_root / "candidate-fsmonitor"
            fsmonitor.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    from pathlib import Path

                    Path({str(sentinel)!r}).write_text("executed", encoding="utf-8")
                    print("builtin:fake")
                    """
                ),
                encoding="utf-8",
            )
            fsmonitor.chmod(0o755)
            subprocess.run(
                ["git", "-C", str(repo), "config", "core.fsmonitor", str(fsmonitor)],
                check=True,
            )
            fake_bin = self._create_fake_uv(fixture_root)
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(sentinel.exists(), "candidate fsmonitor executed on the host")

    def test_fresh_source_never_executes_candidate_audit_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            sentinel = fixture_root / "candidate-audit-adapter-executed"
            candidate_module = (
                repo / "plugins" / "fork-ops" / "src" / "fork_ops" / "dependency_security.py"
            )
            candidate_module.write_text(
                textwrap.dedent(
                    f"""\
                    from pathlib import Path

                    Path({str(sentinel)!r}).write_text("executed", encoding="utf-8")

                    class ForgedEvidence:
                        def to_dict(self):
                            return {{"status": "available", "advisories": []}}

                    def collect_uv_audit_evidence(*args, **kwargs):
                        return ForgedEvidence()
                    """
                ),
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(repo), "add", str(candidate_module)], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", "malicious audit adapter"],
                check=True,
            )
            fake_bin = self._create_fake_uv(fixture_root)
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
            env.update(
                {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_WORKFLOW_REF": (
                        "owner/repo/.github/workflows/validation.yml@refs/heads/main"
                    ),
                    "GITHUB_WORKFLOW_SHA": self._git_commit(repo),
                    "GITHUB_RUN_ID": "12345",
                    "GITHUB_RUN_ATTEMPT": "1",
                }
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "fresh-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            audit = next(
                check
                for check in evidence["checks"]
                if check["id"] == "dependency_audit_matrix"
            )
            self.assertEqual(audit["status"], "passed", completed.stderr)
            self.assertFalse(sentinel.exists(), "candidate audit adapter executed on the host")
            self.assertEqual(audit["evidence"]["provenance"]["source_observation"]["page_count"], 4)
            self.assertEqual(len(audit["provider_requests"]), 4)

    def test_fresh_source_rejects_candidate_network_sources_before_uv_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            (repo / "uv.toml").write_text(
                'index-url = "http://169.254.169.254/latest/meta-data"\n',
                encoding="utf-8",
            )
            sentinel = fixture_root / "uv-executed"
            fake_bin = self._create_fake_uv(fixture_root, operation_sentinel=sentinel)
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
            env.update(
                {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_WORKFLOW_REF": (
                        "owner/repo/.github/workflows/validation.yml@refs/heads/main"
                    ),
                    "GITHUB_WORKFLOW_SHA": self._git_commit(repo),
                    "GITHUB_RUN_ID": "12345",
                    "GITHUB_RUN_ATTEMPT": "1",
                }
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "fresh-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["checks"][0]["id"], "fresh_resolution")
            self.assertIn("rejects candidate uv config", evidence["checks"][0]["stderr_tail"])
            self.assertFalse(sentinel.exists(), "uv executed after unsafe source policy")

    def test_explicit_diff_base_checks_committed_candidate_range(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            base = self._git_commit(repo)
            (repo / "candidate.txt").write_text("trailing whitespace   \n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "candidate.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", "candidate"],
                check=True,
            )
            fake_bin = self._create_fake_uv(fixture_root)
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--diff-base",
                    base,
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            diff_check = evidence["checks"][-1]
            self.assertEqual(diff_check["id"], "diff_hygiene")
            self.assertEqual(diff_check["status"], "failed")
            self.assertEqual(diff_check["command"][-1], f"{base}...HEAD")
            self.assertIn("trailing whitespace", diff_check["stdout_tail"])

    def test_local_diff_hygiene_checks_staged_and_nonignored_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            (repo / "staged.txt").write_text("staged trailing whitespace   \n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "staged.txt"], check=True)
            (repo / "untracked.txt").write_text(
                "untracked trailing whitespace\t\n",
                encoding="utf-8",
            )
            fake_bin = self._create_fake_uv(fixture_root)
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            diff_check = json.loads(output_path.read_text(encoding="utf-8"))["checks"][-1]
            self.assertEqual(diff_check["id"], "diff_hygiene")
            self.assertEqual(diff_check["status"], "failed")
            self.assertIn("staged.txt", diff_check["stdout_tail"])
            self.assertIn("untracked.txt", diff_check["stdout_tail"])

    def test_successful_pytest_requires_coverage_data_and_measured_production_files(self) -> None:
        for coverage_mode in ("missing-data", "no-production-files"):
            with (
                self.subTest(coverage_mode=coverage_mode),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                fixture_root = Path(temp_dir)
                repo = self._create_fixture_repository(fixture_root)
                fake_bin = self._create_fake_uv(fixture_root, coverage_mode=coverage_mode)
                output_path = fixture_root / "validation-evidence.json"
                env = os.environ.copy()
                env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

                completed = subprocess.run(
                    [
                        sys.executable,
                        str(VALIDATION_ENTRYPOINT),
                        "--mode",
                        "locked-source",
                        "--interpreter",
                        sys.executable,
                        "--repo",
                        str(repo),
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                )

                self.assertEqual(completed.returncode, 1)
                evidence = json.loads(output_path.read_text(encoding="utf-8"))
                pytest_check = next(
                    check for check in evidence["checks"] if check["id"] == "pytest"
                )
                self.assertEqual(pytest_check["status"], "failed")
                self.assertIn("coverage", pytest_check["stderr_tail"].lower())

    def test_command_timeout_emits_terminal_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root, delay_when="ruff")
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--command-timeout-seconds",
                    "0.5",
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "failed")
            ruff = next(check for check in evidence["checks"] if check["id"] == "ruff")
            self.assertEqual(ruff["status"], "failed")
            self.assertTrue(ruff["timed_out"])
            self.assertEqual(ruff["exit_code"], 124)

    def test_overall_timeout_bounds_terminal_evidence_production(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root, delay_when="lock")
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            started = __import__("time").monotonic()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--command-timeout-seconds",
                    "5",
                    "--overall-timeout-seconds",
                    "0.1",
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
                timeout=5,
            )
            elapsed = __import__("time").monotonic() - started

            self.assertLess(elapsed, 1.5)
            self.assertEqual(
                completed.returncode,
                124,
                completed.stderr + output_path.read_text(encoding="utf-8"),
            )
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "failed")
            self.assertTrue(any(check["timed_out"] for check in evidence["checks"]))

    def test_overall_timeout_interrupts_source_snapshot_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            large_source = repo / "large-source.bin"
            with large_source.open("wb") as source:
                source.truncate(16 * 1024 * 1024)
            fake_bin = self._create_fake_uv(fixture_root, delay_when="export")
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            started = time.monotonic()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "build",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(fixture_root / "candidate"),
                    "--overall-timeout-seconds",
                    "0.1",
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
                timeout=5,
            )
            elapsed = time.monotonic() - started

            self.assertLess(elapsed, 1.0)
            self.assertEqual(
                completed.returncode,
                124,
                completed.stderr + output_path.read_text(encoding="utf-8"),
            )
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "failed")
            finalization = evidence["checks"][-1]
            self.assertEqual(finalization["id"], "evidence_finalization")
            self.assertTrue(finalization["timed_out"])
            self.assertIn("overall deadline", finalization["stderr_tail"].lower())

    def test_build_mode_emits_once_built_wheel_and_sdist_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(
                fixture_root,
                reject_disabled_candidate_build=True,
            )
            artifact_dir = fixture_root / "candidate"
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "build",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "passed")
            self.assertEqual(
                [check["id"] for check in evidence["checks"]],
                ["build_constraints", "build_dependency_audit", "build_distributions"],
            )
            build_check = evidence["checks"][-1]
            self.assertIn("--build-constraints", build_check["command"])
            self.assertIn("--require-hashes", build_check["command"])
            self.assertEqual(
                evidence["dependency_provenance"]["build"]["scope"],
                "pep517_build_isolation",
            )
            self.assertEqual(len(evidence["dependency_provenance"]["build"]["sha256"]), 64)
            self.assertEqual(
                [artifact["filename"] for artifact in evidence["identity"]["artifacts"]],
                ["fork_ops-0.1-py3-none-any.whl", "fork_ops-0.1.tar.gz"],
            )
            self.assertTrue(
                all(len(artifact["sha256"]) == 64 for artifact in evidence["identity"]["artifacts"])
            )

    def test_build_mode_rejects_an_open_candidate_artifact_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root, extra_artifact=True)
            artifact_dir = fixture_root / "candidate"
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "build",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            build_check = evidence["checks"][-1]
            self.assertEqual(build_check["id"], "build_distributions")
            self.assertEqual(build_check["status"], "failed")
            self.assertIn("unexpected.txt", build_check["stderr_tail"])
            self.assertEqual(evidence["identity"]["artifacts"], [])

    @unittest.skipIf(os.name == "nt", "The fake uv boundary uses POSIX executable launchers.")
    def test_installed_mode_checks_simulated_cli_schema_and_mcp_process_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root)
            selected_interpreter = fake_bin / "selected-python"
            selected_interpreter.symlink_to(sys.executable)
            artifact_dir = fixture_root / "candidate"
            artifact_dir.mkdir()
            (artifact_dir / "fork_ops-0.1-py3-none-any.whl").write_bytes(b"wheel")
            (artifact_dir / "fork_ops-0.1.tar.gz").write_bytes(b"sdist")
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "installed",
                    "--interpreter",
                    selected_interpreter.name,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "passed")
            resolved_interpreter = evidence["identity"]["interpreter"]["resolved"]
            self.assertEqual(resolved_interpreter, str(Path(sys.executable).resolve()))
            for check_id in ("clean_environment", "runtime_constraints"):
                check = next(check for check in evidence["checks"] if check["id"] == check_id)
                python_index = check["command"].index("--python") + 1
                self.assertEqual(check["command"][python_index], resolved_interpreter)
            self.assertEqual(
                [check["id"] for check in evidence["checks"]],
                [
                    "clean_environment",
                    "runtime_constraints",
                    "sync_runtime_dependencies",
                    "install_wheel",
                    "installed_dependency_check",
                    "installed_graph",
                    "installed_cli",
                    "installed_schema",
                    "mcp_protocol",
                ],
            )
            install_check = next(
                check for check in evidence["checks"] if check["id"] == "install_wheel"
            )
            self.assertIn("--no-deps", install_check["command"])
            self.assertIn("--no-index", install_check["command"])
            sync_check = next(
                check for check in evidence["checks"] if check["id"] == "sync_runtime_dependencies"
            )
            self.assertIn("--require-hashes", sync_check["command"])
            runtime = evidence["dependency_provenance"]["runtime"]
            self.assertEqual(runtime["scope"], "fork-ops[mcp]_runtime")
            self.assertEqual(len(runtime["requirements_sha256"]), 64)
            self.assertEqual(len(runtime["installed_graph_sha256"]), 64)
            self.assertIn("fork-ops==0.1", runtime["installed_distributions"])
            self.assertRegex(evidence["producer"]["uv"]["version"], r"^uv ")
            mcp_check = evidence["checks"][-1]
            self.assertEqual(mcp_check["protocol"]["call"], "fork_ops_schema")
            self.assertEqual(mcp_check["protocol"]["shutdown"], "clean")
            self.assertEqual(
                mcp_check["protocol"]["tools"],
                [
                    "fork_ops_capability_report",
                    "fork_ops_config_read",
                    "fork_ops_config_validate",
                    "fork_ops_equipment_migration_preflight",
                    "fork_ops_migration_assessment",
                    "fork_ops_migration_blocker_resolution",
                    "fork_ops_migration_config_patch",
                    "fork_ops_migration_dry_run",
                    "fork_ops_migration_execute",
                    "fork_ops_migration_plan",
                    "fork_ops_plugin_health",
                    "fork_ops_schema",
                    "fork_ops_workflow_catalog",
                    "fork_ops_workflow_migration_inventory",
                ],
            )

    @unittest.skipIf(os.name == "nt", "The fake uv boundary uses POSIX executable launchers.")
    def test_installed_candidate_processes_receive_only_explicit_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root, assert_clean_environment=True)
            artifact_dir = fixture_root / "candidate"
            artifact_dir.mkdir()
            (artifact_dir / "fork_ops-0.1-py3-none-any.whl").write_bytes(b"wheel")
            (artifact_dir / "fork_ops-0.1.tar.gz").write_bytes(b"sdist")
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
            env.update(
                {
                    "GITHUB_TOKEN": "github-secret",
                    "ACTIONS_RUNTIME_TOKEN": "runtime-secret",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "identity-secret",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.invalid",
                    "ACTIONS_RUNTIME_URL": "https://runtime.invalid",
                    "ACTIONS_CACHE_URL": "https://cache.invalid",
                    "ACTIONS_RESULTS_URL": "https://results.invalid",
                    "MY_API_TOKEN": "arbitrary-token",
                    "SERVICE_SECRET": "arbitrary-secret",
                    "DATABASE_PASSWORD": "arbitrary-password",
                    "CLOUD_CREDENTIAL": "arbitrary-credential",
                }
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "installed",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "passed")
            self.assertTrue(
                all(
                    check.get("environment_policy") == "explicit_minimal"
                    for check in evidence["checks"]
                )
            )

    def test_installed_mode_refuses_candidate_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root)
            artifact_dir = fixture_root / "candidate"
            artifact_dir.mkdir()
            (artifact_dir / "fork_ops-0.1-py3-none-any.whl").write_bytes(b"wheel")
            (artifact_dir / "fork_ops-0.1.tar.gz").write_bytes(b"sdist")
            build_evidence = fixture_root / "build-evidence.json"
            build_evidence.write_text(
                json.dumps(
                    {
                        "artifact_kind": "validation_evidence_result",
                        "schema_version": "1.0",
                        "mode": "build",
                        "outcome": "passed",
                        "identity": {
                            "commit_sha": self._git_commit(repo),
                            "source_tree": "dirty",
                            "source_snapshot_sha256": "0" * 64,
                            "lock_sha256": self._sha256(repo / "uv.lock"),
                            "artifacts": [
                                {
                                    "filename": path.name,
                                    "kind": "wheel" if path.suffix == ".whl" else "sdist",
                                    "sha256": "0" * 64,
                                    "size": path.stat().st_size,
                                }
                                for path in sorted(artifact_dir.iterdir())
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "installed",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--build-evidence",
                    str(build_evidence),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "failed")
            self.assertEqual([check["id"] for check in evidence["checks"]], ["candidate_identity"])
            self.assertEqual(evidence["checks"][0]["status"], "failed")
            self.assertIn("source_snapshot_sha256", evidence["checks"][0]["stderr_tail"])

    def test_failed_release_preflight_never_executes_candidate_without_build_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            verifier_entrypoint, trusted_verifier_sha = (
                self._create_verifier_repository(fixture_root)
            )
            fake_bin = self._create_fake_uv(fixture_root)
            artifact_dir = fixture_root / "candidate"
            artifact_dir.mkdir()
            (artifact_dir / "fork_ops-0.1-py3-none-any.whl").write_bytes(b"wheel")
            (artifact_dir / "fork_ops-0.1.tar.gz").write_bytes(b"sdist")
            preflight = fixture_root / "invalid-preflight.json"
            preflight.write_text("{}", encoding="utf-8")
            output_path = fixture_root / "installed-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(verifier_entrypoint),
                    "--mode",
                    "installed",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--release-preflight-evidence",
                    str(preflight),
                    "--trusted-release-workflow-ref",
                    "owner/repo/.github/workflows/release-validation.yml@refs/heads/main",
                    "--trusted-release-workflow-sha",
                    trusted_verifier_sha,
                    "--trusted-release-workflow-path",
                    ".github/workflows/release-validation.yml",
                    "--trusted-verifier-repository",
                    "owner/repo",
                    "--trusted-verifier-sha",
                    trusted_verifier_sha,
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "failed")
            self.assertEqual(
                [check["id"] for check in evidence["checks"]],
                ["release_preflight_inputs"],
            )
            self.assertNotIn("clean_environment", completed.stdout)

    def test_release_trust_binds_api_and_producer_before_wheel_execution(
        self,
    ) -> None:
        for mismatch in (
            "",
            "api_event",
            "api_status",
            "api_conclusion",
            "api_head_sha",
            "api_head_branch",
            "api_workflow_path",
            "api_stale",
            "api_future",
            "api_superseded",
            "latest_incomplete_page",
            "artifact_expired",
            "artifact_stale",
            "artifact_future",
            "artifact_missing_digest",
            "artifact_duplicate",
            "artifact_wrong_head",
            "artifact_wrong_branch",
            "artifact_incomplete_page",
            "producer_attempt",
            "producer_repository",
            "producer_workflow_sha",
            "producer_contract",
            "release_candidate_sha",
            "release_workflow_ref",
            "release_workflow_sha",
            "release_workflow_path",
            "verifier_repository",
            "verifier_sha",
            "dispatch_unvalidated_workflow",
            "handoff_tamper",
        ):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as temp_dir:
                fixture_root = Path(temp_dir)
                repo = self._create_fixture_repository(fixture_root)
                verifier_entrypoint, trusted_verifier_sha = (
                    self._create_verifier_repository(fixture_root)
                )
                fake_bin = self._create_fake_uv(fixture_root)
                commit_sha = self._git_commit(repo)
                run_id = "12345"
                run_attempt = "2"
                build_env = os.environ.copy()
                build_env["PATH"] = os.pathsep.join((str(fake_bin), build_env["PATH"]))
                build_env.update(
                    {
                        "GITHUB_REPOSITORY": "owner/repo",
                        "GITHUB_RUN_ID": run_id,
                        "GITHUB_RUN_ATTEMPT": run_attempt,
                        "GITHUB_WORKFLOW_REF": (
                            "owner/repo/.github/workflows/validation.yml@refs/heads/main"
                        ),
                        "GITHUB_WORKFLOW_SHA": commit_sha,
                        "GITHUB_EVENT_NAME": "push",
                        "GITHUB_SHA": commit_sha,
                    }
                )
                root = fixture_root / "built"
                build_evidence = self._run_fixture_build(repo, root, build_env)
                build_evidence_path = root / "build-evidence.json"
                producer_mismatches = {
                    "producer_attempt": ("run_attempt", "1"),
                    "producer_repository": ("repository", "attacker/repo"),
                    "producer_workflow_sha": ("workflow_sha", "f" * 40),
                    "producer_contract": ("test_contract", "untrusted-contract/build"),
                }
                if mismatch in producer_mismatches:
                    producer = build_evidence.get("producer")
                    self.assertIsInstance(producer, dict)
                    assert isinstance(producer, dict)
                    key, value = producer_mismatches[mismatch]
                    producer[key] = value
                    build_evidence_path.write_text(json.dumps(build_evidence), encoding="utf-8")

                run_payload: dict[str, Any] = {
                    "id": int(run_id),
                    "run_attempt": int(run_attempt),
                    "name": "Validation",
                    "path": (
                        ".github/workflows/other.yml"
                        if mismatch == "api_workflow_path"
                        else ".github/workflows/validation.yml"
                    ),
                    "event": "pull_request" if mismatch == "api_event" else "push",
                    "status": "in_progress" if mismatch == "api_status" else "completed",
                    "conclusion": ("failure" if mismatch == "api_conclusion" else "success"),
                    "head_sha": "e" * 40 if mismatch == "api_head_sha" else commit_sha,
                    "head_branch": ("candidate" if mismatch == "api_head_branch" else "main"),
                    "repository": {"full_name": "owner/repo"},
                    "head_repository": {"full_name": "owner/repo"},
                    "created_at": (
                        datetime.now(UTC) - timedelta(days=2)
                        if mismatch == "api_stale"
                        else datetime.now(UTC) + timedelta(minutes=5)
                        if mismatch == "api_future"
                        else datetime.now(UTC) - timedelta(minutes=10)
                    )
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "run_started_at": (datetime.now(UTC) - timedelta(minutes=9))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "updated_at": (datetime.now(UTC) - timedelta(minutes=2))
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
                artifact_payloads = [
                    {
                        "id": 1,
                        "name": name,
                        "expired": mismatch == "artifact_expired" and name == "candidate-dist",
                        "created_at": (
                            datetime.now(UTC) - timedelta(days=2)
                            if mismatch == "artifact_stale" and name == "candidate-dist"
                            else datetime.now(UTC) + timedelta(minutes=5)
                            if mismatch == "artifact_future" and name == "candidate-dist"
                            else datetime.now(UTC) - timedelta(minutes=5)
                        )
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "updated_at": (datetime.now(UTC) - timedelta(minutes=3))
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "expires_at": (datetime.now(UTC) + timedelta(days=30))
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "digest": (
                            None
                            if mismatch == "artifact_missing_digest" and name == "candidate-dist"
                            else "sha256:" + str(1 if name == "candidate-dist" else 2) * 64
                        ),
                        "workflow_run": {
                            "id": int(run_id),
                            "head_sha": (
                                "d" * 40
                                if mismatch == "artifact_wrong_head" and name == "candidate-dist"
                                else commit_sha
                            ),
                            "head_branch": (
                                "candidate"
                                if mismatch == "artifact_wrong_branch" and name == "candidate-dist"
                                else "main"
                            ),
                        },
                    }
                    for name in ("candidate-dist", "validation-evidence-build")
                ]
                if mismatch == "artifact_duplicate":
                    artifact_payloads.append(dict(artifact_payloads[0], id=3))
                artifacts_payload: dict[str, Any] = {
                    "total_count": (
                        len(artifact_payloads) + 1
                        if mismatch == "artifact_incomplete_page"
                        else len(artifact_payloads)
                    ),
                    "artifacts": artifact_payloads,
                }
                latest_runs = [run_payload]
                if mismatch == "api_superseded":
                    latest_runs = [
                        {
                            **run_payload,
                            "id": 54321,
                            "run_attempt": 1,
                            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        },
                        run_payload,
                    ]
                runs_payload = {
                    "total_count": len(latest_runs)
                    + (1 if mismatch == "latest_incomplete_page" else 0),
                    "workflow_runs": latest_runs,
                }
                api_url, server, thread = self._serve_github_api(
                    run_id,
                    run_payload,
                    artifacts_payload,
                    runs_payload,
                )
                try:
                    preflight_output = fixture_root / "release-preflight-evidence.json"
                    preflight_key = fixture_root / "trusted-state" / "release-preflight.key"
                    trusted_release_workflow_ref = (
                        "verifier/repo/.github/workflows/other-release.yml@refs/heads/main"
                        if mismatch == "release_workflow_ref"
                        else "owner/repo/.github/workflows/release-validation.yml@refs/heads/main"
                        if mismatch == "dispatch_unvalidated_workflow"
                        else "verifier/repo/.github/workflows/release-validation.yml"
                        "@refs/heads/main"
                    )
                    trusted_release_workflow_sha = (
                        "c" * 40 if mismatch == "release_workflow_sha" else trusted_verifier_sha
                    )
                    trusted_release_workflow_path = (
                        ".github/workflows/other-release.yml"
                        if mismatch == "release_workflow_path"
                        else ".github/workflows/release-validation.yml"
                    )
                    trusted_verifier_repository = (
                        "attacker/repo"
                        if mismatch == "verifier_repository"
                        else "owner/repo"
                        if mismatch == "dispatch_unvalidated_workflow"
                        else "verifier/repo"
                    )
                    preflight_env = build_env | {
                        "GITHUB_TOKEN": "read-only-test-token",
                        "GITHUB_API_URL": api_url,
                        "GITHUB_RUN_ID": "54321",
                        "GITHUB_RUN_ATTEMPT": "1",
                        "GITHUB_WORKFLOW_REF": (
                            "owner/repo/.github/workflows/caller.yml@refs/heads/main"
                        ),
                        "GITHUB_WORKFLOW_SHA": "d" * 40,
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "GITHUB_SHA": (
                            "b" * 40 if mismatch == "release_candidate_sha" else commit_sha
                        ),
                    }
                    verifier_argument = (
                        "a" * 40 if mismatch == "verifier_sha" else trusted_verifier_sha
                    )
                    preflight = subprocess.run(
                        [
                            sys.executable,
                            str(verifier_entrypoint),
                            "--mode",
                            "release-preflight",
                            "--interpreter",
                            sys.executable,
                            "--repo",
                            str(repo),
                            "--artifact-dir",
                            str(root / "candidate"),
                            "--build-evidence",
                            str(build_evidence_path),
                            "--trusted-main-run-id",
                            run_id,
                            "--trusted-main-run-attempt",
                            run_attempt,
                            "--trusted-release-workflow-ref",
                            trusted_release_workflow_ref,
                            "--trusted-release-workflow-sha",
                            trusted_release_workflow_sha,
                            "--trusted-release-workflow-path",
                            trusted_release_workflow_path,
                            "--trusted-verifier-repository",
                            trusted_verifier_repository,
                            "--trusted-verifier-sha",
                            verifier_argument,
                            "--release-preflight-key-file",
                            str(preflight_key),
                            "--output",
                            str(preflight_output),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        env=preflight_env,
                    )
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

                preflight_evidence = json.loads(preflight_output.read_text(encoding="utf-8"))
                if mismatch and mismatch != "handoff_tamper":
                    self.assertEqual(preflight.returncode, 1)
                    self.assertEqual(
                        [check["id"] for check in preflight_evidence["checks"]],
                        ["release_trust"],
                    )
                    self.assertNotIn("clean_environment", preflight.stdout)
                else:
                    self.assertEqual(preflight.returncode, 0, preflight.stderr)
                    self.assertEqual(
                        [check["id"] for check in preflight_evidence["checks"]],
                        ["release_trust", "candidate_identity"],
                    )
                    installed_output = fixture_root / "installed-evidence.json"
                    installed_env = dict(preflight_env)
                    installed_env.pop("GITHUB_TOKEN")
                    if mismatch == "handoff_tamper":
                        preflight_evidence["dependency_provenance"]["release"]["run_id"] = "999"
                        preflight_output.write_text(
                            json.dumps(preflight_evidence),
                            encoding="utf-8",
                        )
                    installed = subprocess.run(
                        [
                            sys.executable,
                            str(verifier_entrypoint),
                            "--mode",
                            "installed",
                            "--interpreter",
                            sys.executable,
                            "--repo",
                            str(repo),
                            "--artifact-dir",
                            str(root / "candidate"),
                            "--build-evidence",
                            str(build_evidence_path),
                            "--release-preflight-evidence",
                            str(preflight_output),
                            "--trusted-release-workflow-ref",
                            trusted_release_workflow_ref,
                            "--trusted-release-workflow-sha",
                            trusted_release_workflow_sha,
                            "--trusted-release-workflow-path",
                            trusted_release_workflow_path,
                            "--trusted-verifier-repository",
                            trusted_verifier_repository,
                            "--trusted-verifier-sha",
                            trusted_verifier_sha,
                            "--release-preflight-key-file",
                            str(preflight_key),
                            "--output",
                            str(installed_output),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        env=installed_env,
                    )
                    if mismatch == "handoff_tamper":
                        self.assertEqual(installed.returncode, 1)
                        self.assertFalse(preflight_key.exists())
                        evidence = json.loads(installed_output.read_text(encoding="utf-8"))
                        self.assertEqual(
                            [check["id"] for check in evidence["checks"]],
                            ["release_preflight"],
                        )
                        self.assertIn("preflight_receipt", evidence["checks"][0]["stderr_tail"])
                        continue
                    self.assertEqual(installed.returncode, 0, installed.stderr)
                    self.assertFalse(preflight_key.exists())
                    evidence = json.loads(installed_output.read_text(encoding="utf-8"))
                    self.assertEqual(evidence["checks"][0]["id"], "release_preflight")
                    self.assertEqual(evidence["checks"][1]["id"], "candidate_identity")
                    self.assertIn(
                        "clean_environment",
                        [check["id"] for check in evidence["checks"]],
                    )
                    container_checks = [
                        check
                        for check in evidence["checks"]
                        if check["id"]
                        in {
                            "container_python_identity",
                            "installed_graph",
                            "installed_cli",
                            "installed_schema",
                            "mcp_protocol",
                        }
                    ]
                    self.assertEqual(len(container_checks), 5)
                    expected_minor = f"{sys.version_info.major}.{sys.version_info.minor}"
                    expected_image = {
                        "3.11": "python:3.11-slim@sha256:"
                        "90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff",
                        "3.12": "python:3.12-slim@sha256:"
                        "229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36",
                        "3.13": "python:3.13-slim@sha256:"
                        "ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a",
                        "3.14": "python:3.14-slim@sha256:"
                        "a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc",
                    }[expected_minor]
                    for check in container_checks:
                        command = check["command"]
                        self.assertEqual(command[:2], ["docker", "run"])
                        self.assertIn("--network=none", command)
                        self.assertIn("--read-only", command)
                        self.assertIn("--cap-drop=ALL", command)
                        self.assertIn("--security-opt=no-new-privileges", command)
                        self.assertIn("--pids-limit=256", command)
                        self.assertFalse(
                            any(
                                argument == "--pid" or argument.startswith("--pid=")
                                for argument in command
                            )
                        )
                        self.assertIn("--user=65532:65532", command)
                        self.assertIn(expected_image, command)
                        self.assertEqual(
                            check["environment_policy"],
                            "container_explicit_minimal",
                        )
                    self.assertEqual(
                        evidence["dependency_provenance"]["release"]["run_id"],
                        run_id,
                    )
                    self.assertFalse(evidence["assurance_boundary"]["security_authority"])

                    replay_output = fixture_root / "replayed-installed-evidence.json"
                    replay_argv = list(installed.args)
                    replay_argv[replay_argv.index(str(installed_output))] = str(replay_output)
                    replayed = subprocess.run(
                        replay_argv,
                        check=False,
                        capture_output=True,
                        text=True,
                        env=installed_env,
                    )
                    self.assertEqual(replayed.returncode, 1)
                    replay_evidence = json.loads(replay_output.read_text(encoding="utf-8"))
                    self.assertEqual(
                        [check["id"] for check in replay_evidence["checks"]],
                        ["release_preflight"],
                    )
                    self.assertEqual(replay_evidence["checks"][0]["status"], "failed")

    def test_dirty_source_build_identity_survives_outputs_but_rejects_source_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            (repo / "dirty-source.py").write_text("VALUE = 1\n", encoding="utf-8")
            fake_bin = self._create_fake_uv(fixture_root)
            artifact_dir = repo / "candidate"
            build_evidence = repo / "validation-evidence-build.json"
            installed_evidence = repo / "validation-evidence-installed.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            built = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "build",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--output",
                    str(build_evidence),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(built.returncode, 0, built.stderr)

            installed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "installed",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--build-evidence",
                    str(build_evidence),
                    "--output",
                    str(installed_evidence),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            installed_result = json.loads(installed_evidence.read_text(encoding="utf-8"))
            self.assertEqual(installed_result["checks"][0]["status"], "passed")

            (repo / "dirty-source.py").write_text("VALUE = 2\n", encoding="utf-8")
            changed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "installed",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--artifact-dir",
                    str(artifact_dir),
                    "--build-evidence",
                    str(build_evidence),
                    "--output",
                    str(installed_evidence),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(changed.returncode, 1)
            changed_result = json.loads(installed_evidence.read_text(encoding="utf-8"))
            self.assertIn(
                "source_snapshot_sha256",
                changed_result["checks"][0]["stderr_tail"],
            )

    @unittest.skipIf(os.name == "nt", "This test exercises POSIX symlinks.")
    def test_source_snapshot_rejects_symlinks_without_reading_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            outside = fixture_root / "outside-secret"
            outside.write_bytes(b"first-secret")
            (repo / "outside-link").symlink_to(outside)
            fake_bin = self._create_fake_uv(fixture_root)
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))
            output = fixture_root / "evidence.json"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertIn("rejects symlink", evidence["checks"][0]["stderr_tail"])
            self.assertEqual(outside.read_bytes(), b"first-secret")

    @unittest.skipIf(os.name == "nt", "This test exercises POSIX dirfd semantics.")
    def test_source_snapshot_rejects_a_parent_swap_to_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            nested = repo / "nested"
            nested.mkdir()
            (nested / "source.py").write_bytes(b"candidate")
            outside = fixture_root / "outside"
            outside.mkdir()
            (outside / "source.py").write_bytes(b"external!")
            namespace = runpy.run_path(str(VALIDATION_ENTRYPOINT))
            snapshotter = namespace["_verified_execution_snapshot"]
            original_open = os.open
            swapped = False

            def swapping_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if (
                    not swapped
                    and path == "nested"
                    and dir_fd is not None
                    and flags & os.O_DIRECTORY
                ):
                    displaced = repo / "nested-original"
                    nested.rename(displaced)
                    nested.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(os, "open", side_effect=swapping_open),
                self.assertRaises(OSError),
                snapshotter(repo, (repo / "uv.lock").read_bytes(), []),
            ):
                self.fail("a swapped parent directory must fail before yielding")
            self.assertTrue(swapped)

    @unittest.skipIf(os.name == "nt", "This test exercises POSIX dirfd semantics.")
    def test_candidate_root_binding_spans_identity_snapshot_and_diff_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            namespace = runpy.run_path(str(VALIDATION_ENTRYPOINT))
            bind = namespace["_bind_candidate_repository"]
            verify = namespace["_verify_candidate_repository_binding"]
            snapshotter = namespace["_verified_execution_snapshot"]
            git_commit = namespace["_git_commit"]
            descriptor, bound_repo, identity = bind(repo)
            original_commit = git_commit(bound_repo)
            displaced = fixture_root / "displaced-repo"
            try:
                with snapshotter(
                    repo,
                    (bound_repo / "uv.lock").read_bytes(),
                    [],
                    bound_root_descriptor=descriptor,
                ) as (snapshot, _digest):
                    repo.rename(displaced)
                    replacement = self._create_fixture_repository(fixture_root)
                    (replacement / "replacement.txt").write_text("replacement\n")
                    subprocess.run(["git", "-C", str(replacement), "add", "."], check=True)
                    subprocess.run(
                        ["git", "-C", str(replacement), "commit", "-qm", "replacement"],
                        check=True,
                    )
                    self.assertEqual(repo, replacement)
                    self.assertEqual(git_commit(bound_repo), original_commit)
                    self.assertNotEqual(self._git_commit(replacement), original_commit)
                    self.assertTrue((snapshot / "pyproject.toml").is_file())
                    with self.assertRaisesRegex(RuntimeError, "root changed"):
                        verify(repo, descriptor, identity)
            finally:
                os.close(descriptor)

    def test_validation_rejects_lock_symlinks_before_hashing_or_running_uv(self) -> None:
        for target_kind in ("outside", "in-tree"):
            with self.subTest(target_kind=target_kind), tempfile.TemporaryDirectory() as temp_dir:
                fixture_root = Path(temp_dir)
                repo = self._create_fixture_repository(fixture_root)
                fake_bin = self._create_fake_uv(fixture_root)
                lock_path = repo / "uv.lock"
                lock_path.unlink()
                if target_kind == "outside":
                    target = fixture_root / "outside.lock"
                    target.write_text("version = 1\n", encoding="utf-8")
                else:
                    target = repo / "other.lock"
                    target.write_text("version = 1\n", encoding="utf-8")
                lock_path.symlink_to(target)
                output_path = fixture_root / "validation-evidence.json"
                env = os.environ.copy()
                env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

                completed = subprocess.run(
                    [
                        sys.executable,
                        str(VALIDATION_ENTRYPOINT),
                        "--mode",
                        "locked-source",
                        "--interpreter",
                        sys.executable,
                        "--repo",
                        str(repo),
                        "--output",
                        str(output_path),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                )

                self.assertEqual(completed.returncode, 1)
                evidence = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    [check["id"] for check in evidence["checks"]],
                    ["evidence_finalization"],
                )
                self.assertIn("regular non-symlink", evidence["checks"][0]["stderr_tail"])

    @unittest.skipIf(os.name == "nt", "This test requires POSIX symlink semantics.")
    def test_validation_refuses_a_symlink_evidence_output_without_overwriting_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root)
            outside_target = fixture_root / "outside-target.txt"
            outside_target.write_text("preserve me\n", encoding="utf-8")
            output_path = fixture_root / "validation-evidence.json"
            output_path.symlink_to(outside_target)
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(outside_target.read_text(encoding="utf-8"), "preserve me\n")

    @unittest.skipIf(os.name == "nt", "This test requires POSIX symlink semantics.")
    def test_validation_refuses_a_symlink_evidence_output_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            fake_bin = self._create_fake_uv(fixture_root)
            outside_directory = fixture_root / "outside"
            outside_directory.mkdir()
            output_parent = fixture_root / "linked-output"
            output_parent.symlink_to(outside_directory, target_is_directory=True)
            output_path = output_parent / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((outside_directory / output_path.name).exists())

    def test_uv_never_receives_a_symlink_bearing_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            repo = self._create_fixture_repository(fixture_root)
            outside = fixture_root / "outside-source.py"
            outside.write_text("VALUE = 'outside'\n", encoding="utf-8")
            (repo / "checkout-controlled-source.py").symlink_to(outside)
            fake_bin = self._create_fake_uv(
                fixture_root,
                reject_candidate_repo_cwd=True,
            )
            output_path = fixture_root / "validation-evidence.json"
            env = os.environ.copy()
            env["PATH"] = os.pathsep.join((str(fake_bin), env["PATH"]))

            completed = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATION_ENTRYPOINT),
                    "--mode",
                    "locked-source",
                    "--interpreter",
                    sys.executable,
                    "--repo",
                    str(repo),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            evidence = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["outcome"], "failed")
            self.assertIn("rejects symlink", evidence["checks"][0]["stderr_tail"])

    def test_workflows_expose_one_pinned_validation_contract(self) -> None:
        workflow_paths = (
            REPOSITORY_ROOT / ".github" / "workflows" / "validation.yml",
            REPOSITORY_ROOT / ".github" / "workflows" / "release-validation.yml",
        )
        workflows = [path.read_text(encoding="utf-8") for path in workflow_paths]
        action_references = [
            reference
            for workflow in workflows
            for reference in re.findall(
                r"^\s*- uses: (\S+)(?:\s+#.*)?$",
                workflow,
                flags=re.MULTILINE,
            )
        ]

        self.assertTrue(action_references)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) for ref in action_references))
        self.assertIn("  pull_request_target:\n", workflows[0])
        self.assertNotIn("  pull_request:\n", workflows[0])
        self.assertIn(
            "activates only after this workflow exists on the default branch",
            workflows[0],
        )
        ordinary_producers = re.findall(
            r"python (\S*produce_validation_evidence\.py)",
            workflows[0],
        )
        self.assertTrue(ordinary_producers)
        self.assertTrue(
            all(
                producer == "trusted-verifier/scripts/produce_validation_evidence.py"
                for producer in ordinary_producers
            )
        )
        self.assertNotIn("python scripts/produce_validation_evidence.py", workflows[0])
        self.assertGreaterEqual(workflows[0].count("path: trusted-verifier"), 6)
        self.assertGreaterEqual(workflows[0].count("path: candidate"), 6)
        self.assertGreaterEqual(workflows[0].count("--repo candidate"), 6)
        self.assertGreaterEqual(workflows[0].count("--execution-boundary container"), 3)
        self.assertGreaterEqual(
            workflows[0].count("--execution-boundary local-observational"),
            3,
        )
        self.assertIn("\n  validation:\n    name: Validation\n", workflows[0])
        self.assertIn("\n  validation:\n    name: Release Validation\n", workflows[1])
        self.assertNotIn("\n  validation:\n    name: Validation\n", workflows[1])
        self.assertIn('\'["3.11","3.14"]\'', workflows[0])
        self.assertIn('\'["3.11","3.12","3.13","3.14"]\'', workflows[0])
        self.assertIn("fetch-depth: 0", workflows[0])
        self.assertIn('--diff-base "$DIFF_BASE"', workflows[0])
        self.assertEqual(workflows[0].count("\n    continue-on-error: true\n"), 3)
        self.assertIn("steps.advisory_run.outcome", workflows[0])
        self.assertIn("needs.advisory.outputs.outcome", workflows[0])
        self.assertIn("|| 'not_observed'", workflows[0])
        self.assertGreaterEqual(workflows[0].count("timeout-minutes:"), 5)
        self.assertGreaterEqual(workflows[1].count("timeout-minutes:"), 2)
        self.assertIn("artifact_run_attempt:", workflows[1])
        self.assertIn("--trusted-main-run-id", workflows[1])
        self.assertIn("--trusted-main-run-attempt", workflows[1])
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", workflows[1])
        self.assertIn("TRUSTED_MAIN_RUN_ID: ${{ inputs.artifact_run_id }}", workflows[1])
        self.assertIn(
            "TRUSTED_MAIN_RUN_ATTEMPT: ${{ inputs.artifact_run_attempt }}",
            workflows[1],
        )
        self.assertIn("TRUSTED_ARTIFACT_NAME: ${{ inputs.artifact_name }}", workflows[1])
        verifier_run = (
            workflows[1]
            .split("        run: >-", maxsplit=1)[1]
            .split(
                "      - name: Upload release evidence",
                maxsplit=1,
            )[0]
        )
        self.assertNotIn("${{ inputs.", verifier_run)
        self.assertIn('--trusted-main-run-id "$TRUSTED_MAIN_RUN_ID"', verifier_run)
        self.assertIn(
            '--trusted-main-run-attempt "$TRUSTED_MAIN_RUN_ATTEMPT"',
            verifier_run,
        )
        self.assertIn('--trusted-artifact-name "$TRUSTED_ARTIFACT_NAME"', verifier_run)
        self.assertIn("--trusted-workflow-path .github/workflows/validation.yml", workflows[1])
        self.assertIn("--trusted-event push", workflows[1])
        self.assertIn("path: trusted-verifier", workflows[1])
        self.assertIn("path: candidate", workflows[1])
        self.assertIn("repository: ${{ job.workflow_repository }}", workflows[1])
        self.assertIn("ref: ${{ job.workflow_sha }}", workflows[1])
        self.assertNotIn("ref: refs/heads/main", workflows[1])
        self.assertNotIn("github.workflow_sha", workflows[1])
        self.assertIn("TRUSTED_RELEASE_WORKFLOW_REF: ${{ job.workflow_ref }}", workflows[1])
        self.assertIn("TRUSTED_RELEASE_WORKFLOW_SHA: ${{ job.workflow_sha }}", workflows[1])
        self.assertIn(
            "TRUSTED_RELEASE_WORKFLOW_PATH: ${{ job.workflow_file_path }}",
            workflows[1],
        )
        self.assertIn("--mode release-preflight", workflows[1])
        self.assertIn("--release-preflight-evidence", workflows[1])
        self.assertEqual(workflows[1].count("--release-preflight-key-file"), 2)
        self.assertIn("${{ runner.temp }}/trusted-state", workflows[1])
        self.assertIn("--trusted-release-workflow-ref", workflows[1])
        self.assertIn("--trusted-release-workflow-sha", workflows[1])
        self.assertIn("--trusted-release-workflow-path", workflows[1])
        self.assertIn("--trusted-verifier-repository", workflows[1])
        self.assertIn("--trusted-verifier-sha", workflows[1])
        self.assertEqual(workflows[1].count("GITHUB_TOKEN: ${{ github.token }}"), 1)
        self.assertIn("${{ runner.temp }}/candidate/*.whl", workflows[0])
        self.assertIn("${{ runner.temp }}/candidate/*.tar.gz", workflows[0])
        self.assertNotIn("path: ${{ runner.temp }}/candidate/\n", workflows[0])
        self.assertIn(
            "python trusted-verifier/scripts/produce_validation_evidence.py",
            workflows[1],
        )
        self.assertIn("--repo candidate", workflows[1])
        for python_version in ("3.11", "3.12", "3.13", "3.14"):
            self.assertIn(f'- "{python_version}"', workflows[1])

    def test_actionlint_filter_is_limited_to_new_job_workflow_identity_fields(
        self,
    ) -> None:
        actionlint = shutil.which("actionlint")
        if actionlint is None:
            self.skipTest("actionlint is not installed")
        workflow_paths = [
            str(REPOSITORY_ROOT / ".github" / "workflows" / "validation.yml"),
            str(REPOSITORY_ROOT / ".github" / "workflows" / "release-validation.yml"),
        ]
        raw = subprocess.run(
            [actionlint, "-format", "{{json .}}", *workflow_paths],
            check=False,
            capture_output=True,
            text=True,
        )
        diagnostics = json.loads(raw.stdout or "[]")
        unsupported_job_identity = re.compile(
            r'^property "workflow_(?:ref|sha|repository|file_path)" '
            r"is not defined in object type"
        )
        unexpected = [
            diagnostic
            for diagnostic in diagnostics
            if not unsupported_job_identity.search(diagnostic["message"])
        ]
        self.assertEqual(unexpected, [])

        filtered = subprocess.run(
            [
                actionlint,
                "-ignore",
                unsupported_job_identity.pattern,
                *workflow_paths,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(filtered.returncode, 0, filtered.stdout + filtered.stderr)

    def test_build_isolation_requirements_are_explicit_workspace_lock_inputs(self) -> None:
        for pyproject in (
            REPOSITORY_ROOT / "pyproject.toml",
            REPOSITORY_ROOT / "plugins" / "fork-ops" / "pyproject.toml",
        ):
            content = pyproject.read_text(encoding="utf-8")
            self.assertRegex(content, r"(?ms)^build = \[.*setuptools==.*wheel==.*^\]")
            self.assertRegex(content, r"(?ms)^test = \[.*coverage.*pytest.*^\]")
            self.assertRegex(
                content,
                r"(?ms)^development = \[.*pyrefly.*ruff.*types-jsonschema.*^\]",
            )
        root_content = (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('default-groups = ["test", "development"]', root_content)
        plugin_project = tomllib.loads(
            (REPOSITORY_ROOT / "plugins" / "fork-ops" / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            plugin_project["build-system"]["requires"],
            ["setuptools==83.0.0", "wheel==0.46.2"],
        )
        lock = (REPOSITORY_ROOT / "uv.lock").read_text(encoding="utf-8")
        self.assertRegex(lock, r'(?m)^name = "setuptools"$')
        self.assertRegex(lock, r'(?m)^name = "wheel"$')

    def test_fake_uv_rejects_wrong_locked_export_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_root = Path(temp_dir)
            fake_uv = self._create_fake_uv(fixture_root) / "uv"
            output = fixture_root / "requirements.txt"

            completed = subprocess.run(
                [
                    str(fake_uv),
                    "export",
                    "--locked",
                    "--package",
                    "not-fork-ops",
                    "--no-dev",
                    "--no-default-groups",
                    "--no-emit-project",
                    "--no-emit-workspace",
                    "--no-annotate",
                    "--no-header",
                    "--output-file",
                    str(output),
                    "--python",
                    "3.11",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 97)
            self.assertIn("unexpected fake uv export argv", completed.stderr)

    def _create_fixture_repository(self, fixture_root: Path) -> Path:
        repo = fixture_root / "repo"
        schema_dir = repo / "plugins" / "fork-ops" / "schema"
        packaged_schema_dir = repo / "plugins" / "fork-ops" / "src" / "fork_ops"
        tests_dir = repo / "plugins" / "fork-ops" / "tests"
        schema_dir.mkdir(parents=True)
        packaged_schema_dir.mkdir(parents=True)
        tests_dir.mkdir(parents=True)
        (repo / "scripts").mkdir()
        (repo / "pyproject.toml").write_bytes((REPOSITORY_ROOT / "pyproject.toml").read_bytes())
        (repo / "plugins" / "fork-ops" / "pyproject.toml").write_bytes(
            (REPOSITORY_ROOT / "plugins" / "fork-ops" / "pyproject.toml").read_bytes()
        )
        (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
        schema = (
            REPOSITORY_ROOT / "plugins" / "fork-ops" / "schema" / "fork-ops.schema.json"
        ).read_text(encoding="utf-8")
        (schema_dir / "fork-ops.schema.json").write_text(schema, encoding="utf-8")
        (packaged_schema_dir / "fork-ops.schema.json").write_text(schema, encoding="utf-8")
        (packaged_schema_dir / "__init__.py").write_text("", encoding="utf-8")
        (packaged_schema_dir.parent / "sitecustomize.py").write_text(
            "raise SystemExit('candidate sitecustomize executed')\n",
            encoding="utf-8",
        )
        package_source_dir = REPOSITORY_ROOT / "plugins" / "fork-ops" / "src" / "fork_ops"
        for source_name in (
            "dependency_security.py",
            "security_exceptions.py",
            "security-exception-contract-1.0.json",
        ):
            (packaged_schema_dir / source_name).write_bytes(
                (package_source_dir / source_name).read_bytes()
            )
        (tests_dir / "test_fixture.py").write_text("def test_fixture():\n    assert True\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Validation Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "validation@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        return repo

    def _create_verifier_repository(self, fixture_root: Path) -> tuple[Path, str]:
        verifier = fixture_root / "verifier"
        entrypoint = verifier / "scripts" / "produce_validation_evidence.py"
        entrypoint.parent.mkdir(parents=True)
        shutil.copy2(VALIDATION_ENTRYPOINT, entrypoint)
        subprocess.run(["git", "init", "-q", str(verifier)], check=True)
        subprocess.run(
            ["git", "-C", str(verifier), "config", "user.name", "Validation Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(verifier),
                "config",
                "user.email",
                "validation@example.invalid",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(verifier), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(verifier), "commit", "-qm", "trusted verifier"],
            check=True,
        )
        return entrypoint, self._git_commit(verifier)

    def _serve_github_api(
        self,
        run_id: str,
        run_payload: dict[str, Any],
        artifacts_payload: dict[str, Any],
        runs_payload: dict[str, Any] | None = None,
    ) -> tuple[str, http.server.ThreadingHTTPServer, threading.Thread]:
        payloads = {
            f"/repos/owner/repo/actions/runs/{run_id}": run_payload,
            f"/repos/owner/repo/actions/runs/{run_id}/artifacts?per_page=100": artifacts_payload,
            "/repos/owner/repo/actions/workflows/.github%2Fworkflows%2Fvalidation.yml/"
            "runs?branch=main&event=push&status=success&per_page=100": (
                runs_payload
                if runs_payload is not None
                else {"total_count": 1, "workflow_runs": [run_payload]}
            ),
        }

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                payload = payloads.get(self.path)
                if payload is None:
                    self.send_error(404)
                    return
                rendered = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(rendered)))
                self.end_headers()
                self.wfile.write(rendered)

            @override
            def log_message(self, format: str, *args: object) -> None:
                del format, args
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        address = server.server_address
        host = str(address[0])
        port = int(address[1])
        return f"http://{host}:{port}", server, thread

    def _create_fake_uv(
        self,
        fixture_root: Path,
        fail_when: str = "",
        *,
        coverage_mode: str = "complete",
        delay_when: str = "",
        extra_artifact: bool = False,
        assert_clean_environment: bool = False,
        reject_disabled_locked_workspace_sources: bool = False,
        reject_disabled_candidate_build: bool = False,
        reject_candidate_repo_cwd: bool = False,
        operation_sentinel: Path | None = None,
    ) -> Path:
        fake_bin = fixture_root / "bin"
        fake_bin.mkdir()
        fake_uv = fake_bin / "uv"
        operation_sentinel_literal = repr(
            str(operation_sentinel) if operation_sentinel is not None else ""
        )
        fake_uv.write_text(
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import os
                import sys
                import time

                operation_sentinel = {operation_sentinel_literal}
                if operation_sentinel and sys.argv[1:] != ["--version"]:
                    from pathlib import Path

                    Path(operation_sentinel).write_text(
                        "executed",
                        encoding="utf-8",
                    )

                if {reject_candidate_repo_cwd!r} and sys.argv[1:] != ["--version"]:
                    from pathlib import Path

                    if Path.cwd() == Path({str(fixture_root / "repo")!r}):
                        print("uv received the checkout-controlled project", file=sys.stderr)
                        raise SystemExit(96)
                    if any(path.is_symlink() for path in Path.cwd().rglob("*")):
                        print("uv received a symlink-bearing project", file=sys.stderr)
                        raise SystemExit(96)

                if {assert_clean_environment!r} and sys.argv[1:] != ["--version"]:
                    import os

                    forbidden = {{
                        name
                        for name in os.environ
                        if name.startswith(("GITHUB_", "ACTIONS_"))
                        or name.endswith(("_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL"))
                    }}
                    if forbidden:
                        print(
                            f"inherited forbidden environment: {{sorted(forbidden)!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(98)
                    required = {{"HOME", "PATH", "TMPDIR"}}
                    if not required.issubset(os.environ):
                        print(
                            "missing required environment: "
                            f"{{sorted(required - set(os.environ))!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(98)

                if {reject_disabled_locked_workspace_sources!r}:
                    import os

                    locked_workspace_command = (
                        len(sys.argv) > 1
                        and (
                            sys.argv[1] in {{"export", "run"}}
                            or sys.argv[1:3] == ["lock", "--check"]
                            or (
                                sys.argv[1] == "audit"
                                and "--no-sources" not in sys.argv
                            )
                        )
                    )
                    if locked_workspace_command and os.environ.get("UV_NO_SOURCES"):
                        print(
                            "closed workspace source was disabled for a locked command",
                            file=sys.stderr,
                        )
                        raise SystemExit(99)

                if (
                    {reject_disabled_candidate_build!r}
                    and sys.argv[1:2] == ["build"]
                    and os.environ.get("UV_NO_BUILD")
                ):
                    print("candidate package build was disabled", file=sys.stderr)
                    raise SystemExit(100)

                if {fail_when!r} and {fail_when!r} in sys.argv:
                    print("simulated validation failure", file=sys.stderr)
                    raise SystemExit(7)
                if {delay_when!r} and {delay_when!r} in sys.argv:
                    time.sleep(2)
                if sys.argv[1:] == ["--version"]:
                    print("uv 0.12.3 (fake validation boundary)")
                    raise SystemExit(0)
                tool_args = []
                if len(sys.argv) > 1 and sys.argv[1] == "run":
                    valid_prefix = (
                        len(sys.argv) >= 10
                        and sys.argv[1:5] == ["run", "--locked", "--exact", "--python"]
                        and sys.argv[6:10]
                        == ["--package", "fork-ops", "--extra", "mcp"]
                    )
                    if not valid_prefix:
                        print(
                            f"unexpected fake uv run argv: {{sys.argv[1:]!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    if sys.argv[10:14] == [
                        "--group",
                        "test",
                        "--group",
                        "development",
                    ]:
                        tool_args = sys.argv[14:]
                    else:
                        tool_args = sys.argv[10:]
                if len(sys.argv) > 1 and sys.argv[1] == "lock":
                    from pathlib import Path

                    lock_args = sys.argv[1:]
                    valid_lock = (
                        len(lock_args) == 4
                        and lock_args[:3] == ["lock", "--check", "--python"]
                    ) or (
                        len(lock_args) == 10
                        and lock_args[:10]
                        == [
                            "lock",
                            "--upgrade",
                            "--refresh",
                            "--no-config",
                            "--no-sources",
                            "--no-build",
                            "--default-index",
                            "https://pypi.org/simple",
                            "--python",
                            lock_args[-1],
                        ]
                    )
                    if not valid_lock:
                        print(
                            f"unexpected fake uv lock argv: {{lock_args!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    if "--upgrade" in sys.argv:
                        (Path.cwd() / "uv.lock").write_text("version = 2\\n")
                    raise SystemExit(0)
                if len(sys.argv) > 1 and sys.argv[1] == "venv":
                    import os
                    from pathlib import Path

                    if len(sys.argv) != 5 or sys.argv[2] != "--python":
                        print(
                            f"unexpected fake uv venv argv: {{sys.argv[1:]!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    target = Path(sys.argv[-1])
                    scripts = target / ("Scripts" if os.name == "nt" else "bin")
                    scripts.mkdir(parents=True)
                    python = scripts / ("python.exe" if os.name == "nt" else "python")
                    python.write_text(
                        f"#!{{sys.executable}}\\n"
                        "import json, os, sys\\n"
                        "if len(sys.argv) > 2 and 'from mcp import' in sys.argv[2]:\\n"
                        "    print(json.dumps({{\\n"
                        "        'protocol_version': '2025-11-25',\\n"
                        "        'tools': [\\n"
                        "            'fork_ops_capability_report',\\n"
                        "            'fork_ops_config_read',\\n"
                        "            'fork_ops_config_validate',\\n"
                        "            'fork_ops_equipment_migration_preflight',\\n"
                        "            'fork_ops_migration_assessment',\\n"
                        "            'fork_ops_migration_blocker_resolution',\\n"
                        "            'fork_ops_migration_config_patch',\\n"
                        "            'fork_ops_migration_dry_run',\\n"
                        "            'fork_ops_migration_execute',\\n"
                        "            'fork_ops_migration_plan',\\n"
                        "            'fork_ops_plugin_health',\\n"
                        "            'fork_ops_schema',\\n"
                        "            'fork_ops_workflow_catalog',\\n"
                        "            'fork_ops_workflow_migration_inventory',\\n"
                        "        ],\\n"
                        "        'call': 'fork_ops_schema',\\n"
                        "        'shutdown': 'clean',\\n"
                        "    }}))\\n"
                        "    raise SystemExit(0)\\n"
                        "if len(sys.argv) > 2 and 'importlib.metadata' in sys.argv[2]:\\n"
                        "    print(json.dumps({{'distributions': [\\n"
                        "        'fork-ops==0.1', 'jsonschema==4.0', 'mcp==1.29.0'\\n"
                        "    ]}}))\\n"
                        "    raise SystemExit(0)\\n"
                        f"os.execv({{sys.executable!r}}, [{{sys.executable!r}}, *sys.argv[1:]])\\n"
                    )
                    python.chmod(0o755)
                    for name in ("fork-ops", "fork-ops-mcp"):
                        launcher = scripts / name
                        launcher.write_text(
                            f"#!{{sys.executable}}\\n"
                            "import pathlib, sys\\n"
                            f"if {{name!r}} == 'fork-ops' and sys.argv[1:] == ['--help']:\\n"
                            "    print('usage: fork-ops')\\n"
                            "    raise SystemExit(0)\\n"
                            f"if {{name!r}} == 'fork-ops' and "
                            "sys.argv[1:] == ['schema', 'print']:\\n"
                            "    schema = pathlib.Path("
                            "'plugins/fork-ops/schema/fork-ops.schema.json'"
                            ")\\n"
                            "    print(schema.read_text(), end='')\\n"
                            "    raise SystemExit(0)\\n"
                            "raise SystemExit(97)\\n"
                        )
                        launcher.chmod(0o755)
                    raise SystemExit(0)
                if len(sys.argv) > 1 and sys.argv[1] == "export":
                    from pathlib import Path

                    export_args = sys.argv[1:]
                    if export_args.count("--output-file") != 1:
                        print(
                            f"unexpected fake uv export argv: {{export_args!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    output_value = export_args[export_args.index("--output-file") + 1]
                    scope_inventory_export = "fork-ops-package-scopes-" in output_value
                    if scope_inventory_export and "--python" in export_args:
                        print(
                            "scope inventory export unexpectedly required an installed interpreter",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    if not scope_inventory_export and export_args.count("--python") != 1:
                        print(
                            f"unexpected fake uv export argv: {{export_args!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    python_value = (
                        export_args[export_args.index("--python") + 1]
                        if "--python" in export_args
                        else None
                    )
                    if python_value is not None and python_value not in {{
                        sys.executable,
                        str(Path(sys.executable).resolve()),
                    }}:
                        print(
                            f"unexpected fake uv export argv: {{export_args!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    scope_tail = [
                        "--no-default-groups",
                        "--no-emit-project",
                        "--no-emit-workspace",
                        "--no-annotate",
                        "--no-header",
                        "--output-file",
                        output_value,
                    ]
                    runtime_tail = [
                        "--no-default-groups",
                        "--no-emit-workspace",
                        "--no-annotate",
                        "--no-header",
                        "--output-file",
                        output_value,
                    ]
                    if python_value is not None:
                        scope_tail.extend(("--python", python_value))
                        runtime_tail.extend(("--python", python_value))
                    valid_exports = [
                        [
                            "export",
                            "--locked",
                            "--package",
                            "fork-ops",
                            "--extra",
                            "mcp",
                            "--group",
                            "test",
                            "--group",
                            "development",
                            "--no-emit-project",
                            "--no-emit-workspace",
                            "--no-annotate",
                            "--no-header",
                            "--output-file",
                            output_value,
                            "--python",
                            python_value,
                        ],
                        [
                            "export",
                            "--locked",
                            "--package",
                            "fork-ops",
                            "--no-dev",
                            *scope_tail,
                        ],
                        [
                            "export",
                            "--locked",
                            "--package",
                            "fork-ops",
                            "--extra",
                            "mcp",
                            "--no-dev",
                            *scope_tail,
                        ],
                        [
                            "export",
                            "--locked",
                            "--only-group",
                            "build",
                            *scope_tail,
                        ],
                        [
                            "export",
                            "--locked",
                            "--package",
                            "fork-ops",
                            "--extra",
                            "mcp",
                            "--no-dev",
                            *runtime_tail,
                        ],
                    ]
                    valid_exports.extend(
                        [
                            "export",
                            "--locked",
                            "--package",
                            "fork-ops",
                            "--only-group",
                            group,
                            *scope_tail,
                        ]
                        for group in ("build", "test", "development")
                    )
                    if export_args not in valid_exports:
                        print(
                            f"unexpected fake uv export argv: {{export_args!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    output = Path(output_value)
                    if "--only-group" in export_args:
                        group = export_args[export_args.index("--only-group") + 1]
                        packages = {{
                            "build": ["setuptools==83.0.0", "wheel==0.46.2"],
                            "test": ["coverage==7.15.4", "pytest==9.0.3"],
                            "development": ["pyrefly==1.2.0", "ruff==0.15.13"],
                        }}.get(group)
                        if packages is None:
                            print(f"unexpected fake uv group: {{group}}", file=sys.stderr)
                            raise SystemExit(97)
                    else:
                        packages = [
                            "jsonschema==4.0",
                            "typing-extensions==4.15.0 ; python_full_version < '3.13'",
                        ]
                        if "--extra" in export_args:
                            packages.append("mcp==1.29.0")
                    requirements = "".join(
                        package + " --hash=sha256:" + str(index) * 64 + "\\n"
                        for index, package in enumerate(packages, start=1)
                    )
                    output.write_text(requirements)
                    raise SystemExit(0)
                if len(sys.argv) > 2 and sys.argv[1:3] == ["pip", "compile"]:
                    from pathlib import Path

                    expected = [
                        "pip",
                        "compile",
                        sys.argv[3],
                        "--python-version",
                        sys.argv[5],
                        "--python-platform",
                        "linux",
                        "--no-deps",
                        "--no-header",
                        "--no-annotate",
                        "--generate-hashes",
                        "--output-file",
                        sys.argv[-1],
                    ]
                    if len(sys.argv) != 14 or sys.argv[1:] != expected:
                        print(
                            f"unexpected fake uv pip compile argv: {{sys.argv[1:]!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    python_minor = sys.argv[5]
                    requirements = Path(sys.argv[3]).read_text().splitlines()
                    filtered = []
                    for requirement in requirements:
                        if (
                            requirement.startswith("typing-extensions")
                            and python_minor in {{"3.13", "3.14"}}
                        ):
                            continue
                        filtered.append(
                            requirement.replace(
                                " ; python_full_version < '3.13'",
                                "",
                            )
                        )
                    Path(sys.argv[-1]).write_text("\\n".join(filtered) + "\\n")
                    raise SystemExit(0)
                if len(sys.argv) > 2 and sys.argv[1:3] == ["pip", "sync"]:
                    import os

                    expected = [
                        "pip",
                        "sync",
                        "--python",
                        sys.argv[4],
                        "--strict",
                        "--require-hashes",
                        "--only-binary",
                        ":all:",
                        sys.argv[-1],
                    ]
                    if len(sys.argv) != 10 or sys.argv[1:] != expected:
                        print(
                            f"unexpected fake uv pip sync argv: {{sys.argv[1:]!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    if os.environ.get("GITHUB_TOKEN"):
                        print("candidate dependency sync inherited GITHUB_TOKEN", file=sys.stderr)
                        raise SystemExit(98)
                    raise SystemExit(0)
                if len(sys.argv) > 2 and sys.argv[1:3] == ["pip", "install"]:
                    import os

                    expected = [
                        "pip",
                        "install",
                        "--python",
                        sys.argv[4],
                        "--strict",
                        "--no-deps",
                        "--no-index",
                        "--only-binary",
                        ":all:",
                        sys.argv[-1],
                    ]
                    if len(sys.argv) != 11 or sys.argv[1:] != expected:
                        print(
                            f"unexpected fake uv pip install argv: {{sys.argv[1:]!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    if os.environ.get("GITHUB_TOKEN"):
                        print("candidate wheel install inherited GITHUB_TOKEN", file=sys.stderr)
                        raise SystemExit(98)
                    raise SystemExit(0)
                if len(sys.argv) > 2 and sys.argv[1:3] == ["pip", "check"]:
                    import os

                    expected = ["pip", "check", "--python", sys.argv[4]]
                    if len(sys.argv) != 5 or sys.argv[1:] != expected:
                        print(
                            f"unexpected fake uv pip check argv: {{sys.argv[1:]!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    if os.environ.get("GITHUB_TOKEN"):
                        print("candidate dependency check inherited GITHUB_TOKEN", file=sys.stderr)
                        raise SystemExit(98)
                    raise SystemExit(0)
                if len(sys.argv) > 1 and sys.argv[1] == "audit":
                    if "--output-format" in sys.argv:
                        import json

                        required = {{
                            "--locked",
                            "--no-config",
                            "--no-build",
                            "--output-format",
                            "--python-platform",
                            "--python-version",
                        }}
                        if not required.issubset(sys.argv):
                            print(
                                f"unexpected fake uv audit argv: {{sys.argv[1:]!r}}",
                                file=sys.stderr,
                            )
                            raise SystemExit(97)
                        if sys.argv[sys.argv.index("--output-format") + 1] != "json":
                            print("unexpected fake uv audit format", file=sys.stderr)
                            raise SystemExit(97)
                        expected = [
                            "audit",
                            "--locked",
                            "--no-config",
                            "--no-build",
                            "--default-index",
                            "https://pypi.org/simple",
                            "--index-strategy",
                            "first-index",
                            "--keyring-provider",
                            "disabled",
                            "--service-url",
                            "https://api.osv.dev",
                            "--output-format",
                            "json",
                            "--python-platform",
                            "linux",
                            "--python-version",
                            sys.argv[-1],
                        ]
                        if len(sys.argv) != 19 or sys.argv[1:] != expected:
                            print(
                                f"unexpected fake uv audit argv: {{sys.argv[1:]!r}}",
                                file=sys.stderr,
                            )
                            raise SystemExit(97)
                        print(json.dumps({{"vulnerabilities": [], "adverse_statuses": []}}))
                    else:
                        expected = [
                            "audit",
                            "--locked",
                            "--only-group",
                            "build",
                            "--python-version",
                            sys.argv[-1],
                        ]
                        if len(sys.argv) != 7 or sys.argv[1:] != expected:
                            print(
                                f"unexpected fake uv build audit argv: {{sys.argv[1:]!r}}",
                                file=sys.stderr,
                            )
                            raise SystemExit(97)
                    raise SystemExit(0)
                if len(sys.argv) > 1 and sys.argv[1] == "build":
                    from pathlib import Path

                    expected = [
                        "build",
                        "--package",
                        "fork-ops",
                        "--python",
                        sys.argv[5],
                        "--build-constraints",
                        sys.argv[7],
                        "--require-hashes",
                        "--out-dir",
                        sys.argv[10],
                        "--no-create-gitignore",
                    ]
                    if len(sys.argv) != 12 or sys.argv[1:] != expected:
                        print(
                            f"unexpected fake uv build argv: {{sys.argv[1:]!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    output = Path(sys.argv[sys.argv.index("--out-dir") + 1])
                    output.mkdir(parents=True, exist_ok=True)
                    (output / "fork_ops-0.1-py3-none-any.whl").write_bytes(b"wheel")
                    (output / "fork_ops-0.1.tar.gz").write_bytes(b"sdist")
                    if {extra_artifact!r}:
                        (output / "unexpected.txt").write_text("not a candidate distribution")
                    raise SystemExit(0)
                if (
                    tool_args[:2] == ["coverage", "run"]
                ):
                    from pathlib import Path

                    expected = [
                        "coverage",
                        "run",
                        "--data-file",
                        tool_args[3],
                        "--source",
                        "fork_ops",
                        "-m",
                        "pytest",
                        "plugins/fork-ops/tests",
                        "-q",
                    ]
                    if len(tool_args) != 10 or tool_args != expected:
                        print(
                            f"unexpected fake coverage run argv: {{tool_args!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    if {coverage_mode!r} != "missing-data":
                        data_file = Path(sys.argv[sys.argv.index("--data-file") + 1])
                        data_file.write_bytes(b"coverage-data")
                    raise SystemExit(0)
                if (
                    tool_args[:2] == ["coverage", "json"]
                ):
                    import json
                    from pathlib import Path

                    expected = [
                        "coverage",
                        "json",
                        "--data-file",
                        tool_args[3],
                        "-o",
                        tool_args[5],
                    ]
                    if len(tool_args) != 6 or tool_args != expected:
                        print(
                            f"unexpected fake coverage json argv: {{tool_args!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    output = Path(sys.argv[sys.argv.index("-o") + 1])
                    output.write_text(
                        json.dumps(
                            {{
                                "meta": {{"version": "7.15.4"}},
                                "files": (
                                    {{"fork_ops/core.py": {{}}}}
                                    if {coverage_mode!r} != "no-production-files"
                                    else {{"tests/test_fixture.py": {{}}}}
                                ),
                                "totals": {{
                                    "num_statements": 8,
                                    "covered_lines": 8,
                                    "missing_lines": 0,
                                    "excluded_lines": 0,
                                    "percent_covered": 100.0,
                                }},
                            }},
                            sort_keys=True,
                        )
                    )
                    raise SystemExit(0)
                if tool_args == ["fork-ops", "schema", "print"]:
                    from pathlib import Path

                    print(
                        (Path.cwd() / "plugins/fork-ops/schema/fork-ops.schema.json").read_text(),
                        end="",
                    )
                    raise SystemExit(0)
                if (
                    len(tool_args) == 3
                    and tool_args[:2] == ["python", "-c"]
                    and "from fork_ops.cli import build_parser" in tool_args[2]
                ):
                    import json

                    print(json.dumps({{"leaves": [
                        "capability report",
                        "config init",
                        "config show",
                        "config validate",
                        "migration assess",
                        "migration dry-run",
                        "migration execute",
                        "migration explain-blocker",
                        "migration plan",
                        "migration preflight",
                        "migration propose-config",
                        "plugin health",
                        "schema check",
                        "schema print",
                        "workflow catalog",
                        "workflow inventory",
                    ]}}))
                    raise SystemExit(0)
                if (
                    len(tool_args) == 3
                    and tool_args[:2] == ["python", "-c"]
                    and "from fork_ops.workflow_catalog import workflow_catalog"
                    in tool_args[2]
                ):
                    import json

                    records = [
                        ("authority-source-routing", "diagnostic-only", True),
                        ("blocker-resolution", "diagnostic-only", True),
                        ("carried-divergence-review", "planned", False),
                        ("fork-authority-migration", "current", True),
                        ("guarded-sync-execution", "planned", False),
                        ("operator-onboarding", "current", True),
                        ("publication-closeout", "planned", False),
                        ("review-preparation", "planned", False),
                        ("upstream-status-assessment", "diagnostic-only", True),
                        ("upstream-sync-planning", "next-slice", False),
                        ("workflow-migration-inventory", "diagnostic-only", True),
                    ]
                    print(json.dumps({{"contracts": [
                        {{
                            "available": available,
                            "id": contract_id,
                            "implementation_status": status,
                        }}
                        for contract_id, status, available in records
                    ]}}))
                    raise SystemExit(0)
                if (
                    len(sys.argv) > 1
                    and sys.argv[1] == "run"
                    and len(tool_args) == 9
                    and tool_args[:2] == ["python", "-c"]
                    and "collect_uv_audit_evidence" in tool_args[2]
                ):
                    import os

                    command_index = next(
                        index
                        for index, argument in enumerate(sys.argv)
                        if index > 1
                        and argument == "python"
                        and sys.argv[index + 1] == "-c"
                    )
                    os.execv(sys.executable, [sys.executable, *sys.argv[command_index + 1 :]])
                if len(sys.argv) > 1 and sys.argv[1] == "run":
                    expected_tools = [
                        [
                            "ruff",
                            "check",
                            "--cache-dir",
                            ".ruff_cache",
                            "scripts",
                            "plugins/fork-ops/src",
                            "plugins/fork-ops/tests",
                        ],
                        ["pyrefly", "check"],
                    ]
                    if tool_args not in expected_tools:
                        print(
                            f"unexpected fake uv run tool argv: {{tool_args!r}}",
                            file=sys.stderr,
                        )
                        raise SystemExit(97)
                    raise SystemExit(0)
                print(f"unexpected fake uv argv: {{sys.argv[1:]!r}}", file=sys.stderr)
                raise SystemExit(97)
                """
            ),
            encoding="utf-8",
        )
        fake_uv.chmod(0o755)
        fake_docker = fake_bin / "docker"
        fake_docker.write_text(
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import json
                import os
                import pathlib
                import stat
                import sys

                forbidden = {{
                    name
                    for name in os.environ
                    if name.startswith(("GITHUB_", "ACTIONS_"))
                    or name.endswith(("_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL"))
                }}
                if forbidden:
                    print(  # noqa: E501
                        f"docker inherited forbidden environment: {{sorted(forbidden)!r}}",
                        file=sys.stderr,
                    )
                    raise SystemExit(98)
                if any(
                    argument == "--pid" or argument.startswith("--pid=")
                    for argument in sys.argv[1:]
                ):
                    print(
                        "candidate container set an invalid PID namespace override",
                        file=sys.stderr,
                    )
                    raise SystemExit(98)
                if "--pids-limit=256" not in sys.argv[1:]:
                    print("candidate container omitted the process-count bound", file=sys.stderr)
                    raise SystemExit(98)
                image_index = next(
                    index for index, value in enumerate(sys.argv)
                    if value.startswith("python:") and "@sha256:" in value
                )
                isolated_python = sys.argv[image_index + 1 :]
                if isolated_python[:1] == ["/opt/fork-ops/uv"]:
                    resolver_flags = {{
                        "--read-only",
                        "--cap-drop=ALL",
                        "--security-opt=no-new-privileges",
                        "--network=bridge",
                        "--env=UV_NO_CONFIG=1",
                        "--env=UV_DEFAULT_INDEX=https://pypi.org/simple",
                    }}
                    if not resolver_flags.issubset(sys.argv) or "--network=none" in sys.argv:
                        print("fresh resolver container boundary is incomplete", file=sys.stderr)
                        raise SystemExit(98)
                    workspace_mount = next(
                        value for value in sys.argv if "dst=/workspace" in value
                    )
                    uv_mount = next(
                        value for value in sys.argv if "dst=/opt/fork-ops/uv" in value
                    )
                    if not uv_mount.endswith(",readonly"):
                        print("trusted uv mount was writable", file=sys.stderr)
                        raise SystemExit(98)
                    workspace = pathlib.Path(
                        workspace_mount.split("src=", 1)[1].split(",dst=", 1)[0]
                    )
                    (workspace / "uv.lock").write_text("version = 2\\n")
                    raise SystemExit(0)
                if isolated_python[:1] in (
                    ["/opt/fork-ops/bin/ruff"],
                    ["/opt/fork-ops/bin/pyrefly"],
                ):
                    tools_mount = next(
                        value for value in sys.argv if "dst=/opt/fork-ops/bin" in value
                    )
                    if not tools_mount.endswith(",readonly"):
                        print("trusted tool binaries were writable", file=sys.stderr)
                        raise SystemExit(98)
                    if isolated_python[:1] == ["/opt/fork-ops/bin/pyrefly"]:
                        site_packages_mount = next(
                            value
                            for value in sys.argv
                            if "dst=/opt/fork-ops/site-packages" in value
                        )
                        if not site_packages_mount.endswith(",readonly"):
                            print("trusted site packages were writable", file=sys.stderr)
                            raise SystemExit(98)
                    workspace_mount = next(
                        value for value in sys.argv if "dst=/workspace" in value
                    )
                    if not workspace_mount.endswith(",readonly"):
                        print("candidate source was writable", file=sys.stderr)
                        raise SystemExit(98)
                    raise SystemExit(0)
                if isolated_python[:4] != ["python", "-I", "-S", "-c"]:
                    print("candidate Python did not use isolated startup", file=sys.stderr)
                    raise SystemExit(98)
                if "fork_ops_validation_container_bootstrap" not in isolated_python[4]:
                    print("candidate Python did not use the trusted bootstrap", file=sys.stderr)
                    raise SystemExit(98)
                if any("dst=/opt/fork-ops/bin" in value for value in sys.argv):
                    isolated_site_mount = next(
                        value
                        for value in sys.argv
                        if "dst=/usr/local/lib/python" in value
                        and value.endswith("/site-packages,readonly")
                    )
                    isolated_site = pathlib.Path(
                        isolated_site_mount.split("src=", 1)[1].split(",dst=", 1)[0]
                    )
                    isolated_paths_file = isolated_site / "fork_ops_validation.pth"
                    if isolated_paths_file.read_text(encoding="utf-8").splitlines() != [
                        'import sys; sys.modules["sitecustomize"] = sys.modules["site"]',
                        "/opt/fork-ops/site-packages",
                        "/workspace/plugins/fork-ops/src",
                    ]:
                        print(
                            "isolated child Python paths were not verifier-owned",
                            file=sys.stderr,
                        )
                        raise SystemExit(98)
                isolated_paths = json.loads(isolated_python[5])
                if isolated_paths[:1] != ["/opt/fork-ops/site-packages"]:
                    print(
                        "trusted verifier tools were not the first appended path",
                        file=sys.stderr,
                    )
                    raise SystemExit(98)
                python_args = isolated_python[6:]
                required_flags = {{
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--env=PYTHONSAFEPATH=1",
                }}
                if not required_flags.issubset(sys.argv):
                    print("candidate container was not fail closed", file=sys.stderr)
                    raise SystemExit(98)

                def mount_source(destination):
                    mount = next(
                        value for value in sys.argv
                        if f"dst={{destination}}" in value
                    )
                    return pathlib.Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])

                def require_isolated_user_writable_mount(destination):
                    source = mount_source(destination)
                    user = next(
                        value.split("=", 1)[1]
                        for value in sys.argv
                        if value.startswith("--user=")
                    )
                    user_id, group_id = (int(value) for value in user.split(":", 1))
                    ownership = source.stat()
                    mode = stat.S_IMODE(source.stat().st_mode)
                    owner_access = (
                        ownership.st_uid == user_id
                        and mode & stat.S_IWUSR
                        and mode & stat.S_IXUSR
                    )
                    group_access = (
                        ownership.st_gid == group_id
                        and mode & stat.S_IWGRP
                        and mode & stat.S_IXGRP
                    )
                    if user_id != 65532 or not (owner_access or group_access):
                        print(
                            f"{{destination}} is not writable by the isolated container user",
                            file=sys.stderr,
                        )
                        raise SystemExit(98)
                    return source

                def require_isolated_user_readable_mount(destination):
                    source = mount_source(destination)
                    user = next(
                        value.split("=", 1)[1]
                        for value in sys.argv
                        if value.startswith("--user=")
                    )
                    _, group_id = (int(value) for value in user.split(":", 1))
                    ownership = source.stat()
                    mode = stat.S_IMODE(ownership.st_mode)
                    if ownership.st_gid != group_id or not mode & stat.S_IRGRP:
                        print(
                            f"{{destination}} is not readable by the isolated container user",
                            file=sys.stderr,
                        )
                        raise SystemExit(98)
                    if source.is_dir() and not mode & stat.S_IXGRP:
                        print(
                            f"{{destination}} is not traversable by the isolated container user",
                            file=sys.stderr,
                        )
                        raise SystemExit(98)
                    return source

                candidate_paths = [path for path in isolated_paths if path.startswith("/workspace")]
                if candidate_paths and isolated_paths.index(candidate_paths[0]) == 0:
                    print("candidate source precedes trusted verifier tools", file=sys.stderr)
                    raise SystemExit(98)
                if candidate_paths:
                    workspace_mount = next(
                        value for value in sys.argv if "dst=/workspace" in value
                    )
                    if not workspace_mount.endswith(",readonly"):
                        print("candidate source was writable", file=sys.stderr)
                        raise SystemExit(98)
                    require_isolated_user_readable_mount("/workspace")

                if python_args[:1] == ["-c"] and "platform.python_version_tuple" in python_args[1]:
                    print(json.dumps({{  # noqa: E501
                        "minor": f"{{sys.version_info.major}}.{{sys.version_info.minor}}"
                    }}))
                elif (
                    python_args[:1] == ["-c"]
                    and "fork_ops_distribution_installed" in python_args[1]
                ):
                    print(json.dumps({{
                        "fork_ops": "/workspace/plugins/fork-ops/src/fork_ops/__init__.py",
                        "fork_ops_distribution_installed": False,
                        "jsonschema": "/opt/fork-ops/site-packages/jsonschema/__init__.py",
                        "sitecustomize_is_verifier_placeholder": True,
                        "workspace_paths": ["/workspace/plugins/fork-ops/src"],
                    }}, sort_keys=True))
                elif python_args[:1] == ["-c"] and "importlib.metadata" in python_args[1]:
                    print(json.dumps({{  # noqa: E501
                        "distributions": ["fork-ops==0.1", "jsonschema==4.0", "mcp==1.29.0"]
                    }}))
                elif python_args == ["-m", "fork_ops.cli", "--help"]:
                    print("usage: fork-ops")
                elif python_args == ["-m", "fork_ops.cli", "schema", "print"]:
                    if any("dst=/opt/fork-ops/expected-schema.json" in value for value in sys.argv):
                        schema = mount_source("/opt/fork-ops/expected-schema.json")
                    else:
                        schema = (
                            mount_source("/workspace")
                            / "plugins/fork-ops/schema/fork-ops.schema.json"
                        )
                    print(schema.read_text(), end="")
                elif python_args[:1] == ["-c"] and "from mcp import" in python_args[1]:
                    child_python = python_args[2:]
                    if (
                        child_python[:4] != ["python", "-I", "-S", "-c"]
                        or "fork_ops_validation_container_bootstrap" not in child_python[4]
                        or json.loads(child_python[5]) != ["/opt/fork-ops/site-packages"]
                        or child_python[6:] != ["-m", "fork_ops.mcp_server"]
                    ):
                        print(
                            "installed MCP server could load candidate site hooks",
                            file=sys.stderr,
                        )
                        raise SystemExit(98)
                    print(json.dumps({{
                        "protocol_version": "2025-11-25",
                        "tools": {list(MCP_TOOL_NAMES)!r},
                        "call": "fork_ops_schema",
                        "shutdown": "clean",
                    }}))
                elif (
                    python_args[:1] == ["-c"]
                    and "from fork_ops.cli import build_parser" in python_args[1]
                ):
                    print(json.dumps({{"leaves": [
                        "capability report",
                        "config init",
                        "config show",
                        "config validate",
                        "migration assess",
                        "migration dry-run",
                        "migration execute",
                        "migration explain-blocker",
                        "migration plan",
                        "migration preflight",
                        "migration propose-config",
                        "plugin health",
                        "schema check",
                        "schema print",
                        "workflow catalog",
                        "workflow inventory",
                    ]}}))
                elif (
                    python_args[:1] == ["-c"]
                    and "from fork_ops.workflow_catalog import workflow_catalog"
                    in python_args[1]
                ):
                    records = [
                        ("authority-source-routing", "diagnostic-only", True),
                        ("blocker-resolution", "diagnostic-only", True),
                        ("carried-divergence-review", "planned", False),
                        ("fork-authority-migration", "current", True),
                        ("guarded-sync-execution", "planned", False),
                        ("operator-onboarding", "current", True),
                        ("publication-closeout", "planned", False),
                        ("review-preparation", "planned", False),
                        ("upstream-status-assessment", "diagnostic-only", True),
                        ("upstream-sync-planning", "next-slice", False),
                        ("workflow-migration-inventory", "diagnostic-only", True),
                    ]
                    print(json.dumps({{"contracts": [
                        {{
                            "available": available,
                            "id": contract_id,
                            "implementation_status": status,
                        }}
                        for contract_id, status, available in records
                    ]}}))
                elif python_args[:3] == ["-m", "coverage", "run"]:
                    scratch = require_isolated_user_writable_mount("/scratch")
                    if {coverage_mode!r} != "missing-data":
                        (scratch / "coverage.data").write_bytes(b"coverage-data")
                elif python_args[:3] == ["-m", "coverage", "json"]:
                    output = require_isolated_user_writable_mount("/scratch") / "coverage.json"
                    output.write_text(json.dumps({{
                        "meta": {{"version": "7.15.4"}},
                        "files": (
                            {{"fork_ops/core.py": {{}}}}
                            if {coverage_mode!r} != "no-production-files"
                            else {{"tests/test_fixture.py": {{}}}}
                        ),
                        "totals": {{
                            "num_statements": 8,
                            "covered_lines": 8,
                            "missing_lines": 0,
                            "excluded_lines": 0,
                            "percent_covered": 100.0,
                        }},
                    }}, sort_keys=True))
                elif (
                    python_args[:1] == ["-c"]
                    and "from setuptools import build_meta" in python_args[1]
                ):
                    workspace = require_isolated_user_readable_mount("/workspace")
                    workspace_mount = next(
                        value for value in sys.argv if "dst=/workspace" in value
                    )
                    if not workspace_mount.endswith(",readonly"):
                        print("build source was writable on the host", file=sys.stderr)
                        raise SystemExit(98)
                    if (
                        "shutil.copytree" not in python_args[1]
                        or "/tmp/candidate" not in python_args[1]
                    ):
                        print("build did not use a container-private source copy", file=sys.stderr)
                        raise SystemExit(98)
                    output = require_isolated_user_writable_mount("/output")
                    (output / "fork_ops-0.1-py3-none-any.whl").write_bytes(b"wheel")
                    (output / "fork_ops-0.1.tar.gz").write_bytes(b"sdist")
                    if {extra_artifact!r}:
                        (output / "unexpected.txt").write_text("not a candidate distribution")
                else:
                    print(f"unexpected fake docker argv: {{sys.argv[1:]!r}}", file=sys.stderr)
                    raise SystemExit(97)
                """
            ),
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        return fake_bin

    def _sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _source_snapshot_sha256(self, evidence: dict[str, object]) -> str:
        identity = evidence.get("identity")
        if not isinstance(identity, dict):
            self.fail("validation evidence identity must be a table")
        digest = identity.get("source_snapshot_sha256")
        if not isinstance(digest, str):
            self.fail("source snapshot digest must be a string")
        return digest

    def _run_fixture_build(
        self,
        repo: Path,
        root: Path,
        env: dict[str, str],
    ) -> dict[str, object]:
        artifact_dir = root / "candidate"
        output = root / "build-evidence.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(VALIDATION_ENTRYPOINT),
                "--mode",
                "build",
                "--interpreter",
                sys.executable,
                "--repo",
                str(repo),
                "--artifact-dir",
                str(artifact_dir),
                "--output",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(output.read_text(encoding="utf-8"))

    def _git_commit(self, repo: Path) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()


if __name__ == "__main__":
    unittest.main()
