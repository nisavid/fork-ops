"""Live Git diagnostics must not select executables from the inspected repository."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest

from fork_ops import core


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    executable = shutil.which("git", path=os.defpath)
    assert executable is not None
    repo = tmp_path / "repo"
    repo.mkdir()
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    for arguments in (
        ("init", "-b", "main"),
        ("remote", "add", "origin", "https://github.com/fork/project.git"),
        ("remote", "add", "upstream", "https://github.com/up/project.git"),
        ("symbolic-ref", "refs/remotes/upstream/HEAD", "refs/remotes/upstream/trunk"),
    ):
        subprocess.run(
            [executable, "-C", str(repo), *arguments],
            check=True,
            capture_output=True,
            env=environment,
        )
    return repo


def _substitute_git(directory: Path, marker: Path) -> Path:
    directory.mkdir(exist_ok=True)
    executable = directory / "git"
    executable.write_text(
        f"#!{sys.executable}\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
        "print('substitute')\n"
    )
    executable.chmod(0o755)
    return executable


@pytest.mark.parametrize("search_entry", [".", "", "tools", "repository", "external"])
def test_live_git_ignores_ambient_executable_search(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, search_entry: str
) -> None:
    marker = tmp_path / "substitute-ran"
    _substitute_git(git_repo, marker)
    _substitute_git(git_repo / "tools", marker)
    external = tmp_path / "external"
    _substitute_git(external, marker)
    search_path = {"repository": str(git_repo), "external": str(external)}.get(
        search_entry, search_entry
    )
    monkeypatch.setenv("PATH", search_path)

    result = core._run_git(git_repo, "rev-parse", "--is-inside-work-tree")

    assert result.returncode == 0
    assert result.stdout.strip() == "true"
    assert not marker.exists()


def test_live_git_preserves_repository_diagnostics_and_remote_inference(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "substitute-ran"
    _substitute_git(git_repo, marker)
    monkeypatch.setenv("PATH", ".")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "not-a-repository"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path))
    monkeypatch.setenv("GIT_EXEC_PATH", str(git_repo))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "remote.origin.url")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://example.com/ambient.git")
    config = {
        "fork_remotes": [{"name": "origin", "url": "https://github.com/fork/project.git"}],
        "upstreams": [{"remote": "upstream", "url": "https://github.com/up/project.git"}],
        "upstream_tracks": [{"ref": "refs/remotes/upstream/missing"}],
    }

    diagnostics = core.git_diagnostics(git_repo, config)
    assert [item.code for item in diagnostics] == ["git.ref_missing"]
    assert diagnostics[0].path == "upstream_tracks.0.ref"
    assert core._default_branch(git_repo) == "main"
    assert core._upstream_default_branch(git_repo) == "trunk"
    assert core._git_output(git_repo, "remote", "get-url", "origin") == (
        "https://github.com/fork/project.git"
    )
    discovered = tomllib.loads(core.create_initial_config_text(git_repo))
    assert discovered["fork_remotes"][0]["url"] == "https://github.com/fork/project.git"
    assert discovered["upstreams"][0]["url"] == "https://github.com/up/project.git"
    assert not marker.exists()


def test_live_git_uses_absolute_executable_and_explicit_environment(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORK_OPS_TEST_AMBIENT", "must-not-be-forwarded")
    with patch.object(core, "_default_command_runner") as runner:
        core._run_git(git_repo, "branch", "--show-current")

    command, cwd, timeout = runner.call_args.args
    assert Path(command[0]).is_absolute()
    assert not Path(command[0]).is_relative_to(git_repo)
    assert command[1:] == ["-C", str(git_repo), "branch", "--show-current"]
    assert cwd == git_repo
    assert timeout == 10.0
    environment = runner.call_args.kwargs["env"]
    assert "FORK_OPS_TEST_AMBIENT" not in environment
    assert "GIT_EXEC_PATH" not in environment
    assert "GIT_DIR" not in environment
    assert all(Path(entry).is_absolute() for entry in environment["PATH"].split(os.pathsep))


@pytest.mark.parametrize(
    "selected_kind", ["missing", "relative", "repository", "symlink", "plain", "directory"]
)
def test_live_git_refuses_untrusted_or_unusable_selection(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selected_kind: str
) -> None:
    marker = tmp_path / "substitute-ran"
    substitute = _substitute_git(git_repo, marker)
    link = tmp_path / "git-link"
    link.symlink_to(substitute)
    plain = tmp_path / "plain"
    plain.write_text("not executable")
    selected = {
        "missing": None,
        "relative": "git",
        "repository": str(substitute),
        "symlink": str(link),
        "plain": str(plain),
        "directory": str(tmp_path),
    }[selected_kind]
    def select_git(_command: str, *, path: str) -> str | None:
        return selected

    monkeypatch.setattr(shutil, "which", select_git)
    with patch.object(core, "_default_command_runner") as runner:
        result = core._run_git(git_repo, "rev-parse", "--is-inside-work-tree")
        assert result.returncode == 127
        assert result.stdout == ""
        assert result.stderr
        runner.assert_not_called()
    assert core._git_ok(git_repo, "rev-parse", "--is-inside-work-tree") is False
    diagnostics = core.git_diagnostics(git_repo, {})
    assert [item.code for item in diagnostics] == ["git.unavailable"]
    assert core._git_output(git_repo, "remote", "get-url", "origin") is None
    assert not marker.exists()


def test_live_git_preserves_operator_git_configuration(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(
        '[url "https://mirror.example/"]\n\tinsteadOf = https://github.com/\n'
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))

    assert core._git_output(git_repo, "remote", "get-url", "origin") == (
        "https://mirror.example/fork/project.git"
    )


def test_live_git_rejects_default_search_components_inside_repository(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "substitute-ran"
    _substitute_git(git_repo, marker)
    link = tmp_path / "system-path-link"
    link.symlink_to(git_repo, target_is_directory=True)
    monkeypatch.setattr(os, "defpath", os.pathsep.join((".", "", str(git_repo), str(link))))

    result = core._run_git(git_repo, "rev-parse", "--is-inside-work-tree")

    assert result.returncode == 127
    assert not marker.exists()
