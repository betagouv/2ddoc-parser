from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "gitleaks_pre_push.sh"
ZERO_SHA = "0" * 40


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _init_temp_repo(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "commit.gpgsign", "false")

    (repo / ".gitleaks.toml").write_text("title = 'test'\n", encoding="utf-8")
    (repo / "hello.txt").write_text("hello\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial commit")
    head_sha = _git(repo, "rev-parse", "HEAD")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_file = tmp_path / "gitleaks_args.log"
    stub = bin_dir / "gitleaks"
    stub.write_text(
        f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "{log_file}"\nexit 0\n',
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    return repo, bin_dir, log_file, head_sha


def _run_hook(
    repo: Path,
    bin_dir: Path,
    *args: str,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    for key in (
        "PRE_COMMIT_FROM_REF",
        "PRE_COMMIT_TO_REF",
        "PRE_COMMIT_LOCAL_BRANCH",
        "PRE_COMMIT_REMOTE_NAME",
    ):
        env.pop(key, None)
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["bash", str(SCRIPT_PATH), *args],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_gitleaks_pre_push_scans_orphan_branch_when_to_ref_empty(tmp_path: Path):
    """Non-régression SEC-01 : PRE_COMMIT_TO_REF vide (push initial / branche orpheline) doit scanner."""
    repo, bin_dir, log_file, head_sha = _init_temp_repo(tmp_path)

    # Sans remote configuré : fallback fail-closed sur le SHA résolu de HEAD
    proc = _run_hook(
        repo,
        bin_dir,
        env_overrides={
            "PRE_COMMIT_TO_REF": "",
            "PRE_COMMIT_FROM_REF": "",
            "PRE_COMMIT_LOCAL_BRANCH": "main",
            "PRE_COMMIT_REMOTE_NAME": "origin",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert log_file.exists(), (
        "gitleaks aurait dû être invoqué sur une branche orpheline"
    )
    called_args = log_file.read_text(encoding="utf-8").splitlines()
    assert f"--log-opts={head_sha}" in called_args

    # Avec un remote git connu : exclut uniquement les refs déjà présentes sur ce remote
    log_file.unlink()
    _git(repo, "remote", "add", "origin", "https://example.com/org/repo.git")
    proc_with_remote = _run_hook(
        repo,
        bin_dir,
        env_overrides={
            "PRE_COMMIT_TO_REF": "",
            "PRE_COMMIT_FROM_REF": "",
            "PRE_COMMIT_LOCAL_BRANCH": "main",
            "PRE_COMMIT_REMOTE_NAME": "origin",
        },
    )
    assert proc_with_remote.returncode == 0, proc_with_remote.stderr
    assert log_file.exists()
    called_args_remote = log_file.read_text(encoding="utf-8").splitlines()
    assert f"--log-opts={head_sha} --not --remotes=origin" in called_args_remote


def test_gitleaks_pre_push_exits_zero_on_branch_deletion(tmp_path: Path):
    """Suppression de référence (LOCAL_SHA == 0000...) : quitte en succès sans lancer gitleaks."""
    repo, bin_dir, log_file, head_sha = _init_temp_repo(tmp_path)

    proc = _run_hook(
        repo,
        bin_dir,
        "refs/heads/feature",
        ZERO_SHA,
        "refs/heads/feature",
        head_sha,
        "origin",
    )
    assert proc.returncode == 0, proc.stderr
    assert not log_file.exists()


@pytest.mark.parametrize(
    ("args", "env_overrides"),
    [
        # Injection d'option via LOCAL_SHA (5 args)
        (
            ("refs/heads/main", "--all", "refs/heads/main", ZERO_SHA, "origin"),
            None,
        ),
        # SHA local malformé via PRE_COMMIT_TO_REF
        (
            (),
            {"PRE_COMMIT_TO_REF": "not-a-valid-sha"},
        ),
        # Injection d'option via REMOTE_SHA (5 args)
        (
            (
                "refs/heads/main",
                "a" * 40,
                "refs/heads/main",
                "--exec=evil",
                "origin",
            ),
            None,
        ),
        # Référence locale commençant par '-' quand LOCAL_SHA est vide (fail-closed)
        (
            (),
            {"PRE_COMMIT_TO_REF": "", "PRE_COMMIT_LOCAL_BRANCH": "--all"},
        ),
        # Référence locale introuvable quand LOCAL_SHA est vide (fail-closed)
        (
            (),
            {
                "PRE_COMMIT_TO_REF": "",
                "PRE_COMMIT_LOCAL_BRANCH": "refs/heads/does-not-exist",
            },
        ),
    ],
)
def test_gitleaks_pre_push_rejects_invalid_sha(
    tmp_path: Path,
    args: tuple[str, ...],
    env_overrides: dict[str, str] | None,
):
    """Un SHA ou une ref invalide doit échouer (fail-closed) sans invoquer gitleaks."""
    repo, bin_dir, log_file, _ = _init_temp_repo(tmp_path)

    proc = _run_hook(repo, bin_dir, *args, env_overrides=env_overrides)
    assert proc.returncode != 0
    assert not log_file.exists()


def test_gitleaks_pre_push_normal_range_remote_to_local(tmp_path: Path):
    """Cas nominal : scanne uniquement la plage REMOTE_SHA..LOCAL_SHA."""
    repo, bin_dir, log_file, first_sha = _init_temp_repo(tmp_path)

    (repo / "second.txt").write_text("second\n", encoding="utf-8")
    _git(repo, "add", "second.txt")
    _git(repo, "commit", "-m", "second commit")
    second_sha = _git(repo, "rev-parse", "HEAD")

    # Mode variables d'environnement pre-commit
    proc_env = _run_hook(
        repo,
        bin_dir,
        env_overrides={
            "PRE_COMMIT_FROM_REF": first_sha,
            "PRE_COMMIT_TO_REF": second_sha,
            "PRE_COMMIT_LOCAL_BRANCH": "main",
            "PRE_COMMIT_REMOTE_NAME": "origin",
        },
    )
    assert proc_env.returncode == 0, proc_env.stderr
    assert (
        f"--log-opts={first_sha}..{second_sha}"
        in log_file.read_text(encoding="utf-8").splitlines()
    )

    # Mode 5 arguments git pre-push
    log_file.unlink()
    proc_args = _run_hook(
        repo,
        bin_dir,
        "refs/heads/main",
        second_sha,
        "refs/heads/main",
        first_sha,
        "origin",
    )
    assert proc_args.returncode == 0, proc_args.stderr
    assert (
        f"--log-opts={first_sha}..{second_sha}"
        in log_file.read_text(encoding="utf-8").splitlines()
    )


def test_gitleaks_pre_push_url_remote_falls_back_to_local_sha(tmp_path: Path):
    """Si REMOTE est une URL directe (non configurée comme remote), fallback fail-closed sur LOCAL_SHA."""
    repo, bin_dir, log_file, head_sha = _init_temp_repo(tmp_path)

    proc = _run_hook(
        repo,
        bin_dir,
        "refs/heads/main",
        head_sha,
        "refs/heads/main",
        ZERO_SHA,
        "https://example.com/org/repo.git",
    )
    assert proc.returncode == 0, proc.stderr
    assert f"--log-opts={head_sha}" in log_file.read_text(encoding="utf-8").splitlines()


def test_gitleaks_pre_push_resolves_config_from_subdirectory(tmp_path: Path):
    """Non-régression QUAL-05 : le script résout `.gitleaks.toml` depuis `git rev-parse --show-toplevel` même lancé d'un sous-répertoire."""
    repo, bin_dir, log_file, head_sha = _init_temp_repo(tmp_path)
    subdir = repo / "nested" / "dir"
    subdir.mkdir(parents=True)

    proc = _run_hook(
        subdir,
        bin_dir,
        "refs/heads/main",
        head_sha,
        "refs/heads/main",
        ZERO_SHA,
        "origin",
    )
    assert proc.returncode == 0, proc.stderr
    called_args = log_file.read_text(encoding="utf-8").splitlines()
    config_idx = called_args.index("--config")
    assert (
        Path(called_args[config_idx + 1]).resolve()
        == (repo / ".gitleaks.toml").resolve()
    )
