from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .store import JournalStore, atomic_write_text, ensure_mode, utc_now_iso


PRE_COMMIT_HOOK = """#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import subprocess
import sys

allowed_vault = {"config.json", "manifest.enc"}
blocked_name_parts = (
    ".env",
    "credential",
    "credentials",
    "password",
    "secret",
    "token",
)
blocked_exact_names = {
    "id_ed25519",
    "id_rsa",
}
private_key_markers = tuple(
    f"-----{label}-----"
    for label in (
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN PRIVATE KEY",
    )
)
is_vault_repo = pathlib.Path("manifest.enc").is_file() and pathlib.Path("entries").is_dir()
result = subprocess.run(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
    text=True,
    capture_output=True,
    check=True,
)
bad: list[str] = []
for name in result.stdout.splitlines():
    normalized = name.replace("\\\\", "/")
    lower_name = pathlib.PurePosixPath(normalized).name.lower()
    if normalized.endswith("recovery-note.txt"):
        bad.append(f"{name}: recovery note must not be committed")
        continue
    if is_vault_repo:
        is_entry = normalized.startswith("entries/") and normalized.endswith(".enc")
        if normalized not in allowed_vault and not is_entry:
            bad.append(f"{name}: only encrypted vault payload files may be committed")
            continue
    elif normalized == ".vaultlog" or normalized.startswith(".vaultlog/"):
        bad.append(f"{name}: vault data must live in its own Git repo, not the project repo")
        continue
    path = pathlib.Path(name)
    is_sensitive_name = lower_name in blocked_exact_names or any(part in lower_name for part in blocked_name_parts)
    if is_sensitive_name:
        bad.append(f"{name}: sensitive file name must not be committed")
        continue
    if path.is_file() and path.stat().st_size <= 1_000_000:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(marker in text for marker in private_key_markers):
            bad.append(f"{name}: looks like it contains a private key")

if bad:
    print("vaultlog pre-commit blocked unsafe files:", file=sys.stderr)
    for item in bad:
        print(f"  - {item}", file=sys.stderr)
    sys.exit(1)
"""


@dataclass(slots=True)
class GitBackupResult:
    committed: bool
    pushed: bool
    message: str
    repo: Path
    push_skipped_reason: str | None = None


class GitOperationError(RuntimeError):
    pass


def validate_vault_git_payload(store: JournalStore) -> None:
    allowed = {store.config_path.resolve(), store.manifest_path.resolve()}
    allowed.update(path.resolve() for path in store.entries_dir.glob("*.enc"))
    actual = {
        path.resolve()
        for path in store.vault_dir.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(store.vault_dir).parts
    }
    bad = sorted(actual - allowed)
    if bad:
        formatted = "\n".join(f"  - {path}" for path in bad)
        raise GitOperationError(f"El vault contiene archivos no permitidos para Git:\n{formatted}")


def git_backup(
    store: JournalStore,
    *,
    message: str | None,
    push: bool,
    init_git: bool,
    remote: str | None = None,
) -> GitBackupResult:
    validate_vault_git_payload(store)
    root = vault_git_root_for(store)
    if root is None:
        parent_root = git_root_for(store.vault_dir)
        if init_git:
            run(["git", "init"], cwd=store.vault_dir)
            inherit_git_identity(store)
            root = vault_git_root_for(store)
            if root is not None:
                install_git_hook(root)
        elif parent_root is not None:
            raise GitOperationError(
                "El vault está dentro de otro repo Git. Para mantener el proyecto open source, "
                "usa un repo propio: vaultlog backup --init-git."
            )
        if root is None:
            raise GitOperationError("El vault no tiene repo Git propio. Ejecuta: vaultlog backup --init-git.")

    if remote:
        configure_origin(root, remote)

    paths = [
        "config.json",
        "manifest.enc",
        "entries",
    ]
    run(["git", "add", "-A", "--", *paths], cwd=root)
    diff = run(["git", "diff", "--cached", "--quiet", "--", *paths], cwd=root, check=False)
    committed = False
    commit_message = message or f"backup: vaultlog encrypted vault {utc_now_iso()}"
    if diff.returncode != 0:
        run(["git", "commit", "-m", commit_message, "--", *paths], cwd=root)
        committed = True

    pushed = False
    push_skipped_reason = None
    if push:
        origin = remote_url(root)
        if origin is None:
            push_skipped_reason = "El repo del vault no tiene remote origin configurado."
        else:
            run(["git", "push", "-u", "origin", "HEAD"], cwd=root)
            pushed = True
    return GitBackupResult(
        committed=committed,
        pushed=pushed,
        message=commit_message,
        repo=root,
        push_skipped_reason=push_skipped_reason,
    )


def install_git_hook(path: Path) -> Path:
    root = git_root_for(path)
    if root is None:
        raise GitOperationError("No hay repo Git para instalar el hook.")
    hooks_dir = root / ".git" / "hooks"
    hook_path = hooks_dir / "pre-commit"
    atomic_write_text(hook_path, PRE_COMMIT_HOOK, mode=0o700)
    ensure_mode(hook_path, 0o700)
    return hook_path


def vault_git_root_for(store: JournalStore) -> Path | None:
    root = git_root_for(store.vault_dir)
    if root is None:
        return None
    vault_root = store.vault_dir.resolve()
    return root if root == vault_root else None


def git_root_for(path: Path) -> Path | None:
    result = run(["git", "-C", str(path), "rev-parse", "--show-toplevel"], check=False)
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip()).resolve()


def configure_origin(root: Path, remote: str) -> None:
    if remote_url(root) is None:
        run(["git", "remote", "add", "origin", remote], cwd=root)
    else:
        run(["git", "remote", "set-url", "origin", remote], cwd=root)


def remote_url(root: Path) -> str | None:
    result = run(["git", "remote", "get-url", "origin"], cwd=root, check=False)
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def inherit_git_identity(store: JournalStore) -> None:
    root = store.vault_dir.resolve()
    parent_root = git_root_for(store.vault_dir.parent)
    if parent_root is None:
        return
    for key in ("user.name", "user.email"):
        current = run(["git", "config", "--get", key], cwd=root, check=False)
        if current.returncode == 0 and current.stdout.strip():
            continue
        inherited = run(["git", "config", "--get", key], cwd=parent_root, check=False)
        if inherited.returncode == 0 and inherited.stdout.strip():
            run(["git", "config", key, inherited.stdout.strip()], cwd=root)


def run(command: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        output = (result.stdout or "") + (result.stderr or "")
        raise GitOperationError(output.strip() or f"Command failed: {' '.join(command)}")
    return result
