from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from vaultlog.gitops import git_backup, install_git_hook, remote_url
from vaultlog.store import JournalStore


class GitOpsTests(unittest.TestCase):
    def test_git_backup_commits_only_encrypted_vault_files_in_dedicated_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.local"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Diario Test"], cwd=root, check=True)

            store = JournalStore(root / ".vaultlog")
            session = store.initialize("hunter2", root / "recovery-note.txt")
            session.create_entry("Privada", "contenido")

            result = git_backup(store, message="backup test", push=False, init_git=True)
            project_files = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
            vault_files = subprocess.check_output(["git", "ls-files"], cwd=store.vault_dir, text=True).splitlines()

            self.assertTrue(result.committed)
            self.assertFalse(result.pushed)
            self.assertEqual(result.repo, store.vault_dir.resolve())
            self.assertEqual(project_files, [])
            self.assertEqual(
                sorted(vault_files),
                sorted(
                    [
                        "config.json",
                        "manifest.enc",
                        *[f"entries/{path.name}" for path in store.entries_dir.glob("*.enc")],
                    ]
                ),
            )

    def test_git_backup_refuses_to_use_parent_project_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.local"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Diario Test"], cwd=root, check=True)

            store = JournalStore(root / ".vaultlog")
            session = store.initialize("hunter2", root / "recovery-note.txt")
            session.create_entry("Privada", "contenido")

            with self.assertRaisesRegex(RuntimeError, "repo propio"):
                git_backup(store, message="backup test", push=False, init_git=False)

            project_files = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
            self.assertEqual(project_files, [])

    def test_git_backup_configures_remote_and_pushes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            root = workspace / "work"
            remote = workspace / "remote.git"
            root.mkdir()
            subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.local"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Diario Test"], cwd=root, check=True)
            subprocess.run(["git", "init", "--bare", str(remote)], check=True, stdout=subprocess.DEVNULL)

            store = JournalStore(root / ".vaultlog")
            session = store.initialize("hunter2", root / "recovery-note.txt")
            session.create_entry("Privada", "contenido")

            result = git_backup(
                store,
                message="backup test",
                push=True,
                init_git=True,
                remote=str(remote),
            )
            heads = subprocess.check_output(
                ["git", "ls-remote", "--heads", "origin", "master"],
                cwd=store.vault_dir,
                text=True,
            )

            self.assertTrue(result.committed)
            self.assertTrue(result.pushed)
            self.assertEqual(remote_url(store.vault_dir), str(remote))
            self.assertIn("refs/heads/master", heads)

    def test_pre_commit_hook_blocks_recovery_note(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.local"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Diario Test"], cwd=root, check=True)

            (root / "recovery-note.txt").write_text("Master password: nope\n", encoding="utf-8")
            subprocess.run(["git", "add", "recovery-note.txt"], cwd=root, check=True)
            hook_path = install_git_hook(root)
            result = subprocess.run([str(hook_path)], cwd=root, text=True, capture_output=True)

            self.assertEqual(result.returncode, 1)
            self.assertIn("recovery note must not be committed", result.stderr)

    def test_pre_commit_hook_allows_source_prompt_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.local"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Diario Test"], cwd=root, check=True)

            source = root / "cli.py"
            source.write_text('label = "Contraseña maestra: "\n', encoding="utf-8")
            subprocess.run(["git", "add", "cli.py"], cwd=root, check=True)
            hook_path = install_git_hook(root)
            result = subprocess.run([str(hook_path)], cwd=root, text=True, capture_output=True)

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_vault_pre_commit_hook_blocks_non_payload_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = JournalStore(root / ".vaultlog")
            store.initialize("hunter2", root / "recovery-note.txt")
            subprocess.run(["git", "init"], cwd=store.vault_dir, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.local"], cwd=store.vault_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Diario Test"], cwd=store.vault_dir, check=True)

            (store.vault_dir / "debug.md").write_text("plaintext\n", encoding="utf-8")
            subprocess.run(["git", "add", "debug.md"], cwd=store.vault_dir, check=True)
            hook_path = install_git_hook(store.vault_dir)
            result = subprocess.run([str(hook_path)], cwd=store.vault_dir, text=True, capture_output=True)

            self.assertEqual(result.returncode, 1)
            self.assertIn("only encrypted vault payload files", result.stderr)


if __name__ == "__main__":
    unittest.main()
