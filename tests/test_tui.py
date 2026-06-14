from __future__ import annotations

import tempfile
import subprocess
import unittest
from pathlib import Path

from vaultlog.store import JournalStore
from vaultlog.tui import JournalApp


class TuiTests(unittest.IsolatedAsyncioTestCase):
    def _init_git_repo(self, root: Path) -> None:
        subprocess.run(["git", "init"], cwd=root, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.email", "test@example.local"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Diario Test"], cwd=root, check=True)

    async def test_repeated_autosave_does_not_duplicate_list_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = JournalStore(root / ".vaultlog")
            session = store.initialize("hunter2", root / "recovery-note.txt")
            created = session.create_entry("Cristina", "inicio")
            app = JournalApp(session)

            async with app.run_test() as pilot:
                app._load_entry(created.entry_id)
                await pilot.pause()

                for index in range(3):
                    app._replace_editor_text(f"paste {index}")
                    app.state.dirty = True
                    app._autosave_dirty()
                    await pilot.pause()

                self.assertEqual(session.get_entry(created.entry_id).body, "paste 2")
                self.assertEqual(len(app.entries_view.children), 1)

    async def test_backup_action_commits_and_pushes_encrypted_vault(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            root = workspace / "work"
            remote = workspace / "remote.git"
            root.mkdir()
            self._init_git_repo(root)
            subprocess.run(["git", "init", "--bare", str(remote)], check=True, stdout=subprocess.DEVNULL)

            store = JournalStore(root / ".vaultlog")
            session = store.initialize("hunter2", root / "recovery-note.txt")
            subprocess.run(["git", "init"], cwd=store.vault_dir, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.local"], cwd=store.vault_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Diario Test"], cwd=store.vault_dir, check=True)
            subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=store.vault_dir, check=True)
            created = session.create_entry("Cristina", "inicio")
            app = JournalApp(session)

            async with app.run_test() as pilot:
                app._load_entry(created.entry_id)
                await pilot.pause()
                app._replace_editor_text("guardado desde tui")
                app.state.dirty = True
                app.action_backup_vault()
                await pilot.pause()

            project_tracked = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
            vault_tracked = subprocess.check_output(["git", "ls-files"], cwd=store.vault_dir, text=True).splitlines()
            heads = subprocess.check_output(
                ["git", "ls-remote", "--heads", "origin", "master"],
                cwd=store.vault_dir,
                text=True,
            )

            self.assertEqual(session.get_entry(created.entry_id).body, "guardado desde tui")
            self.assertEqual(project_tracked, [])
            self.assertIn("config.json", vault_tracked)
            self.assertIn("manifest.enc", vault_tracked)
            self.assertTrue(any(name.startswith("entries/") for name in vault_tracked))
            self.assertIn("refs/heads/master", heads)


if __name__ == "__main__":
    unittest.main()
