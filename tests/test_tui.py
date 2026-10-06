from __future__ import annotations

import tempfile
import subprocess
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from time import monotonic

from textual.widgets import Input

from vaultlog.store import JournalStore
from vaultlog.tui import JournalApp


class TuiTests(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def _draft_app(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = JournalStore(root / ".vaultlog")
            session = store.initialize(
                "synthetic-test-password", root / "recovery-note.txt",
                idle_lock_minutes=60, autosave_seconds=3600,
            )
            created = session.create_entry("Synthetic fixture", "saved fixture")
            app = JournalApp(session)
            async with app.run_test() as pilot:
                app._load_entry(created.entry_id)
                await pilot.pause()
                app.editor.load_text("synthetic unsaved draft")
                await pilot.pause()
                self.assertTrue(app.state.dirty)
                yield store, session, created, app, pilot

    async def _unlock_app(self, app, pilot) -> None:
        app.screen.query_one("#prompt-input", Input).value = "synthetic-test-password"
        await pilot.press("enter")
        await pilot.pause()
        self.assertFalse(app.state.locked)

    def _assert_encrypted_draft(self, store, entry_id, expected) -> None:
        reopened = store.unlock("synthetic-test-password")
        self.assertEqual(reopened.get_entry(entry_id).body, expected)
        self.assertTrue(reopened.verify_integrity().ok)
        for path in store.vault_dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(expected.encode(), path.read_bytes())

    async def test_camouflage_lock_unlock_restore_and_save_preserves_draft(self) -> None:
        async with self._draft_app() as (store, session, created, app, pilot):
            await pilot.press("f8", "ctrl+l")
            self.assertTrue(app.state.locked)
            self._assert_encrypted_draft(store, created.entry_id, "synthetic unsaved draft")
            self.assertEqual(app.state.shadow_buffer, "synthetic unsaved draft")

            await self._unlock_app(app, pilot)
            self.assertTrue(app.state.camouflage)
            self.assertTrue(app.editor.read_only)
            self.assertNotIn("synthetic unsaved draft", app.editor.text)
            self.assertNotIn("Synthetic fixture", str(app.meta.render()))

            await pilot.press("f8", "ctrl+s")
            self.assertEqual(app.editor.text, "synthetic unsaved draft")
            self.assertFalse(app.editor.read_only)
            self._assert_encrypted_draft(store, created.entry_id, "synthetic unsaved draft")

    async def test_idle_lock_during_camouflage_preserves_draft(self) -> None:
        async with self._draft_app() as (store, session, created, app, pilot):
            await pilot.press("f8")
            app.last_activity = monotonic() - session.config.idle_lock_minutes * 60 - 1
            app._check_idle_lock()
            await pilot.pause()
            self.assertTrue(app.state.locked)
            self._assert_encrypted_draft(store, created.entry_id, "synthetic unsaved draft")
            await self._unlock_app(app, pilot)
            await pilot.press("f8")
            self.assertEqual(app.editor.text, "synthetic unsaved draft")

    async def test_quit_during_camouflage_saves_draft(self) -> None:
        async with self._draft_app() as (store, session, created, app, pilot):
            await pilot.press("f8", "ctrl+q")
            self._assert_encrypted_draft(store, created.entry_id, "synthetic unsaved draft")

    async def test_save_during_camouflage_keeps_draft_hidden(self) -> None:
        async with self._draft_app() as (store, session, created, app, pilot):
            await pilot.press("f8", "ctrl+s")
            self._assert_encrypted_draft(store, created.entry_id, "synthetic unsaved draft")
            self.assertTrue(app.state.camouflage)
            self.assertTrue(app.editor.read_only)
            self.assertNotIn("synthetic unsaved draft", app.editor.text)
            self.assertNotIn("Synthetic fixture", str(app.meta.render()))
            ciphertext = session.meta_path(created.entry_id).read_bytes()
            await pilot.press("ctrl+s")
            self.assertEqual(session.meta_path(created.entry_id).read_bytes(), ciphertext)

    async def test_repeated_camouflage_lock_cycles_preserve_each_draft(self) -> None:
        async with self._draft_app() as (store, session, created, app, pilot):
            for index in range(3):
                expected = f"synthetic draft cycle {index}"
                app.editor.load_text(expected)
                await pilot.pause()
                await pilot.press("f8", "ctrl+l")
                self._assert_encrypted_draft(store, created.entry_id, expected)
                await self._unlock_app(app, pilot)
                self.assertTrue(app.editor.read_only)
                await pilot.press("f8", "ctrl+s")
                self.assertEqual(app.editor.text, expected)
                self._assert_encrypted_draft(store, created.entry_id, expected)

    async def test_lock_without_camouflage_restores_editable_draft(self) -> None:
        async with self._draft_app() as (store, session, created, app, pilot):
            await pilot.press("ctrl+l")
            self._assert_encrypted_draft(store, created.entry_id, "synthetic unsaved draft")
            await self._unlock_app(app, pilot)
            self.assertFalse(app.state.camouflage)
            self.assertFalse(app.editor.read_only)
            self.assertEqual(app.editor.text, "synthetic unsaved draft")

    async def test_camouflage_quit_preserves_edit_before_changed_event(self) -> None:
        async with self._draft_app() as (store, session, created, app, pilot):
            app.action_save_entry()
            app.editor.load_text("synthetic immediate edit")
            # Capture and quit before TextArea.Changed reaches the app.
            app.action_toggle_camouflage()
            app.action_safe_exit()
            self._assert_encrypted_draft(store, created.entry_id, "synthetic immediate edit")

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
