from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vaultlog.store import JournalStore


class StoreTests(unittest.TestCase):
    def test_init_create_update_rotate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = JournalStore(root / ".vaultlog")
            recovery = root / "recovery-note.txt"
            session = store.initialize("hunter2", recovery)
            created = session.create_entry("Entrada privada", "hola")
            self.assertEqual(session.get_entry(created.slug).body, "hola")
            updated = session.update_entry(created.slug, "hola mundo")
            self.assertEqual(updated.body, "hola mundo")
            self.assertTrue(session.verify_integrity().ok)
            note = recovery.read_text(encoding="utf-8")
            self.assertNotIn("hunter2", note)
            self.assertIn("does not store the master password", note)
            store.change_password("hunter2", "rotated-pass", recovery)
            rotated = store.unlock("rotated-pass")
            self.assertEqual(rotated.get_entry(created.slug).body, "hola mundo")
            self.assertTrue(rotated.verify_integrity().ok)
            self.assertNotIn("rotated-pass", recovery.read_text(encoding="utf-8"))
            self.assertTrue(any(root.glob(".vaultlog.backup-before-password-rotation-*")))
            self.assertTrue(any(root.glob(".vaultlog.rotated-out-*")))

    def test_verify_detects_orphan_entry_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = JournalStore(root / ".vaultlog")
            session = store.initialize("hunter2", root / "recovery-note.txt")
            session.create_entry("Entrada privada", "hola")
            (store.entries_dir / "orphan.enc").write_text("{}", encoding="utf-8")
            report = session.verify_integrity()
            self.assertFalse(report.ok)
            self.assertEqual(report.orphan_files, [str(store.entries_dir / "orphan.enc")])

    def test_update_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            store = JournalStore(root / ".vaultlog")
            store.initialize("hunter2", root / "recovery-note.txt")
            updated = store.update_config(idle_lock_minutes=2, autosave_seconds=3)
            self.assertEqual(updated.idle_lock_minutes, 2)
            self.assertEqual(updated.autosave_seconds, 3)
            config = store.read_config()
            self.assertEqual(config.idle_lock_minutes, 2)
            self.assertEqual(config.autosave_seconds, 3)


if __name__ == "__main__":
    unittest.main()
