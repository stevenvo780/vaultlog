from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from .crypto import decrypt_json, derive_key, encrypt_json
from .models import EntryMeta, EntryRecord, utc_now_iso

DEFAULT_VAULT_DIR = Path(".vaultlog")
DEFAULT_RECOVERY_PATH = Path.home() / ".local" / "share" / "vaultlog" / "recovery-note.txt"
KDF_ITERATIONS = 390_000
DEFAULT_AUTOSAVE_SECONDS = 10
PLAINTEXT_SECRET_MARKERS = ("Master password:", "Contraseña maestra:", "Password:")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or utc_now_iso().replace(":", "-").replace("+00-00", "z")


def ensure_mode(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        tmp_name = handle.name
    ensure_mode(Path(tmp_name), mode)
    os.replace(tmp_name, path)
    ensure_mode(path, mode)
    fsync_dir(path.parent)


def atomic_write_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2), mode=mode)


@dataclass(slots=True)
class VaultConfig:
    version: int
    salt_b64: str
    iterations: int
    verifier: dict[str, Any]
    recovery_note: str
    created_at: str
    idle_lock_minutes: int = 5
    autosave_seconds: int = DEFAULT_AUTOSAVE_SECONDS

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "salt_b64": self.salt_b64,
            "iterations": self.iterations,
            "verifier": self.verifier,
            "recovery_note": self.recovery_note,
            "created_at": self.created_at,
            "idle_lock_minutes": self.idle_lock_minutes,
            "autosave_seconds": self.autosave_seconds,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "VaultConfig":
        return cls(
            version=int(payload["version"]),
            salt_b64=str(payload["salt_b64"]),
            iterations=int(payload["iterations"]),
            verifier=dict(payload["verifier"]),
            recovery_note=str(payload["recovery_note"]),
            created_at=str(payload["created_at"]),
            idle_lock_minutes=int(payload.get("idle_lock_minutes", 5)),
            autosave_seconds=int(payload.get("autosave_seconds", DEFAULT_AUTOSAVE_SECONDS)),
        )


@dataclass(slots=True)
class VaultIntegrityReport:
    ok: bool
    entries: int
    missing_files: list[str]
    orphan_files: list[str]
    corrupt_files: list[str]
    errors: list[str]

    def lines(self) -> list[str]:
        lines = [f"Integrity: {'OK' if self.ok else 'FAILED'}", f"Entries verified: {self.entries}"]
        for label, values in (
            ("Missing files", self.missing_files),
            ("Orphan files", self.orphan_files),
            ("Corrupt files", self.corrupt_files),
            ("Errors", self.errors),
        ):
            if values:
                lines.append(f"{label}:")
                lines.extend(f"  - {value}" for value in values)
        return lines


class JournalStore:
    def __init__(self, vault_dir: Path) -> None:
        self.vault_dir = vault_dir.expanduser().resolve()
        self.entries_dir = self.vault_dir / "entries"
        self.config_path = self.vault_dir / "config.json"
        self.manifest_path = self.vault_dir / "manifest.enc"

    def initialized(self) -> bool:
        return self.config_path.exists() and self.manifest_path.exists()

    def initialize(
        self,
        password: str,
        recovery_path: Path = DEFAULT_RECOVERY_PATH,
        idle_lock_minutes: int = 5,
        autosave_seconds: int = DEFAULT_AUTOSAVE_SECONDS,
    ) -> "UnlockedVault":
        if self.initialized():
            raise RuntimeError(f"The vault already exists at {self.vault_dir}")

        salt = secrets.token_bytes(16)
        key = derive_key(password, salt, KDF_ITERATIONS)
        verifier = encrypt_json(key, {"ok": True, "vault": str(self.vault_dir)})
        config = VaultConfig(
            version=1,
            salt_b64=_b64encode(salt),
            iterations=KDF_ITERATIONS,
            verifier=verifier,
            recovery_note=str(recovery_path.expanduser()),
            created_at=utc_now_iso(),
            idle_lock_minutes=idle_lock_minutes,
            autosave_seconds=autosave_seconds,
        )

        self.entries_dir.mkdir(parents=True, exist_ok=True)
        ensure_mode(self.vault_dir, 0o700)
        ensure_mode(self.entries_dir, 0o700)
        atomic_write_json(self.config_path, config.to_dict())
        atomic_write_json(self.manifest_path, encrypt_json(key, {"entries": []}))
        self._write_recovery_note(recovery_path, config.created_at)
        return self.unlock(password)

    def unlock(self, password: str) -> "UnlockedVault":
        config = self.read_config()
        salt = _b64decode(config.salt_b64)
        key = derive_key(password, salt, config.iterations)
        try:
            decrypt_json(key, config.verifier)
        except Exception as exc:
            raise ValueError("Invalid password") from exc
        return UnlockedVault(self, config, key)

    def read_config(self) -> VaultConfig:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Vault config missing at {self.config_path}")
        return VaultConfig.from_dict(json.loads(self.config_path.read_text(encoding="utf-8")))

    def change_password(
        self,
        current_password: str,
        new_password: str,
        recovery_path: Path | None = None,
    ) -> None:
        session = self.unlock(current_password)
        recovery_target = recovery_path or Path(session.config.recovery_note)
        new_salt = secrets.token_bytes(16)
        new_key = derive_key(new_password, new_salt, KDF_ITERATIONS)
        new_config = VaultConfig(
            version=1,
            salt_b64=_b64encode(new_salt),
            iterations=KDF_ITERATIONS,
            verifier=encrypt_json(new_key, {"ok": True, "vault": str(self.vault_dir)}),
            recovery_note=str(recovery_target.expanduser()),
            created_at=session.config.created_at,
            idle_lock_minutes=session.config.idle_lock_minutes,
            autosave_seconds=session.config.autosave_seconds,
        )

        records = session.export_records()
        manifest = {"entries": [record.meta().to_dict() for record in records]}
        backup_dir = self._snapshot_vault("before-password-rotation")
        temp_dir = self._build_reencrypted_vault(new_config, new_key, manifest, records)
        try:
            temp_store = JournalStore(temp_dir)
            temp_session = temp_store.unlock(new_password)
            report = temp_session.verify_integrity()
            if not report.ok:
                raise RuntimeError("\n".join(report.lines()))
            rotated_out_dir = self._unique_sidecar_dir("rotated-out")
            os.replace(self.vault_dir, rotated_out_dir)
            os.replace(temp_dir, self.vault_dir)
            ensure_mode(self.vault_dir, 0o700)
            fsync_dir(self.vault_dir.parent)
        except Exception:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            if not self.vault_dir.exists() and backup_dir.exists():
                shutil.copytree(backup_dir, self.vault_dir)
            raise
        self._write_recovery_note(recovery_target, utc_now_iso())

    def update_config(
        self,
        *,
        idle_lock_minutes: int | None = None,
        autosave_seconds: int | None = None,
    ) -> VaultConfig:
        config = self.read_config()
        updated = VaultConfig(
            version=config.version,
            salt_b64=config.salt_b64,
            iterations=config.iterations,
            verifier=config.verifier,
            recovery_note=config.recovery_note,
            created_at=config.created_at,
            idle_lock_minutes=idle_lock_minutes
            if idle_lock_minutes is not None
            else config.idle_lock_minutes,
            autosave_seconds=autosave_seconds
            if autosave_seconds is not None
            else config.autosave_seconds,
        )
        if updated.idle_lock_minutes < 1:
            raise ValueError("idle_lock_minutes must be >= 1")
        if updated.autosave_seconds < 1:
            raise ValueError("autosave_seconds must be >= 1")
        atomic_write_json(self.config_path, updated.to_dict())
        return updated

    def scrub_recovery_note(self, recovery_path: Path | None = None) -> Path:
        config = self.read_config()
        target = recovery_path or Path(config.recovery_note)
        self._write_recovery_note(target, utc_now_iso())
        return target.expanduser()

    def recovery_note_has_plaintext_secret(self) -> bool:
        if not self.config_path.exists():
            return False
        target = Path(self.read_config().recovery_note).expanduser()
        if not target.exists():
            return False
        text = target.read_text(encoding="utf-8", errors="replace")
        return any(marker in text for marker in PLAINTEXT_SECRET_MARKERS)

    def _build_reencrypted_vault(
        self,
        config: VaultConfig,
        key: bytes,
        manifest: dict[str, Any],
        records: list["EntryRecord"],
    ) -> Path:
        temp_dir = self._unique_sidecar_dir("tmp")
        temp_entries = temp_dir / "entries"
        temp_entries.mkdir(parents=True, exist_ok=False)
        ensure_mode(temp_dir, 0o700)
        ensure_mode(temp_entries, 0o700)
        atomic_write_json(temp_dir / "config.json", config.to_dict())
        atomic_write_json(temp_dir / "manifest.enc", encrypt_json(key, manifest))
        for record in records:
            atomic_write_json(temp_entries / f"{record.entry_id}.enc", encrypt_json(key, record.to_dict()))
        return temp_dir

    def _snapshot_vault(self, reason: str) -> Path:
        backup_dir = self._unique_sidecar_dir(f"backup-{reason}")
        shutil.copytree(self.vault_dir, backup_dir)
        ensure_mode(backup_dir, 0o700)
        for path in backup_dir.rglob("*"):
            if path.is_dir():
                ensure_mode(path, 0o700)
            elif path.is_file():
                ensure_mode(path, 0o600)
        return backup_dir

    def _unique_sidecar_dir(self, label: str) -> Path:
        stamp = utc_now_iso().replace(":", "").replace("+00:00", "Z")
        base = self.vault_dir.parent / f"{self.vault_dir.name}.{label}-{stamp}"
        if not base.exists():
            return base
        return self.vault_dir.parent / f"{base.name}-{uuid4().hex[:8]}"

    def _write_recovery_note(self, target: Path, stamp: str) -> None:
        target = target.expanduser()
        note = "\n".join(
            [
                "VAULTLOG RECOVERY NOTE",
                "",
                f"Updated at: {stamp}",
                f"Vault path: {self.vault_dir}",
                "",
                "This file intentionally does not store the master password.",
                "If you lose the master password, the encrypted content cannot be recovered.",
                "Keep the password in a separate password manager or offline sealed note.",
                "Git backups protect against disk loss, not forgotten passwords.",
                "",
                "Suggested command:",
                f"  vaultlog tui --vault {self.vault_dir}",
            ]
        )
        atomic_write_text(target, note, mode=0o600)


class UnlockedVault:
    def __init__(self, store: JournalStore, config: VaultConfig, key: bytes) -> None:
        self.store = store
        self.config = config
        self.key = key

    def meta_path(self, entry_id: str) -> Path:
        return self.store.entries_dir / f"{entry_id}.enc"

    def list_entries(self) -> list[EntryMeta]:
        manifest = self._read_manifest()
        entries = [EntryMeta.from_dict(item) for item in manifest.get("entries", [])]
        return sorted(entries, key=lambda item: item.updated_at, reverse=True)

    def create_entry(self, title: str, body: str = "") -> EntryRecord:
        now = utc_now_iso()
        entry = EntryRecord(
            entry_id=uuid4().hex,
            slug=self._unique_slug(title),
            title=title.strip() or "untitled",
            created_at=now,
            updated_at=now,
            body=body,
        )
        self._write_entry(entry)
        manifest = self._read_manifest()
        manifest_entries = manifest.get("entries", [])
        manifest_entries.append(entry.meta().to_dict())
        manifest["entries"] = manifest_entries
        self._write_manifest(manifest)
        return entry

    def rename_entry(self, identifier: str, title: str) -> EntryRecord:
        record = self.get_entry(identifier)
        record.title = title.strip() or record.title
        record.slug = self._unique_slug(record.title, current_entry_id=record.entry_id)
        record.updated_at = utc_now_iso()
        self._write_entry(record)
        self._replace_meta(record.meta())
        return record

    def update_entry(self, identifier: str, body: str) -> EntryRecord:
        record = self.get_entry(identifier)
        record.body = body
        record.updated_at = utc_now_iso()
        self._write_entry(record)
        self._replace_meta(record.meta())
        return record

    def get_entry(self, identifier: str) -> EntryRecord:
        meta = self.resolve_entry(identifier)
        payload = json.loads(self.meta_path(meta.entry_id).read_text(encoding="utf-8"))
        return EntryRecord.from_dict(decrypt_json(self.key, payload))

    def resolve_entry(self, identifier: str) -> EntryMeta:
        normalized = identifier.strip()
        for entry in self.list_entries():
            if entry.entry_id == normalized or entry.slug == normalized:
                return entry
        raise KeyError(f"Entry not found: {identifier}")

    def export_records(self) -> list[EntryRecord]:
        return [self.get_entry(entry.entry_id) for entry in self.list_entries()]

    def verify_integrity(self) -> VaultIntegrityReport:
        missing_files: list[str] = []
        orphan_files: list[str] = []
        corrupt_files: list[str] = []
        errors: list[str] = []
        verified = 0

        try:
            manifest = self._read_manifest()
        except Exception as exc:
            return VaultIntegrityReport(
                ok=False,
                entries=0,
                missing_files=[],
                orphan_files=[],
                corrupt_files=[str(self.store.manifest_path)],
                errors=[f"Manifest decrypt/read failed: {exc}"],
            )

        entries_payload = manifest.get("entries", [])
        if not isinstance(entries_payload, list):
            errors.append("Manifest field 'entries' is not a list")
            entries_payload = []

        seen_ids: set[str] = set()
        expected_ids: set[str] = set()
        for item in entries_payload:
            try:
                meta = EntryMeta.from_dict(item)
            except Exception as exc:
                errors.append(f"Invalid manifest entry: {exc}")
                continue
            if meta.entry_id in seen_ids:
                errors.append(f"Duplicate entry id in manifest: {meta.entry_id}")
            seen_ids.add(meta.entry_id)
            expected_ids.add(meta.entry_id)
            entry_path = self.meta_path(meta.entry_id)
            if not entry_path.exists():
                missing_files.append(str(entry_path))
                continue
            try:
                record = EntryRecord.from_dict(decrypt_json(self.key, json.loads(entry_path.read_text(encoding="utf-8"))))
            except Exception as exc:
                corrupt_files.append(str(entry_path))
                errors.append(f"{entry_path.name}: {exc}")
                continue
            if record.entry_id != meta.entry_id:
                errors.append(f"{entry_path.name}: decrypted entry_id does not match manifest")
            verified += 1

        actual_ids = {path.stem for path in self.store.entries_dir.glob("*.enc")}
        for orphan_id in sorted(actual_ids - expected_ids):
            orphan_files.append(str(self.meta_path(orphan_id)))

        ok = not missing_files and not orphan_files and not corrupt_files and not errors
        return VaultIntegrityReport(ok, verified, missing_files, orphan_files, corrupt_files, errors)

    def verify_password(self, password: str) -> bool:
        try:
            self.store.unlock(password)
        except ValueError:
            return False
        return True

    def _read_manifest(self) -> dict[str, Any]:
        payload = json.loads(self.store.manifest_path.read_text(encoding="utf-8"))
        return decrypt_json(self.key, payload)

    def _write_manifest(self, manifest: dict[str, Any]) -> None:
        atomic_write_json(self.store.manifest_path, encrypt_json(self.key, manifest))

    def _write_entry(self, entry: EntryRecord) -> None:
        atomic_write_json(self.meta_path(entry.entry_id), encrypt_json(self.key, entry.to_dict()))

    def _replace_meta(self, meta: EntryMeta) -> None:
        manifest = self._read_manifest()
        entries = manifest.get("entries", [])
        updated = [meta.to_dict() if item["entry_id"] == meta.entry_id else item for item in entries]
        manifest["entries"] = updated
        self._write_manifest(manifest)

    def _unique_slug(self, title: str, current_entry_id: str | None = None) -> str:
        base = slugify(title)
        existing = {
            entry.slug
            for entry in self.list_entries()
            if current_entry_id is None or entry.entry_id != current_entry_id
        }
        if base not in existing:
            return base
        counter = 2
        while f"{base}-{counter}" in existing:
            counter += 1
        return f"{base}-{counter}"


def _b64encode(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def _b64decode(value: str) -> bytes:
    import base64

    return base64.b64decode(value.encode("ascii"))
