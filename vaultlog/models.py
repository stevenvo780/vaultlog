from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class EntryMeta:
    entry_id: str
    slug: str
    title: str
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, str]:
        return {
            "entry_id": self.entry_id,
            "slug": self.slug,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str]) -> "EntryMeta":
        return cls(
            entry_id=payload["entry_id"],
            slug=payload["slug"],
            title=payload["title"],
            created_at=payload["created_at"],
            updated_at=payload["updated_at"],
        )


@dataclass(slots=True)
class EntryRecord(EntryMeta):
    body: str

    def to_dict(self) -> dict[str, str]:
        payload = EntryMeta.to_dict(self)
        payload["body"] = self.body
        return payload

    def meta(self) -> EntryMeta:
        return EntryMeta(
            entry_id=self.entry_id,
            slug=self.slug,
            title=self.title,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    @classmethod
    def from_dict(cls, payload: dict[str, str]) -> "EntryRecord":
        meta = EntryMeta.from_dict(payload)
        return cls(
            entry_id=meta.entry_id,
            slug=meta.slug,
            title=meta.title,
            created_at=meta.created_at,
            updated_at=meta.updated_at,
            body=payload["body"],
        )
