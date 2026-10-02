"""Model sertifikat, status urgensi, dan laporan."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field, asdict
from enum import Enum

WARN_DAYS = 30
CRIT_DAYS = 7


class Urgency(str, Enum):
    ERROR = "ERROR"          # tidak bisa dicek
    EXPIRED = "EXPIRED"      # sudah lewat
    CRITICAL = "CRITICAL"    # <= 7 hari
    WARNING = "WARNING"      # <= 30 hari
    OK = "OK"
    NEW = "NEW"              # pertama kali terlihat

    @property
    def symbol(self) -> str:
        return {"ERROR": "❌", "EXPIRED": "⛔", "CRITICAL": "🔴", "WARNING": "⚠️ ",
                "OK": "✅", "NEW": "🆕"}[self.value]

    @property
    def order(self) -> int:
        return {"ERROR": 0, "EXPIRED": 1, "CRITICAL": 2, "WARNING": 3, "NEW": 4,
                "OK": 5}[self.value]


@dataclass
class CertInfo:
    host: str
    port: int = 443
    ok: bool = True
    error: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: dt.datetime | None = None
    not_after: dt.datetime | None = None
    days_left: int | None = None
    fingerprint: str = ""
    tls_version: str = ""
    cipher: str = ""
    sans: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"

    def urgency(self, warn_days: int = WARN_DAYS, crit_days: int = CRIT_DAYS) -> Urgency:
        if not self.ok:
            return Urgency.ERROR
        if self.days_left is None:
            return Urgency.ERROR
        if self.days_left < 0:
            return Urgency.EXPIRED
        if self.days_left <= crit_days:
            return Urgency.CRITICAL
        if self.days_left <= warn_days:
            return Urgency.WARNING
        return Urgency.OK

    def as_dict(self) -> dict:
        d = asdict(self)
        for k in ("not_before", "not_after"):
            d[k] = self.__dict__[k].isoformat() if self.__dict__[k] else None
        return d


@dataclass
class Report:
    started: str = ""
    finished: str = ""
    checked: list[CertInfo] = field(default_factory=list)
    changes: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warn_days: int = WARN_DAYS
    crit_days: int = CRIT_DAYS

    def by_urgency(self) -> list[tuple[CertInfo, Urgency]]:
        rows = [(c, c.urgency(self.warn_days, self.crit_days)) for c in self.checked]
        return sorted(rows, key=lambda r: (r[1].order, r[0].days_left
                                           if r[0].days_left is not None else -999))

    def needs_attention(self) -> list[tuple[CertInfo, Urgency]]:
        return [(c, u) for c, u in self.by_urgency()
                if u in (Urgency.ERROR, Urgency.EXPIRED, Urgency.CRITICAL, Urgency.WARNING)]

    @property
    def worst(self) -> Urgency:
        rows = [u for _, u in self.by_urgency()]
        return min(rows, key=lambda u: u.order) if rows else Urgency.OK

    def as_dict(self) -> dict:
        return {
            "started": self.started,
            "finished": self.finished,
            "thresholds": {"warn_days": self.warn_days, "crit_days": self.crit_days},
            "worst": self.worst.value,
            "summary": {u.value: sum(1 for c in self.checked
                                     if c.urgency(self.warn_days, self.crit_days) is u)
                        for u in Urgency},
            "certificates": [c.as_dict() for c in self.checked],
            "changes": self.changes,
            "errors": self.errors,
        }
