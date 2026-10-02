"""Daftar target + state (riwayat) untuk mendeteksi perubahan sertifikat."""
from __future__ import annotations

import json
from pathlib import Path


def parse_targets(text: str) -> list[tuple[str, int]]:
    """Urai daftar target: satu per baris, `host` atau `host:port`, `#` untuk komentar."""
    out: list[tuple[str, int]] = []
    seen = set()
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # buang skema bila ada
        for prefix in ("https://", "http://"):
            if line.startswith(prefix):
                line = line[len(prefix):]
        line = line.rstrip("/")
        if "/" in line:
            line = line.split("/", 1)[0]
        host, _, port_s = line.partition(":")
        host = host.strip()
        if not host:
            continue
        try:
            port = int(port_s) if port_s else 443
        except ValueError:
            port = 443
        key = (host, port)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def load_targets(path: str | Path) -> list[tuple[str, int]]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"berkas target tidak ada: {p}")
    return parse_targets(p.read_text())


class State:
    """Riwayat ringkas per target untuk mendeteksi sertifikat berubah."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.data: dict[str, dict] = {}
        if self.path.is_file():
            try:
                self.data = json.loads(self.path.read_text())
            except json.JSONDecodeError:
                self.data = {}

    def diff(self, key: str, fingerprint: str, not_after: str | None) -> dict | None:
        """Kembalikan info perubahan, atau None bila sama/target baru."""
        prev = self.data.get(key)
        if not prev:
            return {"key": key, "kind": "baru", "detail": "target pertama kali dipantau"}
        if fingerprint and prev.get("fingerprint") and prev["fingerprint"] != fingerprint:
            return {"key": key, "kind": "sertifikat berubah",
                    "detail": f"sidik jari lama {prev['fingerprint'][:16]}… → "
                              f"baru {fingerprint[:16]}…"}
        if not_after and prev.get("not_after") and prev["not_after"] != not_after:
            return {"key": key, "kind": "masa berlaku berubah",
                    "detail": f"{prev['not_after']} → {not_after}"}
        return None

    def update(self, entries: list[dict]) -> None:
        """Simpan ringkasan tiap sertifikat. `key` diturunkan dari host:port bila tidak ada."""
        for e in entries:
            key = e.get("key") or f"{e.get('host')}:{e.get('port', 443)}"
            self.data[key] = {
                "fingerprint": e.get("fingerprint", ""),
                "not_after": e.get("not_after"),
                "issuer": e.get("issuer", ""),
            }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False),
                             encoding="utf-8")
