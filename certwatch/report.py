"""Penyusun laporan certwatch: teks, Markdown, JSON, CSV."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
from pathlib import Path

from .model import Report, Urgency


def to_text(r: Report) -> str:
    bar = "=" * 78
    L = [bar, "  CERTWATCH — masa berlaku & perubahan sertifikat TLS", bar]
    L.append(f"waktu      : {r.started} → {r.finished}")
    L.append(f"ambang     : peringatan ≤ {r.warn_days} hari, kritis ≤ {r.crit_days} hari")
    L.append(f"kesimpulan : {r.worst.symbol} {r.worst.value}   "
             f"({len(r.checked)} host diperiksa)")
    L.append("")
    L.append(f"  {'HOST':<34}{'HARI':>6}  {'STATUS':<10}{'PENERBIT':<28}{'BERLAKU SAMPAI'}")
    L.append("-" * 78)
    for c, u in r.by_urgency():
        hari = "—" if c.days_left is None else f"{c.days_left}"
        sampai = c.not_after.date().isoformat() if c.not_after else (c.error[:22] or "—")
        L.append(f"{u.symbol} {c.key:<34}{hari:>6}  {u.value:<10}"
                 f"{c.issuer[:26]:<28}{sampai}")
    if r.changes:
        L.append("")
        L.append("PERUBAHAN SEJAK PEMERIKSAAN TERAKHIR")
        L.append("-" * 78)
        for ch in r.changes:
            L.append(f"  • {ch['key']} — {ch['kind']}: {ch['detail']}")
    if r.errors:
        L.append("\nERROR")
        L.append("-" * 78)
        L.extend(f"  {e}" for e in r.errors)
    return "\n".join(L)


def to_markdown(r: Report) -> str:
    L = ["# Certwatch — masa berlaku sertifikat", ""]
    L.append(f"- **Waktu**: {r.started} → {r.finished}")
    L.append(f"- **Ambang**: peringatan ≤ {r.warn_days} hari, kritis ≤ {r.crit_days} hari")
    L.append(f"- **Kesimpulan**: **{r.worst.value}** ({len(r.checked)} host)")
    L.append("")
    L.append("| Status | Host | Sisa hari | Berlaku sampai | Penerbit |")
    L.append("|---|---|---|---|---|")
    for c, u in r.by_urgency():
        hari = "—" if c.days_left is None else c.days_left
        sampai = c.not_after.date().isoformat() if c.not_after else (c.error or "—")
        L.append(f"| {u.value} | `{c.key}` | {hari} | {sampai} | {c.issuer} |")
    if r.changes:
        L.append("")
        L.append("## Perubahan")
        L.append("")
        for ch in r.changes:
            L.append(f"- `{ch['key']}` — **{ch['kind']}**: {ch['detail']}")
    return "\n".join(L)


def to_json(r: Report) -> str:
    return json.dumps(r.as_dict(), indent=2, ensure_ascii=False)


def to_csv(r: Report) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "port", "status", "sisa_hari", "berlaku_sampai",
                "penerbit", "subject", "tls", "sidik_jari_sha256", "error"])
    for c, u in r.by_urgency():
        w.writerow([c.host, c.port, u.value,
                    "" if c.days_left is None else c.days_left,
                    c.not_after.date().isoformat() if c.not_after else "",
                    c.issuer, c.subject, c.tls_version, c.fingerprint, c.error])
    return buf.getvalue()


def write(outdir: Path, r: Report, formats: list[str]) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"certwatch-{stamp}"
    written: list[Path] = []
    for fmt, renderer, ext in (("text", to_text, "txt"), ("md", to_markdown, "md"),
                               ("json", to_json, "json"), ("csv", to_csv, "csv")):
        if fmt in formats:
            p = outdir / f"{base}.{ext}"
            p.write_text(renderer(r), encoding="utf-8")
            written.append(p)
    return written
