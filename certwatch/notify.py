"""Notifikasi saat ada sertifikat yang perlu perhatian."""
from __future__ import annotations

import os
import subprocess


def notify(command: str, subject: str, detail: str) -> bool:
    """Jalankan perintah notifikasi dengan env CERTWATCH_SUBJECT / CERTWATCH_DETAIL."""
    if not command:
        return False
    env = {**os.environ,
           "CERTWATCH_SUBJECT": subject,
           "CERTWATCH_DETAIL": detail[:4000]}
    try:
        p = subprocess.run(command, shell=True, env=env, capture_output=True,
                           text=True, timeout=60)
        return p.returncode == 0
    except Exception:                      # noqa: BLE001
        return False


def build_message(rows: list[tuple], changes: list[dict]) -> tuple[str, str]:
    """Susun (subject, detail) dari daftar (CertInfo, Urgency)."""
    penting = [r for r in rows if r[1].value in ("EXPIRED", "CRITICAL", "WARNING", "ERROR")]
    if not penting and not changes:
        return "", ""
    judul = f"certwatch: {len(penting)} sertifikat perlu perhatian"
    baris = [f"• {c.key} — {u.value} ({c.days_left if c.days_left is not None else c.error})"
             for c, u in penting[:20]]
    if changes:
        baris.append("")
        baris += [f"• perubahan: {ch['key']} — {ch['kind']}" for ch in changes[:10]]
    return judul, "\n".join(baris)
