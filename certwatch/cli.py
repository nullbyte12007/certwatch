"""CLI certwatch.

    python3 -m certwatch example.com
    python3 -m certwatch --file targets.txt --warn-days 21
    python3 -m certwatch a.com b.com:8443 --state ~/.cache/certwatch.json
    python3 -m certwatch --file targets.txt --notify "openclaw message send ..."
    python3 -m certwatch --file targets.txt --out laporan --format md,csv,json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import __version__
from . import notify as notify_mod
from . import report as report_mod
from .checker import check
from .model import CRIT_DAYS, WARN_DAYS, Report, Urgency
from .state import State, load_targets, parse_targets


def _split(v: str | None) -> list[str] | None:
    return [x.strip() for x in v.split(",") if x.strip()] if v else None


def run_check(targets, warn_days=WARN_DAYS, crit_days=CRIT_DAYS, workers=8,
              timeout=10.0, verify=True, progress=None) -> Report:
    rep = Report(started=dt.datetime.now().isoformat(timespec="seconds"),
                 warn_days=warn_days, crit_days=crit_days)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(check, h, p, timeout, verify): (h, p) for h, p in targets}
        for fut in as_completed(futs):
            host, port = futs[fut]
            try:
                info = fut.result()
            except Exception as exc:                   # noqa: BLE001
                rep.errors.append(f"{host}:{port}: {type(exc).__name__}: {exc}")
                continue
            rep.checked.append(info)
            if progress:
                progress(info)
    rep.finished = dt.datetime.now().isoformat(timespec="seconds")
    return rep


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="certwatch",
        description="Pantau masa berlaku & perubahan sertifikat TLS (banyak host sekaligus)")
    ap.add_argument("hosts", nargs="*", help="host atau host:port")
    ap.add_argument("--file", help="berkas daftar target (satu per baris, # komentar)")
    ap.add_argument("--warn-days", type=int, default=WARN_DAYS)
    ap.add_argument("--crit-days", type=int, default=CRIT_DAYS)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--no-verify", action="store_true",
                    help="jangan validasi sertifikat (untuk sertifikat internal/self-signed)")
    ap.add_argument("--state", help="berkas riwayat untuk deteksi perubahan sertifikat")
    ap.add_argument("--notify", help="perintah yang dijalankan bila ada peringatan")
    ap.add_argument("--out", help="folder laporan")
    ap.add_argument("--format", help="text,md,json,csv")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--fail-on-warn", action="store_true",
                    help="exit ≠ 0 juga saat status WARNING")
    ap.add_argument("--version", action="version", version=f"certwatch {__version__}")
    args = ap.parse_args(argv)

    targets = []
    for h in args.hosts:
        targets += parse_targets(h)
    if args.file:
        try:
            targets += load_targets(args.file)
        except FileNotFoundError as exc:
            print(exc, file=sys.stderr)
            return 2
    # buang duplikat, pertahankan urutan
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    targets = uniq

    if not targets:
        print("tidak ada target. Contoh: certwatch example.com  atau  --file targets.txt",
              file=sys.stderr)
        return 2

    state = State(args.state) if args.state else None

    def progress(info) -> None:
        if args.quiet:
            return
        u = info.urgency(args.warn_days, args.crit_days)
        sisa = "—" if info.days_left is None else f"{info.days_left} hari"
        print(f"  {u.symbol} {info.key:<34} {u.value:<9} {sisa}", file=sys.stderr)

    rep = run_check(targets, args.warn_days, args.crit_days, args.workers,
                    args.timeout, not args.no_verify, progress)

    if state:
        for c in rep.checked:
            ch = state.diff(c.key, c.fingerprint,
                            c.not_after.isoformat() if c.not_after else None)
            if ch:
                rep.changes.append(ch)
        state.update([c.as_dict() for c in rep.checked])
        state.save()

    if args.json and not args.out:
        print(report_mod.to_json(rep))
    elif not args.out:
        print(report_mod.to_text(rep))

    if args.out:
        formats = _split(args.format) or ["text", "md", "json"]
        for p in report_mod.write(Path(args.out).expanduser(), rep, formats):
            print(f"  -> {p}")

    if args.notify:
        subject, detail = notify_mod.build_message(rep.by_urgency(), rep.changes)
        if subject:
            ok = notify_mod.notify(args.notify, subject, detail)
            print(f"  notifikasi: {'terkirim' if ok else 'GAGAL'}", file=sys.stderr)

    worst = rep.worst
    if worst in (Urgency.ERROR, Urgency.EXPIRED, Urgency.CRITICAL):
        return 1
    if args.fail_on_warn and worst is Urgency.WARNING:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
