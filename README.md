# certwatch

**Pantau masa berlaku & perubahan sertifikat TLS** untuk banyak host sekaligus.

Sertifikat yang kedaluwarsa adalah salah satu penyebab outage paling memalukan — dan paling
mudah dicegah. `certwatch` memberi peringatan jauh sebelum tanggal merah, dan memberi tahu
kalau sertifikat berubah di luar perkiraan.

[![CI](https://github.com/nullbyte12007/certwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/nullbyte12007/certwatch/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Zero deps](https://img.shields.io/badge/dependencies-none-success)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Keluaran contoh

```
$ certwatch --file targets.txt --state ~/.cache/certwatch.json
  ✅ cloudflare.com:443                 OK        63 hari
  ✅ github.com:443                     OK        58 hari
  ✅ example.com:443                    OK        84 hari

==============================================================================
  CERTWATCH — masa berlaku & perubahan sertifikat TLS
==============================================================================
ambang     : peringatan ≤ 30 hari, kritis ≤ 7 hari
kesimpulan : ✅ OK   (4 host diperiksa)

  HOST                                HARI  STATUS    PENERBIT                    BERLAKU SAMPAI
------------------------------------------------------------------------------
✅ github.com:443                        58  OK        Sectigo Limited             2026-11-29
✅ cloudflare.com:443                    63  OK        Google Trust Services       2026-12-04
✅ example.com:443                       84  OK        SSL Corporation             2026-12-25

PERUBAHAN SEJAK PEMERIKSAAN TERAKHIR
------------------------------------------------------------------------------
  • cloudflare.com:443 — baru: target pertama kali dipantau
```

Kalau ada yang mendekati kedaluwarsa, urutannya otomatis naik ke atas dengan 🔴/⛔ —
dan `--notify` bisa langsung mengirim peringatan ke WhatsApp/Telegram/Slack.

## Instalasi & pemakaian

Zero dependency — cukup standard library Python 3.10+ (memakai modul `ssl` bawaan).

```bash
git clone https://github.com/nullbyte12007/certwatch
cd certwatch

python3 -m certwatch example.com github.com          # host langsung
python3 -m certwatch --file targets.txt              # dari berkas
python3 -m certwatch --file targets.txt --warn-days 21 --crit-days 5
python3 -m certwatch --file targets.txt --state ~/.cache/certwatch.json
python3 -m certwatch --file targets.txt --out laporan --format md,csv,json
```

Berkas target sederhana — satu per baris, `#` untuk komentar:

```
example.com
internal.corp:8443
https://situs.id/
```

**Exit code**: `1` bila ada sertifikat **kedaluwarsa / kritis / tidak bisa dicek** — langsung
bisa dipakai di cron/monitoring. Tambahkan `--fail-on-warn` bila peringatan juga harus menggagalkan.

## Yang diperiksa

| | |
|---|---|
| **Sisa hari** | Sampai kedaluwarsa, dengan ambang bisa diatur (`--warn-days`, `--crit-days`) |
| **Status** | `OK` · `WARNING` (≤30 hari) · `CRITICAL` (≤7 hari) · `EXPIRED` · `ERROR` |
| **Penerbit & subject** | Siapa yang menerbitkan, untuk CN apa |
| **Masa berlaku** | Tanggal berlaku sampai |
| **Sidik jari SHA-256** | Untuk mendeteksi sertifikat berubah |
| **TLS** | Versi protokol & cipher yang dinegosiasikan |
| **SAN** | Nama alternatif di dalam sertifikat (JSON) |

**Deteksi perubahan** (`--state`): pada setiap pemeriksaan, sidik jari dan masa berlaku
dibandingkan dengan riwayat. Kalau sertifikat berganti lebih cepat dari siklus renewal normal,
itu bisa berarti renewal biasa — atau penerbitan yang tidak seharusnya. Berguna juga sebagai
jaring pengaman kalau ada yang menukar sertifikat tanpa memberi tahu tim.

## Dipakai otomatis

```ini
# ~/.config/systemd/user/certwatch.service
[Unit]
Description=Pemeriksaan sertifikat harian

[Service]
Type=oneshot
ExecStart=%h/projects/certwatch/.venv/bin/python -m certwatch \
  --file %h/certwatch/targets.txt \
  --state %h/.cache/certwatch.json \
  --out %h/certwatch-reports --format md,csv \
  --notify "openclaw message send --channel whatsapp --target +628xxx --message \"$CERTWATCH_SUBJECT\""
```

```ini
# ~/.config/systemd/user/certwatch.timer
[Timer]
OnCalendar=*-*-* 07:00:00
Persistent=true
```

Atau satu baris cron:
```
0 7 * * * /usr/bin/python3 -m certwatch --file ~/certwatch/targets.txt --state ~/.cache/certwatch.json
```

## Format laporan

Teks (terminal), **Markdown**, **JSON**, dan **CSV** (untuk spreadsheet / dashboard).
Contoh CSV: `host,port,status,sisa_hari,berlaku_sampai,penerbit,subject,tls,sidik_jari_sha256,error`

## Desain

```
certwatch/
  cli.py       # argparse + paralelisasi pemeriksaan (ThreadPool)
  checker.py   # handshake TLS via stdlib ssl; kegagalan jadi status, bukan exception
  model.py     # CertInfo, Urgency (OK/WARNING/CRITICAL/EXPIRED/ERROR), Report
  state.py     # daftar target + riwayat untuk deteksi perubahan
  notify.py    # perintah notifikasi via env CERTWATCH_SUBJECT / CERTWATCH_DETAIL
  report.py    # render teks / Markdown / JSON / CSV
```

Keputusan desain yang disengaja:

1. **Tidak pernah melempar.** Host mati, port tertutup, handshake gagal — semuanya jadi
   `ERROR` dengan pesan singkat. Satu target bermasalah tidak boleh menggagalkan seluruh
   pemeriksaan.
2. **Logika murni dipisah.** Perhitungan sisa hari, klasifikasi urgensi, dan diff state adalah
   fungsi murni — sehingga 24 test berjalan **tanpa jaringan** dan tetap hijau di CI.

## Batasan yang jujur

- Memeriksa **sertifikat yang disajikan**, bukan konfigurasi web server. Ia tidak tahu apakah
  ada host lain di load balancer yang sertifikatnya berbeda, kecuali host itu didaftarkan.
- `--no-verify` hanya untuk sertifikat internal/self-signed. Dengan opsi itu, validitas tidak
  dinilai — hanya tanggal dan penerbit dibaca.
- Untuk sertifikat yang memakai SNI berbeda per nama, pastikan mendaftarkan nama yang benar
  (tool memakai nama host sebagai SNI).
- Tidak menghubungi Certificate Transparency; fokusnya operasional (kapan kedaluwarsa), bukan
  pemantauan penerbitan yang mencurigakan.
- Perbandingan perubahan memakai sidik jari: renewal normal juga akan terdeteksi sebagai
  "sertifikat berubah". Gunakan tanggal `not_after` untuk membedakan.

## Uji

```bash
python3 -m unittest discover -s tests -v     # 24 test, tanpa jaringan
```

## Lisensi

MIT — lihat [LICENSE](LICENSE). Copyright (c) 2026 M Yusuf Chairul Saleh.
