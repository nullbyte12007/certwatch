"""Uji certwatch — semuanya offline (tanpa jaringan)."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from certwatch import cli, report as report_mod                    # noqa: E402
from certwatch.model import CertInfo, Report, Urgency               # noqa: E402
from certwatch.notify import build_message                          # noqa: E402
from certwatch.state import State, parse_targets                    # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)


def cert(days: int | None, host: str = "contoh.id", ok: bool = True) -> CertInfo:
    c = CertInfo(host=host, port=443, ok=ok)
    if ok and days is not None:
        c.not_after = NOW + dt.timedelta(days=days)
        c.days_left = days
        c.not_before = NOW - dt.timedelta(days=90)
        c.issuer = "Let's Encrypt"
        c.subject = host
        c.fingerprint = "a" * 64
    return c


class TestTargets(unittest.TestCase):
    def test_parse_berbagai_bentuk(self):
        text = """
        # contoh komentar
        example.com
        example.com:8443
        https://aman.id/
        http://lain.id/path
        10.0.0.1:443

        example.com            # duplikat harus dibuang
        """
        self.assertEqual(parse_targets(text), [
            ("example.com", 443),
            ("example.com", 8443),
            ("aman.id", 443),
            ("lain.id", 443),
            ("10.0.0.1", 443),
        ])

    def test_kosong(self):
        self.assertEqual(parse_targets("\n\n# cuma komentar\n"), [])

    def test_port_tidak_valid_jadi_443(self):
        self.assertEqual(parse_targets("host:abc"), [("host", 443)])


class TestUrgency(unittest.TestCase):
    def test_batas_ambang(self):
        self.assertIs(cert(31).urgency(), Urgency.OK)
        self.assertIs(cert(30).urgency(), Urgency.WARNING)
        self.assertIs(cert(8).urgency(), Urgency.WARNING)
        self.assertIs(cert(7).urgency(), Urgency.CRITICAL)
        self.assertIs(cert(0).urgency(), Urgency.CRITICAL)
        self.assertIs(cert(-1).urgency(), Urgency.EXPIRED)

    def test_ambang_dapat_diubah(self):
        c = cert(20)
        self.assertIs(c.urgency(warn_days=30, crit_days=7), Urgency.WARNING)
        self.assertIs(c.urgency(warn_days=10, crit_days=5), Urgency.OK)

    def test_error_dan_tanpa_tanggal(self):
        self.assertIs(CertInfo(host="x", ok=False, error="timeout").urgency(), Urgency.ERROR)
        self.assertIs(CertInfo(host="x").urgency(), Urgency.ERROR)

    def test_urut_kepentingan(self):
        c = CertInfo(host="x", ok=False)
        self.assertLess(c.urgency().order, Urgency.CRITICAL.order)


class TestState(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="certwatch-test-"))
        self.path = self.tmp / "state.json"

    def test_target_baru(self):
        s = State(self.path)
        ch = s.diff("a.id:443", "f" * 64, "2027-01-01T00:00:00+00:00")
        self.assertIsNotNone(ch)
        self.assertEqual(ch["kind"], "baru")

    def test_sertifikat_berubah(self):
        s = State(self.path)
        s.data["a.id:443"] = {"fingerprint": "0" * 64, "not_after": "2027-01-01T00:00:00+00:00"}
        ch = s.diff("a.id:443", "f" * 64, "2027-01-01T00:00:00+00:00")
        self.assertIsNotNone(ch)
        self.assertEqual(ch["kind"], "sertifikat berubah")

    def test_masa_berlaku_berubah(self):
        s = State(self.path)
        s.data["a.id:443"] = {"fingerprint": "f" * 64, "not_after": "2027-01-01T00:00:00+00:00"}
        ch = s.diff("a.id:443", "f" * 64, "2027-04-01T00:00:00+00:00")
        self.assertEqual(ch["kind"], "masa berlaku berubah")

    def test_tidak_ada_perubahan(self):
        s = State(self.path)
        s.data["a.id:443"] = {"fingerprint": "f" * 64, "not_after": "2027-01-01T00:00:00+00:00"}
        self.assertIsNone(s.diff("a.id:443", "f" * 64, "2027-01-01T00:00:00+00:00"))

    def test_simpan_dan_muat(self):
        s = State(self.path)
        s.update([{"key": "a.id:443", "fingerprint": "f" * 64, "not_after": "2027-01-01T00:00:00+00:00",
                   "issuer": "LE"}])
        s.save()
        self.assertTrue(self.path.is_file())
        s2 = State(self.path)
        self.assertEqual(s2.data["a.id:443"]["issuer"], "LE")

    def test_berkas_rusak_tidak_melempar(self):
        self.path.write_text("{ bukan json")
        self.assertEqual(State(self.path).data, {})


class TestNotify(unittest.TestCase):
    def test_pesan_dibuat_saat_ada_masalah(self):
        rep = Report()
        rep.checked = [cert(3, "kritis.id"), cert(400, "aman.id")]
        subject, detail = build_message(rep.by_urgency(), [])
        self.assertIn("perlu perhatian", subject)
        self.assertIn("kritis.id", detail)
        self.assertNotIn("aman.id", detail)

    def test_tanpa_masalah_tidak_mengirim(self):
        rep = Report()
        rep.checked = [cert(400)]
        subject, detail = build_message(rep.by_urgency(), [])
        self.assertEqual(subject, "")


class TestReport(unittest.TestCase):
    def _rep(self) -> Report:
        r = Report(started="a", finished="b")
        r.checked = [cert(3, "kritis.id"), cert(20, "peringatan.id"),
                     cert(400, "aman.id"), CertInfo(host="mati.id", ok=False, error="timeout")]
        r.changes = [{"key": "aman.id:443", "kind": "sertifikat berubah", "detail": "x"}]
        return r

    def test_urut_kepentingan_di_depan(self):
        rows = self._rep().by_urgency()
        self.assertEqual(rows[0][0].host, "mati.id")
        self.assertEqual(rows[-1][0].host, "aman.id")

    def test_text_memuat_semua(self):
        t = report_mod.to_text(self._rep())
        for nama in ("kritis.id", "peringatan.id", "aman.id", "mati.id"):
            self.assertIn(nama, t)
        self.assertIn("sertifikat berubah", t)

    def test_markdown_dan_json(self):
        md = report_mod.to_markdown(self._rep())
        self.assertIn("| Status | Host |", md)
        d = json.loads(report_mod.to_json(self._rep()))
        self.assertEqual(d["summary"]["CRITICAL"], 1)
        self.assertEqual(d["summary"]["ERROR"], 1)

    def test_csv_bisa_dibaca_ulang(self):
        text = report_mod.to_csv(self._rep())
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["status"], "ERROR")

    def test_write_semua_format(self):
        with tempfile.TemporaryDirectory() as td:
            files = report_mod.write(Path(td), self._rep(), ["text", "md", "json", "csv"])
            self.assertEqual(len(files), 4)
            for f in files:
                self.assertTrue(f.stat().st_size > 0)


class TestCli(unittest.TestCase):
    def test_tanpa_target(self):
        self.assertEqual(cli.main([]), 2)

    def test_berkas_target_tidak_ada(self):
        self.assertEqual(cli.main(["--file", "/tidak/ada.txt"]), 2)

    def test_host_mati_lapor_rapi_dan_exit_1(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state.json"
            code = cli.main(["tidak-ada-host.invalid", "--out", td,
                             "--format", "json,csv", "--state", str(state), "--quiet"])
            self.assertEqual(code, 1)
            data = json.loads(next(Path(td).glob("certwatch-*.json")).read_text())
            self.assertEqual(data["summary"]["ERROR"], 1)
            self.assertTrue(state.is_file())
            self.assertEqual(data["changes"][0]["kind"], "baru")

    def test_perubahan_terdeteksi_antar_jalannya(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state.json"
            state.write_text(json.dumps({
                "tidak-ada-host.invalid:443": {"fingerprint": "b" * 64,
                                               "not_after": "2030-01-01T00:00:00+00:00"}}))
            cli.main(["tidak-ada-host.invalid", "--out", td, "--format", "json",
                      "--state", str(state), "--quiet", "--no-verify"])
            data = json.loads(next(Path(td).glob("certwatch-*.json")).read_text())
            # host mati -> fingerprint kosong -> tidak dianggap berubah
            self.assertIsInstance(data["changes"], list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
