"""Pengambil informasi sertifikat lewat TLS handshake (stdlib ssl)."""
from __future__ import annotations

import datetime as dt
import hashlib
import socket
import ssl

from .model import CertInfo


def _parse_date(value: str) -> dt.datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return dt.datetime.strptime(value, fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def _cn(parts) -> str:
    try:
        return dict(x[0] for x in parts).get("commonName", "")
    except Exception:                      # noqa: BLE001
        return ""


def _org(parts) -> str:
    try:
        d = dict(x[0] for x in parts)
        return d.get("organizationName") or d.get("commonName") or ""
    except Exception:                      # noqa: BLE001
        return ""


def check(host: str, port: int = 443, timeout: float = 10.0,
          verify: bool = True) -> CertInfo:
    """Ambil sertifikat dari host:port. Tidak pernah melempar — kegagalan jadi CertInfo(ok=False)."""
    info = CertInfo(host=host, port=port)
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                info.tls_version = ss.version() or ""
                info.cipher = (ss.cipher() or [None])[0] or ""
                der = ss.getpeercert(binary_form=True) or b""
                info.fingerprint = hashlib.sha256(der).hexdigest()
                cert = ss.getpeercert() or {}
                info.subject = _cn(cert.get("subject", []))
                info.issuer = _org(cert.get("issuer", []))
                info.not_before = _parse_date(cert.get("notBefore", ""))
                info.not_after = _parse_date(cert.get("notAfter", ""))
                info.sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    except ssl.SSLCertVerificationError as exc:
        info.ok = False
        info.error = f"verifikasi gagal: {str(exc)[:160]}"
        return info
    except Exception as exc:               # noqa: BLE001
        info.ok = False
        info.error = f"{type(exc).__name__}: {exc}"
        return info

    if info.not_after:
        info.days_left = (info.not_after - dt.datetime.now(dt.timezone.utc)).days
    return info
