"""`nexus-dns status`: проверить сервер тем же путём, каким ходят телефоны.

Не «процесс запущен», а запрос снаружи: на публичный IP, через nginx, с
настоящим сертификатом.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import urllib.parse

from . import dnswire
from .config import Config
from .lists import LISTS_DIR, Lists, read_domains
from .site import MOBILECONFIG

TIMEOUT = 8


@dataclass
class Check:
    ok: bool
    title: str
    detail: str = ""


def _tls(ip: str, port: int, sni: str) -> ssl.SSLSocket:
    ctx = ssl.create_default_context()
    raw = socket.create_connection((ip, port), timeout=TIMEOUT)
    try:
        return ctx.wrap_socket(raw, server_hostname=sni)
    except Exception:
        raw.close()
        raise


def doh(ip: str, sni: str, path: str, name: str, qtype: str = "A") -> tuple[str, list[str]]:
    sock = _tls(ip, 443, sni)
    conn = http.client.HTTPSConnection(sni, 443, timeout=TIMEOUT)
    conn.sock = sock  # соединение уже открыто на нужный IP — http.client его возьмёт
    try:
        conn.request(
            "POST", path, body=dnswire.build_query(name, qtype),
            headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
        )
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    if resp.status != 200:
        raise RuntimeError(f"HTTP {resp.status}: {body[:120]!r}")
    return dnswire.parse_response(body)


def dot(ip: str, sni: str, name: str) -> tuple[str, list[str]]:
    with _tls(ip, 853, sni) as sock:
        q = dnswire.build_query(name)
        sock.sendall(struct.pack("!H", len(q)) + q)
        size = struct.unpack("!H", _read(sock, 2))[0]
        return dnswire.parse_response(_read(sock, size))


def _read(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("соединение закрыто посреди ответа")
        buf += chunk
    return buf


def cert_days_left(ip: str, sni: str) -> int:
    with _tls(ip, 443, sni) as sock:
        not_after = sock.getpeercert()["notAfter"]
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
    return (expires - datetime.now(timezone.utc)).days


def _service(name: str) -> Check:
    r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
    state = r.stdout.strip() or r.stderr.strip()
    return Check(state == "active", f"служба {name}", state)


def _try(title: str, fn, expect) -> Check:
    # Правила AdGuard Home перечитывает в фоне секунды после apply — даём шанс.
    last = ""
    for attempt in range(3):
        try:
            result = fn()
            ok, detail = expect(result)
            if ok or attempt == 2:
                return Check(ok, title, detail)
            last = detail
        except Exception as e:  # noqa: BLE001 — любая причина идёт на экран
            last = f"{type(e).__name__}: {e}"
            if attempt == 2:
                return Check(False, title, last)
        time.sleep(2)
    return Check(False, title, last)


def https_get(ip: str, host: str, path: str) -> tuple[int, bytes]:
    sock = _tls(ip, 443, host)
    conn = http.client.HTTPSConnection(host, 443, timeout=TIMEOUT)
    conn.sock = sock
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def protected_blocked(agh, root=LISTS_DIR) -> list[str]:
    """Домены из lists/protect.txt, которые живые блок-листы всё-таки режут."""
    bad = []
    for host in read_domains(root / "protect.txt"):
        r = agh.get("filtering/check_host?name=" + urllib.parse.quote(host)) or {}
        if str(r.get("reason", "")).startswith("Filtered"):
            rule = (r.get("rules") or [{}])[0].get("text", "")
            bad.append(f"{host} ({rule})")
    return bad


def run(cfg: Config, lists: Lists, services: bool = True, agh=None) -> list[Check]:
    ip, host, path = cfg.public_ip, cfg.dns_domain, "/dns-query"
    checks: list[Check] = []
    if services:
        checks += [_service("AdGuardHome"), _service("nginx")]

    def resolves(result):
        rcode, addrs = result
        return (rcode == "NOERROR" and bool(addrs)), f"{rcode} {', '.join(addrs[:2])}"

    checks.append(_try("DoH: обычный домен (example.com)", lambda: doh(ip, host, path, "example.com"), resolves))
    checks.append(_try("DoT :853 (Android, Частный DNS)", lambda: dot(ip, host, "example.com"), resolves))

    if lists.proxy:
        probe = lists.proxy[0]

        def to_us(result):
            rcode, addrs = result
            return addrs == [ip], f"{rcode} {', '.join(addrs) or '—'} (ждали {ip})"

        def no_v6(result):
            rcode, addrs = result
            return not addrs, f"{rcode} {', '.join(addrs) or 'пусто'}"

        checks.append(_try(f"прокси: {probe} → IP сервера", lambda: doh(ip, host, path, probe), to_us))
        checks.append(_try(f"прокси: {probe} без IPv6", lambda: doh(ip, host, path, probe, "AAAA"), no_v6))

        def handshake():
            with _tls(ip, 443, probe) as sock:
                return sock.version()

        checks.append(_try(f"прокси: TLS до настоящего {probe} через сервер", handshake, lambda v: (True, v)))

    if lists.block:
        target = lists.block[0]

        def blocked(result):
            rcode, addrs = result
            return addrs in ([], ["0.0.0.0"]), f"{rcode} {', '.join(addrs) or 'пусто'}"

        checks.append(_try(f"реклама: {target} заблокирован", lambda: doh(ip, host, path, target), blocked))

    def page(path: str, needle: bytes):
        def fn():
            return https_get(ip, host, path)

        def ok(result):
            status, body = result
            return status == 200 and needle in body, f"HTTP {status}"

        return fn, ok

    for title, path, needle in (
        ("сайт с инструкцией", "/", b"Nexus DNS"),
        ("профиль iPhone", f"/{MOBILECONFIG}", cfg.doh_url.encode()),
        ("панель на /admin/", "/admin/login.html", b"<html"),
    ):
        fn, ok = page(path, needle)
        checks.append(_try(title, fn, ok))

    if agh is not None:
        # Исключение (@@) в чужом списке перебивает нашу строку в block.txt —
        # молча. Ловим здесь, а не жалобой «реклама вернулась».
        loose = [h for h in lists.block
                 if not str((agh.get("filtering/check_host?name=" + urllib.parse.quote(h)) or {})
                            .get("reason", "")).startswith("Filtered")]
        checks.append(Check(not loose, "весь lists/block.txt блокируется",
                            "да" if not loose else "перебиты исключением: " + ", ".join(loose[:5])))
        bad = protected_blocked(agh)
        checks.append(Check(not bad, "важные сайты не заблокированы (lists/protect.txt)",
                            "все открываются" if not bad else "; ".join(bad[:5])))

    try:
        days = cert_days_left(ip, cfg.dns_domain)
        checks.append(Check(days > 14, "сертификат", f"ещё {days} дн."))
    except Exception as e:  # noqa: BLE001
        checks.append(Check(False, "сертификат", f"{type(e).__name__}: {e}"))
    return checks
