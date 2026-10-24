"""A-запись DNS-сервера в Cloudflare (необязательно: если домен там и дан токен).

Облако серое: через прокси Cloudflare DoT (853) не ходит вовсе, а 443 он
расшифрует своим сертификатом.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API = "https://api.cloudflare.com/client/v4"


class CloudflareError(RuntimeError):
    pass


class Cloudflare:
    def __init__(self, token: str, timeout: float = 20):
        self.token = token
        self.timeout = timeout

    def call(self, method: str, path: str, body: Any = None) -> Any:
        req = urllib.request.Request(
            f"{API}{path}",
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            data = _json_or_text(e.read())
            raise CloudflareError(f"Cloudflare {method} {path}: {e.code} {_errors(data)}") from None
        except (urllib.error.URLError, OSError) as e:
            raise CloudflareError(f"Cloudflare API недоступен: {e}") from None
        if not data.get("success"):
            raise CloudflareError(f"Cloudflare {method} {path}: {_errors(data)}")
        return data["result"]

    def find_zone(self, fqdn: str) -> dict[str, Any]:
        labels = fqdn.split(".")
        for i in range(len(labels) - 1):
            name = ".".join(labels[i:])
            zones = self.call("GET", f"/zones?name={urllib.parse.quote(name)}")
            if zones:
                return zones[0]
        raise CloudflareError(
            f"зоны для {fqdn} нет в этом аккаунте Cloudflare (или у токена нет Zone:Read)"
        )

    def upsert_a(self, zone_id: str, name: str, ip: str) -> str:
        found = self.call("GET", f"/zones/{zone_id}/dns_records?type=A&name={urllib.parse.quote(name)}")
        record = {"type": "A", "name": name, "content": ip, "ttl": 300, "proxied": False}
        if found:
            rec = found[0]
            if rec["content"] == ip and not rec.get("proxied"):
                return f"{name} → {ip} (уже)"
            self.call("PUT", f"/zones/{zone_id}/dns_records/{rec['id']}", record)
            return f"{name} → {ip} (обновлена)"
        self.call("POST", f"/zones/{zone_id}/dns_records", record)
        return f"{name} → {ip} (создана)"


def ensure_records(token: str, dns_domain: str, ip: str) -> list[str]:
    cf = Cloudflare(token)
    zone = cf.find_zone(dns_domain)
    return [cf.upsert_a(zone["id"], dns_domain, ip)]


def _json_or_text(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def _errors(data: Any) -> str:
    if isinstance(data, dict) and data.get("errors"):
        return "; ".join(f"{e.get('code')}: {e.get('message')}" for e in data["errors"])
    return str(data)[:300]
