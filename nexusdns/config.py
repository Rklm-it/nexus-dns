"""Настройки сервера: /etc/nexus-dns/nexus-dns.env (пишет install.sh)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ENV_FILE = Path(os.environ.get("NEXUS_DNS_ENV", "/etc/nexus-dns/nexus-dns.env"))
NGINX_CONF = Path(os.environ.get("NEXUS_DNS_NGINX_CONF", "/etc/nginx/nexus-dns/stream.conf"))
NGINX_SITE_CONF = Path(os.environ.get("NEXUS_DNS_NGINX_SITE", "/etc/nginx/conf.d/nexus-dns-site.conf"))
CERT_DIR = Path("/etc/letsencrypt/live/nexus-dns")
SITE_ROOT = Path(os.environ.get("NEXUS_DNS_SITE_ROOT", "/var/lib/nexus-dns/site"))
# Локальные списки AdGuard Home берёт только отсюда (filtering.safe_fs_patterns).
USERFILTERS = Path(os.environ.get("NEXUS_DNS_USERFILTERS", "/opt/AdGuardHome/userfilters"))

AGH_URL = "http://127.0.0.1:3000"
DOH_PORT = 8443  # HTTPS AdGuard Home на 127.0.0.1, снаружи — через nginx на 443
PLAIN_PORT = 5300  # обычный DNS: только для порядка, снаружи закрыт файрволом


class ConfigError(RuntimeError):
    pass


def parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out[key.strip()] = value
    return out


@dataclass(frozen=True)
class Config:
    dns_domain: str
    public_ip: str
    agh_user: str
    agh_password: str
    agh_url: str = AGH_URL
    doh_port: int = DOH_PORT

    @classmethod
    def load(cls, path: Path = ENV_FILE) -> "Config":
        if not path.exists():
            raise ConfigError(f"нет {path} — сервер ещё не установлен (install.sh)")
        env = parse_env(path.read_text(encoding="utf-8"))
        need = ["DNS_DOMAIN", "PUBLIC_IP", "AGH_USER", "AGH_PASSWORD"]
        missing = [k for k in need if not env.get(k)]
        if missing:
            raise ConfigError(f"в {path} не заданы: {', '.join(missing)}")
        return cls(
            dns_domain=env["DNS_DOMAIN"].lower(),
            public_ip=env["PUBLIC_IP"],
            agh_user=env["AGH_USER"],
            agh_password=env["AGH_PASSWORD"],
            agh_url=env.get("AGH_URL") or AGH_URL,
            doh_port=int(env.get("DOH_PORT") or DOH_PORT),
        )

    @property
    def doh_url(self) -> str:
        return f"https://{self.dns_domain}/dns-query"
