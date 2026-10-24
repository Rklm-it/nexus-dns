"""Устройства (клиенты AdGuard Home) и их профили.

У каждого устройства свой секретный ClientID. Он же — пропуск: в «разрешённые
клиенты» AdGuard Home попадают только ClientID, поэтому запрос без него (или с
чужим) получает REFUSED. Голый IP 127.0.0.1 туда класть нельзя никогда: весь
DoH приходит от nginx с этого адреса, и он открыл бы DNS всем.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import string
from typing import Any

from .agh import AGH
from .config import Config

SELFTEST_NAME = "nexus-самопроверка"

_SAFE_SEARCH_ON = {
    "enabled": True, "bing": True, "duckduckgo": True, "ecosia": True,
    "google": True, "pixabay": True, "yandex": True, "youtube": True,
}

# Реклама, трекеры и прокси ИИ — у всех (глобальные настройки). Детский
# профиль добавляет взрослый контент (родительский контроль AdGuard) и
# безопасный поиск. filtering_enabled у детей обязан быть True: на нём
# держатся и блок-листы, и подмена адресов для прокси.
PROFILES: dict[str, dict[str, Any]] = {
    "family": {
        "title": "семья: без рекламы, ИИ через прокси",
        "tags": ["user_regular"],
        "settings": {"use_global_settings": True},
    },
    "kids": {
        "title": "ребёнок: + взрослые сайты закрыты, безопасный поиск",
        "tags": ["user_child"],
        "settings": {
            "use_global_settings": False,
            "filtering_enabled": True,
            "parental_enabled": True,
            "safebrowsing_enabled": True,
            "safe_search": _SAFE_SEARCH_ON,
        },
    },
}

_ID_RE = re.compile(r"^[a-z][a-z0-9]{9}$")


class ClientError(RuntimeError):
    pass


def new_client_id() -> str:
    """10 символов, первая — буква: годится и в поддомен (DoT), и в путь (DoH)."""
    alphabet = string.ascii_lowercase + string.digits
    return secrets.choice(string.ascii_lowercase) + "".join(
        secrets.choice(alphabet) for _ in range(9)
    )


def profile_of(client: dict[str, Any]) -> str:
    return "kids" if "user_child" in (client.get("tags") or []) else "family"


def client_body(name: str, client_id: str, profile: str) -> dict[str, Any]:
    p = PROFILES[profile]
    body: dict[str, Any] = {
        "name": name,
        "ids": [client_id],
        "tags": list(p["tags"]),
        "use_global_blocked_services": True,
        "upstreams": [],
        "ignore_querylog": False,
        "ignore_statistics": False,
    }
    body.update(p["settings"])
    return body


def list_clients(agh: AGH) -> list[dict[str, Any]]:
    return list((agh.get("clients") or {}).get("clients") or [])


def find_client(agh: AGH, key: str) -> dict[str, Any]:
    key_l = key.lower()
    for c in list_clients(agh):
        if c["name"].lower() == key_l or key_l in [i.lower() for i in c.get("ids") or []]:
            return c
    raise ClientError(f"нет устройства «{key}» (nexus-dns client list)")


def add_client(agh: AGH, cfg: Config, name: str, profile: str) -> dict[str, Any]:
    if profile not in PROFILES:
        raise ClientError(f"нет профиля {profile}; есть: {', '.join(PROFILES)}")
    taken = {i for c in list_clients(agh) for i in c.get("ids") or []}
    if name.lower() in {c["name"].lower() for c in list_clients(agh)}:
        raise ClientError(f"устройство «{name}» уже есть — другое имя или client show")
    client_id = new_client_id()
    while client_id in taken or client_id == cfg.selftest_id:
        client_id = new_client_id()
    body = client_body(name, client_id, profile)
    agh.post("clients/add", body)
    sync_access(agh, cfg)
    return body


def remove_client(agh: AGH, cfg: Config, key: str) -> dict[str, Any]:
    client = find_client(agh, key)
    if client["name"] == SELFTEST_NAME:
        raise ClientError("служебное устройство самопроверки не удаляется")
    agh.post("clients/delete", {"name": client["name"]})
    sync_access(agh, cfg)
    return client


def ensure_selftest(agh: AGH, cfg: Config) -> None:
    for c in list_clients(agh):
        if c["name"] == SELFTEST_NAME:
            if cfg.selftest_id in (c.get("ids") or []):
                return
            agh.post("clients/delete", {"name": SELFTEST_NAME})
    body = client_body(SELFTEST_NAME, cfg.selftest_id, "family")
    body.update(ignore_querylog=True, ignore_statistics=True)
    agh.post("clients/add", body)


def _is_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_network(value, strict=False).is_loopback
    except ValueError:
        return False


def allowed_ids(clients: list[dict[str, Any]], selftest_id: str) -> list[str]:
    ids = [selftest_id]
    for c in clients:
        for i in c.get("ids") or []:
            if not _is_loopback(i) and i not in ids:
                ids.append(i)
    return ids


def sync_access(agh: AGH, cfg: Config) -> list[str]:
    """Разрешённые клиенты = все устройства. Пустой список в AdGuard Home
    значит «пускать всех», поэтому самопроверка там есть всегда."""
    current = agh.get("access/list") or {}
    allowed = allowed_ids(list_clients(agh), cfg.selftest_id)
    agh.post(
        "access/set",
        {
            "allowed_clients": allowed,
            "disallowed_clients": current.get("disallowed_clients") or [],
            "blocked_hosts": current.get("blocked_hosts")
            or ["version.bind", "id.server", "hostname.bind"],
        },
    )
    return allowed


def howto(cfg: Config, name: str, client_id: str, profile: str) -> str:
    dot = cfg.dot_host(client_id)
    doh = cfg.doh_url(client_id)
    return f"""\
Устройство «{name}» — профиль {profile} ({PROFILES[profile]['title']})

  Без VPN — Android 9+:  Настройки → Подключение и общий доступ (или «Сеть») →
                 Частный DNS → Имя хоста →  {dot}
  iPhone, браузер, Windows 11 (DoH):
                 {doh}
  Роутер (DoT, если умеет):  tls://{dot}

  С VPN (любым, и для обхода белых списков) — DoH в настройках VPN-приложения,
  поле «Удалённый DNS» / Remote DNS (v2rayNG, Hiddify, Happ — раздел DNS):
                 {doh}
  а Частный DNS в Android — «Автоматически». Так DNS идёт внутри туннеля и
  работает под белыми списками, а VPN не ждёт наш DNS, чтобы подключиться.
  (Строгий Частный DNS при VPN тоже работает, но под белыми списками VPN с
  доменом в адресе сервера не поднимется: найти сервер ему нечем.)

Адрес личный: по нему видно, чьи запросы, и с ним работает профиль.
Не публикуй — потерялся, удали устройство и заведи заново.
Без VPN под белыми списками мобильного оператора сервер недоступен, и Android
с Частным DNS покажет «нет интернета» — переключить на «Автоматически»."""


def describe(clients: list[dict[str, Any]]) -> list[str]:
    rows = []
    for c in clients:
        if c["name"] == SELFTEST_NAME:
            continue
        ids = ", ".join(c.get("ids") or [])
        rows.append(f"{c['name']:<24} {profile_of(c):<7} {ids}")
    return rows

