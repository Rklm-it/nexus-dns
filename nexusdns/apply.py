"""`nexus-dns apply`: привести AdGuard Home и nginx к состоянию из репо.

Повторный запуск безопасен: правила и списки человека, добавленные руками в
AdGuard Home, не трогаем — только свой блок правил и свои списки «nexus:».
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Callable

from .agh import AGH, AGHError
from .config import CERT_DIR, NGINX_CONF, Config
from .lists import Lists, agh_rules, merge_user_rules, nginx_stream_conf

FILTER_PREFIX = "nexus: "

UPSTREAMS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
]
BOOTSTRAP = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

DAY_MS = 24 * 3600 * 1000


def filter_name(url: str) -> str:
    tail = url.rstrip("/").rsplit("/", 2)
    return FILTER_PREFIX + "/".join(tail[-2:])


def dns_settings() -> dict[str, Any]:
    return {
        "upstream_dns": UPSTREAMS,
        "bootstrap_dns": BOOTSTRAP,
        "upstream_mode": "parallel",
        "cache_enabled": True,
        "cache_size": 16 * 1024 * 1024,
        "cache_optimistic": True,
        # Лимита по IP нет: весь DoH приходит от nginx с 127.0.0.1, а DoT под
        # VPN — с одного IP выхода ноды на всех её пользователей. Лимит в
        # 20 запросов/с на подсеть ронял бы DNS целой ноде. Усилителя атак
        # нет и без лимита: снаружи только TCP (DoT/DoH).
        "ratelimit": 0,
        "blocking_mode": "default",
        "dnssec_enabled": True,
    }


def tls_settings(cfg: Config, cert_dir: Path) -> dict[str, Any]:
    return {
        "enabled": True,
        "server_name": cfg.dns_domain,
        "force_https": False,
        "port_https": cfg.doh_port,
        "port_dns_over_tls": 853,
        "port_dns_over_quic": 853,
        "port_dnscrypt": 0,
        "dnscrypt_config_file": "",
        "certificate_chain": "",
        "private_key": "",
        "private_key_saved": False,
        "certificate_path": str(cert_dir / "fullchain.pem"),
        "private_key_path": str(cert_dir / "privkey.pem"),
        "serve_plain_dns": True,
    }


def configure_tls(agh: AGH, cfg: Config, cert_dir: Path) -> str:
    # На негодный сертификат AdGuard Home отвечает 200 и НИЧЕГО не применяет,
    # причина — только в warning_validation. Без этой проверки apply «прошёл»,
    # а DoT/DoH остались на старом сертификате или выключены.
    r = agh.post("tls/configure", tls_settings(cfg, cert_dir)) or {}
    if isinstance(r, dict) and r.get("valid_pair") is False:
        raise AGHError(f"AdGuard Home не принял сертификат: {r.get('warning_validation') or 'без причины'}")
    return f"TLS: DoT :853, DoH через :443 ({cfg.dns_domain})"


def sync_filters(agh: AGH, urls: list[str]) -> list[str]:
    log = []
    status = agh.get("filtering/status") or {}
    have = {f["url"]: f for f in status.get("filters") or []}
    for url in urls:
        f = have.get(url)
        if f is None:
            try:
                agh.post("filtering/add_url", {"name": filter_name(url), "url": url, "whitelist": False})
                log.append(f"+ список {filter_name(url)}")
            except AGHError as e:
                log.append(f"! список {url} не добавлен: {e}")
        elif not f.get("enabled"):
            agh.post(
                "filtering/set_url",
                {"url": url, "whitelist": False,
                 "data": {"name": f["name"], "url": url, "enabled": True}},
            )
            log.append(f"~ список {f['name']} включён")
    for url, f in have.items():
        if f["name"].startswith(FILTER_PREFIX) and url not in urls:
            agh.post("filtering/remove_url", {"url": url, "whitelist": False})
            log.append(f"- список {f['name']}")
    return log


def _update_config(agh: AGH, path: str, **changes: Any) -> None:
    # Берём текущий объект и меняем поля: набор полей отличается между
    # версиями AdGuard Home, а незнакомое поле он отвергает.
    current = agh.get(f"{path}/config") or {}
    current.update(changes)
    agh.put(f"{path}/config/update", current)


def open_access(agh: AGH) -> str:
    """Один общий адрес для всех: пускаем любого.

    Непустой allowed_clients сделал бы DNS закрытым для всех, кого там нет, а
    устройств мы больше не заводим. Открытый DoT/DoH не годится в усилитель
    DDoS (только TCP), обычный DNS на 53/5300 закрыт файрволом. Чёрный список
    (disallowed_clients) и blocked_hosts, если их вписали в панели, сохраняем.
    """
    current = agh.get("access/list") or {}
    agh.post(
        "access/set",
        {
            "allowed_clients": [],
            "disallowed_clients": current.get("disallowed_clients") or [],
            "blocked_hosts": current.get("blocked_hosts")
            or ["version.bind", "id.server", "hostname.bind"],
        },
    )
    return "доступ: общий адрес, без регистрации устройств"


def write_nginx(conf: str, path: Path = NGINX_CONF, run: Callable[..., Any] = subprocess.run) -> bool:
    """Записать конфиг шлюза, проверить `nginx -t`, перезагрузить.

    Не прошёл проверку — вернуть прежний файл: сломанный nginx на 443 = DNS
    лёг у всех. Возвращает True, если файл изменился.
    """
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if old == conf:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(conf, encoding="utf-8")
    test = run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        if old is None:
            path.unlink()
        else:
            path.write_text(old, encoding="utf-8")
        raise RuntimeError(f"nginx -t не принял конфиг, вернул прежний:\n{test.stderr.strip()}")
    reload = run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    if reload.returncode != 0:
        raise RuntimeError(f"nginx не перезагрузился: {reload.stderr.strip()}")
    return True


def apply(cfg: Config, lists: Lists, agh: AGH, nginx: bool = True) -> list[str]:
    lists.validate(cfg.dns_domain)
    log: list[str] = []

    agh.post("dns_config", dns_settings())
    log.append("DNS: апстримы DoH, кэш, лимиты")

    if (CERT_DIR / "fullchain.pem").exists():
        log.append(configure_tls(agh, cfg, CERT_DIR))
    else:
        log.append(f"! нет сертификата в {CERT_DIR} — DoT/DoH не включены")

    agh.post("filtering/config", {"enabled": True, "interval": 24})
    agh.post("safebrowsing/enable")
    log += sync_filters(agh, lists.filters)

    current_rules = (agh.get("filtering/status") or {}).get("user_rules") or []
    rules = merge_user_rules(current_rules, agh_rules(lists, cfg.public_ip))
    agh.post("filtering/set_rules", {"rules": rules})
    log.append(
        f"правила: прокси {len(lists.proxy)}, блок {len(lists.block)}, исключения {len(lists.allow)}"
    )

    # Журнал — сутки (хватит разобрать «почему не работает»), статистика — неделя.
    _update_config(agh, "querylog", enabled=True, interval=DAY_MS)
    _update_config(agh, "stats", enabled=True, interval=7 * DAY_MS)

    log.append(open_access(agh))

    if nginx:
        changed = write_nginx(nginx_stream_conf(lists, cfg.dns_domain, cfg.doh_port))
        log.append("nginx: шлюз обновлён" if changed else "nginx: без изменений")
    return log
