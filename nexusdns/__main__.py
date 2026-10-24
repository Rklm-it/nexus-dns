"""nexus-dns — управление своим DNS-сервером.

  nexus-dns status                       проверить сервер снаружи
  nexus-dns apply                        применить lists/ и настройки
  nexus-dns howto                        что вписать на телефоне, роутере, в VPN
  nexus-dns lists check                  проверить lists/ (можно без сервера)
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__


def _agh(cfg):
    from .agh import AGH

    return AGH(cfg.agh_url, cfg.agh_user, cfg.agh_password)


def cmd_status(args) -> int:
    from . import selfcheck
    from .config import Config
    from .lists import Lists

    cfg = Config.load()
    checks = selfcheck.run(cfg, Lists.load())
    for c in checks:
        mark = "\033[32m✓\033[0m" if c.ok else "\033[31m✗\033[0m"
        print(f" {mark} {c.title:<52} {c.detail}")
    failed = [c for c in checks if not c.ok]
    print(f"\nВсё в порядке: {cfg.dns_domain}" if not failed else f"\nПроблем: {len(failed)}")
    return 1 if failed else 0


def cmd_apply(args) -> int:
    from .apply import apply
    from .config import Config
    from .lists import Lists

    cfg = Config.load()
    for line in apply(cfg, Lists.load(), _agh(cfg), nginx=not args.no_nginx):
        print(" ", line)
    return 0


HOWTO = """\
Адрес один для всех — вписать один раз:

  Android 9+   Настройки → Подключение и общий доступ (или «Сеть и интернет») →
               Частный DNS → Имя хоста →   {domain}
  iPhone, браузер, Windows 11 (DoH):      {doh}
  Роутер:      DoT  tls://{domain}   или DoH-ссылка выше

С VPN ничего менять не нужно: запросы к DNS идут внутри туннеля и доходят
до сервера даже под белыми списками мобильного оператора.
Под белыми списками БЕЗ VPN не работает ничего зарубежного, и наш DNS тоже:
Android покажет «нет интернета», пока не включишь VPN или не уйдёшь на Wi-Fi.
VPN под белыми списками должен знать свой сервер по IP, а не по домену:
домен ему найти нечем, пока туннель не поднят (это настройка подписки).
"""


def cmd_howto(args) -> int:
    from .config import Config

    cfg = Config.load()
    print(HOWTO.format(domain=cfg.dns_domain, doh=cfg.doh_url))
    return 0


def cmd_lists(args) -> int:
    from .lists import Lists

    lists = Lists.load()
    print(f"proxy {len(lists.proxy)}, block {len(lists.block)}, allow {len(lists.allow)}, filters {len(lists.filters)} — ок")
    return 0


def cmd_cloudflare(args) -> int:
    from .cloudflare import ensure_records

    token = os.environ.get("CF_API_TOKEN", "")
    if not token:
        print("нужен CF_API_TOKEN в окружении", file=sys.stderr)
        return 2
    for line in ensure_records(token, args.domain, args.ip):
        print(" ", line)
    return 0


def resolve_a(name: str, server: str, timeout: float = 4) -> list[str]:
    """A-записи имени у публичного резолвера, мимо кэша системы."""
    import socket

    from . import dnswire

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(dnswire.build_query(name), (server, 53))
        _, addrs = dnswire.parse_response(sock.recv(4096))
    return addrs


def cmd_wait_dns(args) -> int:
    import time

    deadline = time.monotonic() + args.timeout
    told = False
    while True:
        seen: set[str] = set()
        for server in ("1.1.1.1", "8.8.8.8"):
            try:
                seen.update(resolve_a(args.domain, server))
            except OSError:
                pass
        if seen == {args.ip}:
            print(f"  {args.domain} → {args.ip} ✓")
            return 0
        if not told:
            print(f"  Жду A-запись у регистратора домена:  {args.domain}  →  {args.ip}")
            print("  (тип A, без прокси/«оранжевого облака»; обычно расходится за 1–10 минут)")
            told = True
        if time.monotonic() > deadline:
            now = ", ".join(sorted(seen)) or "нет записи"
            print(f"  {args.domain} сейчас: {now} — а нужно {args.ip}", file=sys.stderr)
            return 1
        time.sleep(10)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nexus-dns", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"nexus-dns {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="проверить сервер снаружи").set_defaults(fn=cmd_status)

    ap = sub.add_parser("apply", help="применить lists/ и настройки")
    ap.add_argument("--no-nginx", action="store_true", help="не трогать nginx")
    ap.set_defaults(fn=cmd_apply)

    sub.add_parser("howto", help="что вписать на устройствах").set_defaults(fn=cmd_howto)

    lp = sub.add_parser("lists", help="списки доменов")
    lp.add_argument("action", choices=["check"])
    lp.set_defaults(fn=cmd_lists)

    wd = sub.add_parser("wait-dns", help=argparse.SUPPRESS)
    wd.add_argument("domain")
    wd.add_argument("ip")
    wd.add_argument("--timeout", type=int, default=900)
    wd.set_defaults(fn=cmd_wait_dns)

    cf = sub.add_parser("cloudflare-records", help=argparse.SUPPRESS)
    cf.add_argument("domain")
    cf.add_argument("ip")
    cf.set_defaults(fn=cmd_cloudflare)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except Exception as e:  # noqa: BLE001 — причина на экран, без трейсбека
        if os.environ.get("NEXUS_DNS_DEBUG"):
            raise
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
