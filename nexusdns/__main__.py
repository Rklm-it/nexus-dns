"""nexus-dns — управление своим DNS-сервером.

  nexus-dns status                       проверить сервер снаружи
  nexus-dns apply                        применить lists/ и настройки
  nexus-dns client add "Сын" --profile kids
  nexus-dns client list | show ИМЯ | rm ИМЯ
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


def cmd_client(args) -> int:
    from . import clients
    from .config import Config

    cfg = Config.load()
    agh = _agh(cfg)
    if args.action == "add":
        body = clients.add_client(agh, cfg, args.name, args.profile)
        print(clients.howto(cfg, body["name"], body["ids"][0], args.profile))
    elif args.action == "list":
        rows = clients.describe(clients.list_clients(agh))
        print("\n".join(rows) if rows else "Устройств пока нет: nexus-dns client add ИМЯ")
    elif args.action == "show":
        c = clients.find_client(agh, args.name)
        print(clients.howto(cfg, c["name"], c["ids"][0], clients.profile_of(c)))
    elif args.action == "rm":
        c = clients.remove_client(agh, cfg, args.name)
        print(f"Удалено «{c['name']}»: его адрес больше не обслуживается.")
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nexus-dns", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"nexus-dns {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="проверить сервер снаружи").set_defaults(fn=cmd_status)

    ap = sub.add_parser("apply", help="применить lists/ и настройки")
    ap.add_argument("--no-nginx", action="store_true", help="не трогать nginx")
    ap.set_defaults(fn=cmd_apply)

    cp = sub.add_parser("client", help="устройства")
    csub = cp.add_subparsers(dest="action", required=True)
    add = csub.add_parser("add", help="новое устройство")
    add.add_argument("name")
    add.add_argument("--profile", default="family", choices=["family", "kids"])
    csub.add_parser("list", help="все устройства")
    for name, help_ in (("show", "адрес и инструкция"), ("rm", "удалить")):
        x = csub.add_parser(name, help=help_)
        x.add_argument("name", help="имя или ClientID")
    cp.set_defaults(fn=cmd_client)

    lp = sub.add_parser("lists", help="списки доменов")
    lp.add_argument("action", choices=["check"])
    lp.set_defaults(fn=cmd_lists)

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
