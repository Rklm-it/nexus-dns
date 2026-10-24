"""Списки доменов из lists/ и всё, что из них рождается.

Список прокси — ОДИН источник для двух мест: правил AdGuard Home (домен
резолвится в IP сервера) и карты nginx (соединение с этим SNI пропускаем
наружу). Разойдутся — DNS отправит человека на сервер, а nginx его сбросит,
и никто ничего не залогирует. Поэтому оба рендерятся отсюда.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

LISTS_DIR = Path(__file__).resolve().parent.parent / "lists"

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Через прокси нельзя пускать то, что режет ТСПУ по SNI (прокси не шифрует —
# не поможет, а трафика съест море), и общие домены крупных платформ (уйдёт
# через сервер половина интернета человека). Нужен поддомен — пиши поддомен.
TOO_BROAD = frozenset(
    {
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "clients6.google.com", "googlevideo.com", "youtube.com", "ytimg.com",
        "youtu.be", "microsoft.com", "live.com", "apple.com", "icloud.com",
        "cloudflare.com", "amazonaws.com", "cloudfront.net", "akamai.net",
        "akamaized.net", "facebook.com", "instagram.com", "whatsapp.net",
        "telegram.org", "t.me", "discord.com", "x.com", "twitter.com",
    }
)

BEGIN_MARK = "! nexus-dns: начало — блок пишет `nexus-dns apply`, правки внутри пропадут"
END_MARK = "! nexus-dns: конец"


class ListError(ValueError):
    pass


def is_domain(value: str) -> bool:
    labels = value.split(".")
    return len(value) <= 253 and len(labels) >= 2 and all(_LABEL.match(x) for x in labels)


def read_list(path: Path, lower: bool = True) -> list[str]:
    """Строки файла без комментариев (`#`) и пустых, без дублей.

    `lower=False` — для ссылок: путь в URL чувствителен к регистру.
    """
    seen: dict[str, None] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if lower:
            line = line.lower()
        if line:
            seen.setdefault(line, None)
    return list(seen)


def read_domains(path: Path) -> list[str]:
    domains = read_list(path)
    bad = [d for d in domains if not is_domain(d)]
    if bad:
        raise ListError(f"{path.name}: не домены: {', '.join(bad)}")
    return domains


@dataclass(frozen=True)
class Lists:
    proxy: list[str]
    block: list[str]
    allow: list[str]
    filters: list[str]

    @classmethod
    def load(cls, root: Path = LISTS_DIR) -> "Lists":
        lists = cls(
            proxy=read_domains(root / "proxy.txt"),
            block=read_domains(root / "block.txt"),
            allow=read_domains(root / "allow.txt"),
            filters=read_list(root / "filters.txt", lower=False),
        )
        lists.validate()
        return lists

    def validate(self, dns_domain: str | None = None) -> None:
        broad = [d for d in self.proxy if d in TOO_BROAD]
        if broad:
            raise ListError(
                "proxy.txt: слишком широкие домены (через сервер уйдёт лишнее "
                f"или то, что режут по SNI): {', '.join(broad)}"
            )
        both = sorted(set(self.proxy) & set(self.block))
        if both:
            raise ListError(f"домены и в proxy.txt, и в block.txt: {', '.join(both)}")
        if dns_domain:
            own = [d for d in self.proxy if _covers(d, dns_domain) or _covers(dns_domain, d)]
            if own:
                raise ListError(f"proxy.txt пересекается с адресом самого DNS: {', '.join(own)}")
        bad = [u for u in self.filters if not u.startswith("https://")]
        if bad:
            raise ListError(f"filters.txt: только https-ссылки: {', '.join(bad)}")


def _covers(parent: str, name: str) -> bool:
    return name == parent or name.endswith("." + parent)


def agh_rules(lists: Lists, public_ip: str) -> list[str]:
    """Наш блок пользовательских правил AdGuard Home.

    `$dnsrewrite=<IPv4>` проверен на живом AdGuard Home: A отдаёт IP сервера,
    AAAA и HTTPS — пустой NOERROR. Это и нужно: по IPv6 телефон ушёл бы мимо
    прокси, а из HTTPS-записи взял бы ECH, и nginx увидел бы чужой SNI.
    """
    rules = [BEGIN_MARK, "! Через прокси сервера (lists/proxy.txt)"]
    rules += [f"||{d}^$dnsrewrite={public_ip}" for d in lists.proxy]
    rules.append("! Реклама в играх и приложениях (lists/block.txt)")
    rules += [f"||{d}^" for d in lists.block]
    rules.append("! Исключения (lists/allow.txt)")
    rules += [f"@@||{d}^$important" for d in lists.allow]
    rules.append(END_MARK)
    return rules


def merge_user_rules(current: list[str], ours: list[str]) -> list[str]:
    """Заменить наш блок в правилах AdGuard Home, не трогая правила человека."""
    out: list[str] = []
    inside = False
    for line in current:
        if line == BEGIN_MARK:
            inside = True
            continue
        if inside:
            if line == END_MARK:
                inside = False
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    while out and not out[0].strip():
        out.pop(0)
    return ours + ([""] + out if out else [])


NGINX_TEMPLATE = """\
# Сгенерировано `nexus-dns apply` — правки вручную пропадут.
# Шлюз на 443: смотрит SNI и не расшифровывает трафик.
#   {dns_domain} и *.{dns_domain}  -> DoH AdGuard Home (127.0.0.1:{doh_port})
#   домены из lists/proxy.txt      -> наружу, на настоящий сайт
#   остальное                      -> сброс (иначе это открытый прокси для всех)
stream {{
    map $ssl_preread_server_name $nexus_dns_upstream {{
        hostnames;
        default 127.0.0.1:9;
        # «.домен» с hostnames — сам домен и все поддомены; отдельная строка
        # для голого домена nginx считает конфликтом и не стартует.
        .{dns_domain} 127.0.0.1:{doh_port};
{proxy_lines}
    }}

    server {{
        listen 443;
        ssl_preread on;
        # Не наш AdGuard: он вернёт на домен из прокси наш же IP, и nginx
        # отправит соединение сам в себя.
        resolver {resolvers} ipv6=off valid=300s;
        resolver_timeout 5s;
        proxy_pass $nexus_dns_upstream;
        proxy_connect_timeout 10s;
        proxy_timeout 15m;
    }}
}}
"""

NGINX_RESOLVERS = ("1.1.1.1", "8.8.8.8")


def nginx_stream_conf(lists: Lists, dns_domain: str, doh_port: int) -> str:
    proxy_lines = "\n".join(
        f"        .{d} $ssl_preread_server_name:443;" for d in lists.proxy
    )
    return NGINX_TEMPLATE.format(
        dns_domain=dns_domain,
        doh_port=doh_port,
        proxy_lines=proxy_lines,
        resolvers=" ".join(NGINX_RESOLVERS),
    )
