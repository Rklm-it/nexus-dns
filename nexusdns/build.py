"""`nexus-dns lists build`: списки, которые собираются из чужих источников.

1. Российские правила «только на чужих сайтах». В RU AdList большинство
   доменов помечены `$third-party`, а такие правила AdGuard Home не берёт вовсе
   (проверено: из 5 634 новых доменов работал 1 183). Переводим их в обычные,
   но выкидываем популярные сайты (Tranco top) и `lists/protect.txt`: на
   популярном домене пометка означает «это нормальный сайт, режь только
   встроенное», и блок целиком его бы сломал.
2. Реклама внутри VPN-списков podkop. Домены из списков podkop роутер отвечает
   сам и шлёт в туннель — до нашего DNS они не доходят, и an.facebook.com
   проходит, хотя у нас он в блоке. Собираем то, что наш DNS режет внутри
   этих списков, и раздаём на `https://<домен>/podkop-block.txt` для
   секции podkop с типом «Block».

Сеть нужна только здесь; разбор — чистые функции, их проверяют тесты.
"""

from __future__ import annotations

import csv
import io
import re
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable

from .lists import LISTS_DIR, is_domain, read_domains

RU_ADLIST = (
    "https://easylist-downloads.adblockplus.org/advblock.txt",
    "https://easylist-downloads.adblockplus.org/cntblock.txt",
)
TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_TOP = 20000

# Что наш DNS блокирует — те же источники, что в lists/filters.txt (основные).
BLOCK_SOURCES = (
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
)

# Списки сообщества podkop (itdoginfo/allow-domains) — их домены роутер шлёт в VPN.
PODKOP_LISTS = tuple(
    f"https://raw.githubusercontent.com/itdoginfo/allow-domains/main/{p}"
    for p in (
        "Russia/inside-raw.lst", "Russia/outside-raw.lst",
        "Services/meta.lst", "Services/twitter.lst", "Services/tiktok.lst",
        "Services/youtube.lst", "Services/discord.lst", "Services/telegram.lst",
        "Services/cloudflare.lst", "Services/google_play.lst", "Services/google_ai.lst",
        "Services/hdrezka.lst", "Services/roblox.lst",
        "Categories/geoblock.lst", "Categories/block.lst", "Categories/news.lst",
        "Categories/anime.lst", "Categories/porn.lst",
    )
)

RU_FILTER_NAME = "nexus-ru-thirdparty.txt"
PODKOP_FILE = "podkop-block.txt"

_THIRD_PARTY = re.compile(r"^\|\|([a-z0-9.-]+)\^\$third-party$")
_HOST_RULE = re.compile(r"^(@@)?\|\|([a-z0-9.-]+)\^(\$important)?$")


def fetch(url: str, timeout: float = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "nexus-dns"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def text(url: str) -> list[str]:
    return fetch(url).decode("utf-8", errors="replace").splitlines()


def registrable(host: str) -> str:
    """Грубо: две последние метки. Для отбора популярных сайтов хватает."""
    return ".".join(host.split(".")[-2:])


def covered(host: str, suffixes: set[str]) -> bool:
    labels = host.split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(len(labels) - 1))


def third_party_hosts(lines: Iterable[str]) -> set[str]:
    return {m.group(1) for ln in lines if (m := _THIRD_PARTY.match(ln.strip()))}


def tranco_top(raw_zip: bytes, top: int = TRANCO_TOP) -> set[str]:
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as z:
        name = z.namelist()[0]
        rows = csv.reader(io.TextIOWrapper(z.open(name), encoding="utf-8"))
        return {registrable(r[1].lower()) for _, r in zip(range(top), rows) if len(r) > 1}


def ru_thirdparty(candidates: set[str], popular: set[str], protect: set[str]) -> list[str]:
    keep = [
        h for h in candidates
        if is_domain(h) and registrable(h) not in popular and not covered(h, protect)
    ]
    return sorted(keep)


def blocked_hosts(sources: Iterable[list[str]], extra: Iterable[str], allow: Iterable[str]) -> set[str]:
    """Домены, которые режет наш DNS: строки `домен` (HaGeZi) и `||домен^` (AdGuard)."""
    block: set[str] = set(extra)
    exceptions: set[str] = set(allow)
    for lines in sources:
        for ln in lines:
            ln = ln.strip()
            if not ln or ln[0] in "#!":
                continue
            m = _HOST_RULE.match(ln)
            if m:
                (exceptions if m.group(1) else block).add(m.group(2))
            elif is_domain(ln.lstrip("*.")):
                block.add(ln.lstrip("*."))
    return {h for h in block if not covered(h, exceptions)}


def podkop_block(block: set[str], podkop_domains: set[str], protect: set[str]) -> list[str]:
    """Что наш DNS режет внутри доменов, которые podkop шлёт в VPN.

    Сам домен из списка podkop (facebook.com) не берём, даже если он в блоке:
    человек завёл его в VPN, чтобы им пользоваться, — режем только поддомены.
    """
    out = [
        h for h in block
        if h not in podkop_domains and covered(h, podkop_domains) and not covered(h, protect)
    ]
    return sorted(out)


def read_podkop(lines: Iterable[str]) -> set[str]:
    out = set()
    for ln in lines:
        d = ln.strip().lower().lstrip(".")
        if d and not d.startswith("#") and is_domain(d):
            out.add(d)
    return out


def write_list(path: Path, header: str, domains: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(header + "\n".join(domains) + "\n", encoding="utf-8")
    tmp.replace(path)


def build(userfilters: Path, site_root: Path, root: Path = LISTS_DIR) -> list[str]:
    protect = set(read_domains(root / "protect.txt"))
    allow = read_domains(root / "allow.txt")
    log = []

    ru_lines = [ln for url in RU_ADLIST for ln in text(url)]
    popular = tranco_top(fetch(TRANCO_ZIP, timeout=120))
    ru = ru_thirdparty(third_party_hosts(ru_lines), popular, protect)
    write_list(
        userfilters / RU_FILTER_NAME,
        "! Nexus DNS: RU AdList ($third-party → обычные), без Tranco top и lists/protect.txt\n",
        [f"||{h}^" for h in ru],
    )
    log.append(f"российские правила $third-party → {len(ru)} доменов ({userfilters / RU_FILTER_NAME})")

    block = blocked_hosts(
        (text(u) for u in BLOCK_SOURCES),
        read_domains(root / "block.txt"),
        allow,
    )
    podkop_domains = set().union(*(read_podkop(text(u)) for u in PODKOP_LISTS))
    pk = podkop_block(block, podkop_domains, protect)
    write_list(
        site_root / PODKOP_FILE,
        "# Nexus DNS: реклама и трекеры внутри VPN-списков podkop.\n"
        "# Podkop → секция с типом «Block» → «Внешние списки доменов» → ссылка на этот файл.\n",
        pk,
    )
    log.append(f"podkop: {len(pk)} рекламных доменов внутри его VPN-списков ({site_root / PODKOP_FILE})")
    return log
