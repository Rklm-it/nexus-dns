"""Минимум DNS-формата для самопроверки: собрать запрос, разобрать A/AAAA ответа."""

from __future__ import annotations

import ipaddress
import secrets
import struct

TYPES = {"A": 1, "AAAA": 28, "HTTPS": 65}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def build_query(name: str, qtype: str = "A") -> bytes:
    header = struct.pack("!HHHHHH", secrets.randbits(16), 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")
    ) + b"\x00"
    return header + qname + struct.pack("!HH", TYPES[qtype], 1)


def _skip_name(data: bytes, pos: int) -> int:
    while True:
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:  # сжатие: указатель на 2 байта
            return pos + 2
        pos += 1 + length


def parse_response(data: bytes) -> tuple[str, list[str]]:
    """(rcode, адреса из A/AAAA). Остальные записи (CNAME и пр.) пропускаем."""
    if len(data) < 12:
        raise ValueError("ответ короче заголовка DNS")
    _, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    rcode = RCODES.get(flags & 0x000F, str(flags & 0x000F))
    pos = 12
    for _ in range(qd):
        pos = _skip_name(data, pos) + 4
    addrs = []
    for _ in range(an):
        pos = _skip_name(data, pos)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
        pos += 10
        rdata = data[pos : pos + rdlen]
        if rtype == 1 and rdlen == 4:
            addrs.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == 28 and rdlen == 16:
            addrs.append(str(ipaddress.IPv6Address(rdata)))
        pos += rdlen
    return rcode, addrs
