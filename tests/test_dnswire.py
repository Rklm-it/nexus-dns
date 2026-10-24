import struct

from nexusdns import dnswire


def _response(qname: bytes, answers: list[tuple[int, bytes]], rcode: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", 1, 0x8180 | rcode, 1, len(answers), 0, 0)
    body = qname + struct.pack("!HH", 1, 1)
    for rtype, rdata in answers:
        # имя ответа — указатель сжатия на вопрос (смещение 12)
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    return header + body


QNAME = b"\x07example\x03com\x00"


def test_build_query():
    q = dnswire.build_query("example.com", "AAAA")
    assert q[12:] == QNAME + struct.pack("!HH", 28, 1)
    assert struct.unpack("!H", q[2:4])[0] == 0x0100  # RD


def test_parse_a_aaaa_and_skip_cname():
    cname = (5, b"\x03www\xc0\x0c")
    a = (1, bytes([1, 2, 3, 4]))
    aaaa = (28, bytes(15) + b"\x01")
    rcode, addrs = dnswire.parse_response(_response(QNAME, [cname, a, aaaa]))
    assert rcode == "NOERROR"
    assert addrs == ["1.2.3.4", "::1"]


def test_parse_refused():
    assert dnswire.parse_response(_response(QNAME, [], rcode=5)) == ("REFUSED", [])
