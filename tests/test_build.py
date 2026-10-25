import io
import zipfile

from nexusdns import build


def test_third_party_hosts_only_plain_rules():
    lines = [
        "||ads.example.ru^$third-party",
        "||site.ru/ads/^$third-party",      # с путём — не домен
        "||x.ru^$third-party,script",       # другие пометки — не трогаем
        "||plain.ru^",
        "! комментарий",
    ]
    assert build.third_party_hosts(lines) == {"ads.example.ru"}


def test_ru_thirdparty_drops_popular_and_protected():
    cands = {"ads.small.ru", "cdn.popular.ru", "widget.vk.com", "bad..ru"}
    out = build.ru_thirdparty(cands, popular={"popular.ru"}, protect={"vk.com"})
    # На популярном домене $third-party значит «сайт нормальный, режь только
    # встроенное» — целиком его блокировать нельзя.
    assert out == ["ads.small.ru"]


def test_tranco_top_registrable():
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as z:
        z.writestr("top-1m.csv", "1,google.com\n2,www.yandex.ru\n3,third.org\n")
    assert build.tranco_top(raw.getvalue(), top=2) == {"google.com", "yandex.ru"}


def test_blocked_hosts_formats_and_exceptions():
    hagezi = ["# заголовок", "ads.one.com", "*.wild.com"]
    adguard = ["! x", "||two.com^", "||imp.com^$important", "@@||ok.two.com^", "||path.com/x^"]
    got = build.blocked_hosts([hagezi, adguard], extra=["mine.com"], allow=["one.com"])
    assert got == {"wild.com", "two.com", "imp.com", "mine.com"}
    # исключение @@ снимает поддомен, но не родителя
    assert not build.covered("ok.two.com", got - {"two.com"})


def test_podkop_block_subdomains_only():
    block = {"an.facebook.com", "facebook.com", "pixel.facebook.com", "ads.example.com", "x.ok.ru"}
    podkop = {"facebook.com", "ok.ru"}
    out = build.podkop_block(block, podkop, protect={"ok.ru"})
    # facebook.com человек сам завёл в VPN — его не режем; ok.ru под защитой
    assert out == ["an.facebook.com", "pixel.facebook.com"]


def test_read_podkop_cleans():
    assert build.read_podkop(["facebook.com", ".fbcdn.net", "# x", "", "bad"]) == {"facebook.com", "fbcdn.net"}


def test_write_list_atomic(tmp_path):
    path = tmp_path / "a" / "list.txt"
    build.write_list(path, "# h\n", ["a.com", "b.com"])
    assert path.read_text() == "# h\na.com\nb.com\n"
    assert not path.with_suffix(".tmp").exists()


def test_google_subnets_minus_cloud():
    goog = {"prefixes": [{"ipv4Prefix": "10.0.0.0/16"}, {"ipv6Prefix": "2001::/32"}, {"ipv4Prefix": "10.1.0.0/24"}]}
    cloud = {"prefixes": [{"ipv4Prefix": "10.0.128.0/17"}, {"ipv4Prefix": "10.1.0.0/24"}]}
    # Google Cloud — чужие сайты, им в VPN незачем
    assert build.google_subnets(goog, cloud) == ["10.0.0.0/17"]
