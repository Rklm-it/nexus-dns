import re

import pytest

from nexusdns import clients
from nexusdns.config import Config

from .fake_agh import FakeAGH

CFG = Config(dns_domain="dns.example.com", public_ip="203.0.113.7",
             agh_user="admin", agh_password="x", selftest_id="tselftest1")


def test_client_id_shape():
    ids = {clients.new_client_id() for _ in range(500)}
    assert len(ids) == 500
    # Годится в поддомен для DoT: буква первой, только [a-z0-9].
    assert all(re.fullmatch(r"[a-z][a-z0-9]{9}", i) for i in ids)


def test_kids_profile_keeps_filtering_on():
    # Без filtering_enabled у ребёнка пропали бы и блок-листы, и прокси ИИ.
    body = clients.client_body("Сын", "abcdefghij", "kids")
    assert body["filtering_enabled"] is True
    assert body["parental_enabled"] is True
    assert body["safe_search"]["enabled"] is True
    assert body["tags"] == ["user_child"]
    assert clients.profile_of(body) == "kids"


def test_family_profile_uses_global():
    body = clients.client_body("Папа", "abcdefghij", "family")
    assert body["use_global_settings"] is True
    assert clients.profile_of(body) == "family"


def test_allowed_never_contains_loopback():
    # 127.0.0.1 в разрешённых = DoH открыт всем: он весь приходит от nginx с loopback.
    cl = [{"name": "a", "ids": ["127.0.0.1", "abc1234567"]}, {"name": "b", "ids": ["::1", "10.0.0.0/8"]}]
    assert clients.allowed_ids(cl, "tselftest1") == ["tselftest1", "abc1234567", "10.0.0.0/8"]


def test_allowed_list_never_empty():
    # Пустой allowed_clients в AdGuard Home = «пускать всех».
    agh = FakeAGH()
    clients.sync_access(agh, CFG)
    assert agh.access["allowed_clients"] == ["tselftest1"]


def test_add_and_remove_client_updates_access():
    agh = FakeAGH()
    body = clients.add_client(agh, CFG, "Сын", "kids")
    cid = body["ids"][0]
    assert cid in agh.access["allowed_clients"]
    clients.remove_client(agh, CFG, "сын")
    assert cid not in agh.access["allowed_clients"]
    assert agh.access["allowed_clients"] == ["tselftest1"]


def test_duplicate_name_rejected():
    agh = FakeAGH()
    clients.add_client(agh, CFG, "Сын", "kids")
    with pytest.raises(clients.ClientError, match="уже есть"):
        clients.add_client(agh, CFG, "сын", "family")


def test_find_by_id():
    agh = FakeAGH()
    cid = clients.add_client(agh, CFG, "Мама", "family")["ids"][0]
    assert clients.find_client(agh, cid)["name"] == "Мама"


def test_selftest_not_removable_and_hidden():
    agh = FakeAGH()
    clients.ensure_selftest(agh, CFG)
    clients.ensure_selftest(agh, CFG)  # повтор не плодит
    assert [c["name"] for c in agh.clients] == [clients.SELFTEST_NAME]
    assert clients.describe(agh.clients) == []
    with pytest.raises(clients.ClientError):
        clients.remove_client(agh, CFG, clients.SELFTEST_NAME)


def test_selftest_recreated_when_id_changed():
    agh = FakeAGH()
    agh.clients.append({"name": clients.SELFTEST_NAME, "ids": ["oldid00000"]})
    clients.ensure_selftest(agh, CFG)
    assert agh.clients[0]["ids"] == ["tselftest1"]


def test_howto_has_both_addresses():
    text = clients.howto(CFG, "Сын", "kid1234567", "kids")
    assert "kid1234567.dns.example.com" in text
    assert "https://dns.example.com/dns-query/kid1234567" in text


def test_howto_covers_vpn():
    # С VPN — DoH в «удалённый DNS» приложения: иначе под белыми списками VPN
    # с доменом в адресе сервера не поднимется (строгий Частный DNS недоступен).
    text = clients.howto(CFG, "Папа", "dad1234567", "family")
    assert "Удалённый DNS" in text and "Автоматически" in text
