from nexusdns.__main__ import HOWTO, build_parser


def test_howto_one_address_for_everything():
    text = HOWTO.format(domain="dns.example.com", doh="https://dns.example.com/dns-query")
    assert "Имя хоста →   dns.example.com" in text
    assert "https://dns.example.com/dns-query" in text
    assert "С VPN ничего менять не нужно" in text


def test_no_per_device_commands():
    cmds = build_parser()._subparsers._group_actions[0].choices
    assert "client" not in cmds and "howto" in cmds
