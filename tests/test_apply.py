import subprocess
from pathlib import Path

import pytest

from nexusdns import apply as ap
from nexusdns.agh import AGHError
from nexusdns.config import Config
from nexusdns.lists import BEGIN_MARK, Lists

from .fake_agh import FakeAGH

CFG = Config(dns_domain="dns.example.com", public_ip="203.0.113.7",
             agh_user="admin", agh_password="x")


def test_tls_rejected_cert_raises():
    # AdGuard Home отвечает 200 и не применяет — проверено на v0.107.79.
    agh = FakeAGH()
    agh.tls_reply = {"valid_pair": False, "warning_validation": "reading cert file: no such file"}
    with pytest.raises(AGHError, match="no such file"):
        ap.configure_tls(agh, CFG, Path("/nonexistent"))


def test_tls_settings_paths_and_ports(tmp_path):
    s = ap.tls_settings(CFG, tmp_path)
    assert s["certificate_path"] == str(tmp_path / "fullchain.pem")
    assert s["port_https"] == 8443 and s["port_dns_over_tls"] == 853
    assert s["server_name"] == "dns.example.com"


def test_sync_filters_adds_and_removes_only_ours():
    agh = FakeAGH()
    agh.filters = [
        {"id": 1, "url": "https://mine.example/list.txt", "name": "мой список", "enabled": True},
        {"id": 2, "url": "https://old.example/a/old.txt", "name": "nexus: a/old.txt", "enabled": True},
        {"id": 3, "url": "https://keep.example/b/k.txt", "name": "nexus: b/k.txt", "enabled": False},
    ]
    log = ap.sync_filters(agh, ["https://keep.example/b/k.txt", "https://new.example/c/new.txt"])
    urls = {f["url"]: f for f in agh.filters}
    assert "https://mine.example/list.txt" in urls  # руками добавленный — не трогаем
    assert "https://old.example/a/old.txt" not in urls
    assert urls["https://keep.example/b/k.txt"]["enabled"] is True
    assert urls["https://new.example/c/new.txt"]["name"] == "nexus: c/new.txt"
    assert len(log) == 3


def test_apply_full_and_repeatable(monkeypatch, tmp_path):
    monkeypatch.setattr(ap, "CERT_DIR", tmp_path)
    monkeypatch.setattr(ap, "SITE_ROOT", tmp_path / "site")
    monkeypatch.setattr(ap, "USERFILTERS", tmp_path / "uf")
    (tmp_path / "fullchain.pem").write_text("x")
    agh = FakeAGH()
    agh.user_rules = ["||mine.com^"]
    lists = Lists.load()
    ap.apply(CFG, lists, agh, nginx=False)
    first = list(agh.user_rules)
    ap.apply(CFG, lists, agh, nginx=False)
    assert agh.user_rules == first
    assert first[0] == BEGIN_MARK and first[-1] == "||mine.com^"
    assert agh.access["allowed_clients"] == []
    assert agh.configs["querylog"]["interval"] == ap.DAY_MS


def _runner(nginx_rc):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        rc = nginx_rc if cmd[0] == "nginx" else 0
        return subprocess.CompletedProcess(cmd, rc, "", "boom" if rc else "")

    return run, calls


def test_write_nginx_restores_all_on_bad_config(tmp_path):
    stream, site = tmp_path / "stream.conf", tmp_path / "site.conf"
    stream.write_text("old")
    run, calls = _runner(nginx_rc=1)
    with pytest.raises(RuntimeError, match="boom"):
        ap.write_nginx({stream: "new", site: "new"}, run)
    assert stream.read_text() == "old"
    assert not site.exists()  # нового не было — и не остаётся
    assert ["systemctl", "reload", "nginx"] not in calls


def test_write_nginx_skips_when_unchanged(tmp_path):
    path = tmp_path / "stream.conf"
    path.write_text("same")
    run, calls = _runner(nginx_rc=0)
    assert ap.write_nginx({path: "same"}, run) is False
    assert calls == []
    assert ap.write_nginx({path: "other"}, run) is True
    assert calls == [["nginx", "-t"], ["systemctl", "reload", "nginx"]]


def test_local_filters_only_ours(tmp_path):
    (tmp_path / "nexus-ru-thirdparty.txt").write_text("||x.ru^")
    (tmp_path / "mine.txt").write_text("||y.ru^")
    assert ap.local_filters(tmp_path) == [str(tmp_path / "nexus-ru-thirdparty.txt")]
    assert ap.local_filters(tmp_path / "нет") == []


def test_no_per_ip_ratelimit():
    # Под VPN все пользователи ноды приходят с одного IP выхода: лимит по IP
    # ронял бы DNS целой ноде.
    assert ap.dns_settings()["ratelimit"] == 0


def test_open_access_keeps_blacklist():
    # Один адрес для всех: allowed_clients пуст (= пускать всех), но чёрный
    # список, вписанный в панели руками, apply не стирает.
    agh = FakeAGH()
    agh.access = {"allowed_clients": ["old1234567"], "disallowed_clients": ["198.51.100.9"],
                  "blocked_hosts": ["version.bind"]}
    ap.open_access(agh)
    assert agh.access == {"allowed_clients": [], "disallowed_clients": ["198.51.100.9"],
                          "blocked_hosts": ["version.bind"]}


def test_selfcheck_waits_for_rules_reload(monkeypatch):
    """block.txt, вставший через несколько секунд после apply, — не тревога
    (на боевом сервере 25.10.2026: 564 тыс. правил TIF перечитывались, и
    майнеры из block.txt «не блокировались» первые секунды)."""
    from nexusdns import selfcheck

    calls = {"n": 0}

    class SlowAGH:
        def get(self, path):
            calls["n"] += 1
            # первые два прохода — ещё старые правила
            return {"reason": "FilteredBlackList" if calls["n"] > 2 * len(lists.block) else "NotFilteredNotFound"}

    lists = Lists.load()
    monkeypatch.setattr(selfcheck.time, "sleep", lambda s: None)
    monkeypatch.setattr(selfcheck, "protected_blocked", lambda agh: [])
    monkeypatch.setattr(selfcheck, "_try", lambda title, fn, expect: selfcheck.Check(True, title))
    monkeypatch.setattr(selfcheck, "cert_days_left", lambda ip, sni: 60)
    checks = selfcheck.run(CFG, lists, services=False, agh=SlowAGH())
    blk = [c for c in checks if "block.txt" in c.title][0]
    assert blk.ok, blk.detail
