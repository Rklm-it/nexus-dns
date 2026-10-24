import subprocess
from pathlib import Path

import pytest

from nexusdns import apply as ap
from nexusdns.agh import AGHError
from nexusdns.config import Config
from nexusdns.lists import BEGIN_MARK, Lists

from .fake_agh import FakeAGH

CFG = Config(dns_domain="dns.example.com", public_ip="203.0.113.7",
             agh_user="admin", agh_password="x", selftest_id="tselftest1")


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
    (tmp_path / "fullchain.pem").write_text("x")
    agh = FakeAGH()
    agh.user_rules = ["||mine.com^"]
    lists = Lists.load()
    ap.apply(CFG, lists, agh, nginx=False)
    first = list(agh.user_rules)
    ap.apply(CFG, lists, agh, nginx=False)
    assert agh.user_rules == first
    assert first[0] == BEGIN_MARK and first[-1] == "||mine.com^"
    assert agh.access["allowed_clients"] == ["tselftest1"]
    assert agh.configs["querylog"]["interval"] == ap.DAY_MS


def _runner(nginx_rc):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        rc = nginx_rc if cmd[0] == "nginx" else 0
        return subprocess.CompletedProcess(cmd, rc, "", "boom" if rc else "")

    return run, calls


def test_write_nginx_restores_on_bad_config(tmp_path):
    path = tmp_path / "stream.conf"
    path.write_text("old")
    run, calls = _runner(nginx_rc=1)
    with pytest.raises(RuntimeError, match="boom"):
        ap.write_nginx("new", path, run)
    assert path.read_text() == "old"
    assert ["systemctl", "reload", "nginx"] not in calls


def test_write_nginx_removes_new_file_on_bad_config(tmp_path):
    path = tmp_path / "sub" / "stream.conf"
    run, _ = _runner(nginx_rc=1)
    with pytest.raises(RuntimeError):
        ap.write_nginx("new", path, run)
    assert not path.exists()


def test_write_nginx_skips_when_unchanged(tmp_path):
    path = tmp_path / "stream.conf"
    path.write_text("same")
    run, calls = _runner(nginx_rc=0)
    assert ap.write_nginx("same", path, run) is False
    assert calls == []
    assert ap.write_nginx("other", path, run) is True
    assert calls == [["nginx", "-t"], ["systemctl", "reload", "nginx"]]


def test_no_per_ip_ratelimit():
    # Под VPN все пользователи ноды приходят с одного IP выхода: лимит по IP
    # ронял бы DNS целой ноде. Чужих отсекает ClientID, а не лимит.
    assert ap.dns_settings()["ratelimit"] == 0
