import re
import shutil
import subprocess
from pathlib import Path

import pytest

from nexusdns.lists import (
    BEGIN_MARK, END_MARK, ListError, Lists, agh_rules, merge_user_rules,
    nginx_stream_conf, read_list,
)

IP = "203.0.113.7"
DOMAIN = "dns.example.com"


@pytest.fixture(scope="module")
def lists():
    return Lists.load()


def test_repo_lists_valid(lists):
    lists.validate(DOMAIN)
    assert "gemini.google.com" in lists.proxy
    assert "unityads.unity3d.com" in lists.block
    assert lists.filters


def test_filter_urls_keep_case(lists):
    # Путь в URL чувствителен к регистру: HostlistsRegistry в нижнем — 404.
    assert any("HostlistsRegistry" in u for u in lists.filters)


def _write(tmp_path, proxy="", block="", allow="", filters="https://x.example/list.txt"):
    for name, body in (("proxy", proxy), ("block", block), ("allow", allow), ("filters", filters)):
        (tmp_path / f"{name}.txt").write_text(body, encoding="utf-8")
    return tmp_path


def test_too_broad_rejected(tmp_path):
    with pytest.raises(ListError, match="youtube.com"):
        Lists.load(_write(tmp_path, proxy="gemini.google.com\nyoutube.com\n"))


def test_proxy_and_block_overlap_rejected(tmp_path):
    with pytest.raises(ListError, match="chatgpt.com"):
        Lists.load(_write(tmp_path, proxy="chatgpt.com", block="chatgpt.com"))


def test_proxy_must_not_cover_own_domain(tmp_path):
    lists = Lists.load(_write(tmp_path, proxy="example.com"))
    with pytest.raises(ListError, match="адресом самого DNS"):
        lists.validate(DOMAIN)


def test_not_a_domain_rejected(tmp_path):
    with pytest.raises(ListError, match="не домены"):
        Lists.load(_write(tmp_path, block="*.ads.com"))


def test_read_list_comments_dupes_case(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("# заголовок\nA.com  # хвост\n\na.com\nb.com\n", encoding="utf-8")
    assert read_list(p) == ["a.com", "b.com"]


def test_agh_rules_shape(lists):
    rules = agh_rules(lists, IP)
    assert rules[0] == BEGIN_MARK and rules[-1] == END_MARK
    assert f"||gemini.google.com^$dnsrewrite={IP}" in rules
    assert "||unityads.unity3d.com^" in rules


def test_proxy_list_same_in_dns_and_nginx(lists):
    """Один список рождает два конфига. Домен, который DNS ведёт на сервер,
    а nginx не пропускает, — тихо мёртвый сайт: это и сторожим."""
    rules = agh_rules(lists, IP)
    conf = nginx_stream_conf(lists, DOMAIN, 8443)
    in_dns = {m.group(1) for r in rules if (m := re.match(rf"\|\|(.+)\^\$dnsrewrite={re.escape(IP)}$", r))}
    in_nginx = set(re.findall(r"^\s+\.(\S+) \$ssl_preread_server_name:443;$", conf, re.M))
    assert in_dns == in_nginx == set(lists.proxy)


def test_nginx_map_has_no_duplicate_keys(lists):
    conf = nginx_stream_conf(lists, DOMAIN, 8443)
    keys = re.findall(r"^\s+(\.?[a-z0-9.-]+) \S+;$", conf, re.M)
    bare = [k.lstrip(".") for k in keys]
    # «dns.example.com» и «.dns.example.com» вместе nginx не принимает.
    assert len(bare) == len(set(bare))
    assert f".{DOMAIN} 127.0.0.1:8443;" in conf


@pytest.mark.skipif(not shutil.which("nginx"), reason="нет nginx")
def test_nginx_accepts_rendered_conf(lists, tmp_path):
    modules = Path("/usr/lib/nginx/modules/ngx_stream_module.so")
    stream = tmp_path / "stream.conf"
    stream.write_text(nginx_stream_conf(lists, DOMAIN, 8443), encoding="utf-8")
    main = tmp_path / "nginx.conf"
    load = f"load_module {modules};\n" if modules.exists() else ""
    main.write_text(
        f"{load}pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/error.log;\n"
        f"events {{}}\ninclude {stream};\n",
        encoding="utf-8",
    )
    r = subprocess.run(["nginx", "-t", "-c", str(main), "-p", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_merge_keeps_user_rules_and_is_idempotent(lists):
    ours = agh_rules(lists, IP)
    user = ["||my-own.com^", "! моё"]
    once = merge_user_rules(user, ours)
    twice = merge_user_rules(once, ours)
    assert once == twice
    assert once[: len(ours)] == ours
    assert once[len(ours):] == [""] + user


def test_merge_replaces_old_block():
    old = merge_user_rules(["||x.com^"], [BEGIN_MARK, "||old.com^", END_MARK])
    new = merge_user_rules(old, [BEGIN_MARK, "||new.com^", END_MARK])
    assert "||old.com^" not in new and "||new.com^" in new and "||x.com^" in new


def test_merge_empty_user_rules(lists):
    ours = agh_rules(lists, IP)
    assert merge_user_rules([], ours) == ours
