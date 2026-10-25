import plistlib
import shutil
import subprocess
from pathlib import Path

import pytest

from nexusdns import site
from nexusdns.config import Config
from nexusdns.lists import Lists, nginx_stream_conf

CFG = Config(dns_domain="dns.example.com", public_ip="203.0.113.7", agh_user="admin", agh_password="x")


def test_mobileconfig_is_valid_dns_profile():
    data = plistlib.loads(site.mobileconfig(CFG).encode())
    dns = data["PayloadContent"][0]
    assert dns["PayloadType"] == "com.apple.dnsSettings.managed"
    assert dns["DNSSettings"] == {
        "DNSProtocol": "HTTPS",
        "ServerURL": "https://dns.example.com/dns-query",
        "ServerAddresses": ["203.0.113.7"],
    }
    # UUID стабилен: повторная загрузка заменяет профиль, а не плодит второй
    assert site.mobileconfig(CFG) == site.mobileconfig(CFG)


def test_index_has_every_way_to_connect():
    page = site.index_html(CFG)
    for needle in ("dns.example.com", "https://dns.example.com/dns-query",
                   "nexus-dns.mobileconfig", "podkop-block.txt", "Block"):
        assert needle in page


def test_write_site_keeps_podkop_list(tmp_path):
    (tmp_path / "podkop-block.txt").write_text("a.com\n")
    assert site.write_site(CFG, tmp_path) == ["index.html", "nexus-dns.mobileconfig"]
    assert site.write_site(CFG, tmp_path) == []
    assert (tmp_path / "podkop-block.txt").read_text() == "a.com\n"


def test_site_conf_real_ip_and_admin():
    conf = site.nginx_site_conf(CFG, Path("/c"), Path("/s"))
    assert "listen 127.0.0.1:8444 ssl proxy_protocol;" in conf
    assert "real_ip_header proxy_protocol;" in conf
    assert "proxy_set_header X-Real-IP $remote_addr;" in conf
    assert "location /admin/" in conf and "proxy_redirect / /admin/;" in conf
    assert "absolute_redirect off;" in conf


@pytest.mark.skipif(not (shutil.which("nginx") and shutil.which("openssl")), reason="нет nginx/openssl")
def test_nginx_accepts_stream_and_site_together(tmp_path):
    """Оба конфига вместе — то, что пишет apply. Проверяет и PROXY protocol
    между ними, и что сайт стартует с настоящими путями к сертификату."""
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", str(tmp_path / "privkey.pem"), "-out", str(tmp_path / "fullchain.pem"),
         "-days", "1", "-subj", "/CN=dns.example.com"],
        check=True, capture_output=True,
    )
    stream = tmp_path / "stream.conf"
    stream.write_text(nginx_stream_conf(Lists.load(), CFG.dns_domain))
    sitef = tmp_path / "site.conf"
    sitef.write_text(site.nginx_site_conf(CFG, tmp_path, tmp_path))
    modules = Path("/usr/lib/nginx/modules/ngx_stream_module.so")
    main = tmp_path / "nginx.conf"
    main.write_text(
        (f"load_module {modules};\n" if modules.exists() else "")
        + f"pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/error.log;\nevents {{}}\n"
        f"include {stream};\nhttp {{ access_log off; include {sitef}; }}\n"
    )
    r = subprocess.run(["nginx", "-t", "-c", str(main), "-p", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
