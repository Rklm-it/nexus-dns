"""Сайт DNS-сервера: https://<домен>/ — инструкция, профиль iPhone, список для podkop.

Здесь же nginx http-сервер, который принимает всё, что пришло на 443 с именем
DNS: страница для людей, DoH (дальше в AdGuard Home с настоящим IP человека)
и панель AdGuard Home на /admin/.
"""

from __future__ import annotations

import html
import uuid
from pathlib import Path

from .config import Config
from .lists import SITE_PORT

MOBILECONFIG = "nexus-dns.mobileconfig"

SITE_CONF = """\
# Сгенерировано `nexus-dns apply` — правки вручную пропадут.
# Сюда приходит всё, что на 443 шло с именем {domain} (через nginx stream).
server {{
    listen 127.0.0.1:{site_port} ssl proxy_protocol;
    server_name {domain};
    ssl_certificate {cert}/fullchain.pem;
    ssl_certificate_key {cert}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Адрес человека — из PROXY protocol: иначе все были бы 127.0.0.1.
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
    # Мы за nginx stream на 443: в абсолютном Location ушёл бы внутренний порт.
    absolute_redirect off;

    root {site_root};
    index index.html;

    location = /{mobileconfig} {{
        default_type application/x-apple-aspen-config;
    }}
    location = /podkop-block.txt {{
        default_type text/plain;
        charset utf-8;
    }}

    # DoH: в HTTPS AdGuard Home, он берёт адрес из X-Real-IP (127.0.0.1 у него
    # в trusted_proxies по умолчанию).
    location /dns-query {{
        proxy_pass https://127.0.0.1:{doh_port};
        proxy_ssl_server_name on;
        proxy_ssl_name {domain};
        proxy_set_header Host {domain};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }}

    # Панель AdGuard Home: её пути относительные, поэтому живёт под /admin/.
    location /admin/ {{
        proxy_pass https://127.0.0.1:{doh_port}/;
        proxy_ssl_server_name on;
        proxy_ssl_name {domain};
        proxy_set_header Host {domain};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_redirect / /admin/;
        proxy_cookie_path / /admin/;
    }}
    location = /admin {{
        return 301 /admin/;
    }}

    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"""


def nginx_site_conf(cfg: Config, cert_dir: Path, site_root: Path) -> str:
    return SITE_CONF.format(
        domain=cfg.dns_domain,
        site_port=SITE_PORT,
        cert=cert_dir,
        site_root=site_root,
        doh_port=cfg.doh_port,
        mobileconfig=MOBILECONFIG,
    )


def mobileconfig(cfg: Config) -> str:
    """Профиль iOS/macOS: DoH одним касанием (Настройки → Профиль загружен)."""
    ns = uuid.uuid5(uuid.NAMESPACE_DNS, cfg.dns_domain)
    ident = ".".join(reversed(cfg.dns_domain.split(".")))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>{html.escape(cfg.doh_url)}</string>
                <key>ServerAddresses</key>
                <array>
                    <string>{cfg.public_ip}</string>
                </array>
            </dict>
            <key>PayloadDisplayName</key>
            <string>Nexus DNS</string>
            <key>PayloadIdentifier</key>
            <string>{ident}.dnssettings</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>{uuid.uuid5(ns, "dnssettings")}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Без рекламы, ИИ без VPN. {html.escape(cfg.dns_domain)}</string>
    <key>PayloadDisplayName</key>
    <string>Nexus DNS</string>
    <key>PayloadIdentifier</key>
    <string>{ident}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{ns}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"""


PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexus DNS</title>
<style>
:root {{ --bg:#f6f7f9; --card:#fff; --text:#16181d; --muted:#5d6470; --accent:#2f6fed; --line:#e3e6eb; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0f1115; --card:#181b21; --text:#eceef2; --muted:#9aa2ae; --accent:#6b9bff; --line:#2a2f38; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
main {{ max-width:720px; margin:0 auto; padding:28px 16px 48px; }}
h1 {{ font-size:28px; margin:0 0 6px; }}
h2 {{ font-size:19px; margin:0 0 10px; }}
p {{ margin:0 0 10px; }}
.lead {{ color:var(--muted); margin-bottom:22px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:18px; margin:0 0 14px; }}
.addr {{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin:8px 0 4px; }}
code {{ font:15px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; background:var(--bg); border:1px solid var(--line);
        border-radius:8px; padding:8px 10px; word-break:break-all; }}
button, .btn {{ font:inherit; border:0; border-radius:10px; padding:9px 14px; background:var(--accent); color:#fff;
               text-decoration:none; cursor:pointer; display:inline-block; }}
ol {{ margin:6px 0 0; padding-left:20px; }}
li {{ margin:3px 0; }}
.note {{ color:var(--muted); font-size:14px; }}
</style>
</head>
<body>
<main>
<h1>Nexus DNS</h1>
<p class="lead">Один адрес — вписать один раз. Режет рекламу (и в играх), трекеры и опасные сайты.
Gemini, ChatGPT и Claude открываются без VPN.</p>

<section class="card">
<h2>Android</h2>
<p>Настройки → Подключение и общий доступ (или «Сеть и интернет») → <b>Частный DNS</b> → Имя хоста:</p>
<div class="addr"><code id="dot">{domain}</code><button data-copy="dot">Копировать</button></div>
</section>

<section class="card">
<h2>iPhone, iPad, Mac</h2>
<p><a class="btn" href="/{mobileconfig}">Скачать профиль</a></p>
<ol>
<li>Нажми «Разрешить», когда спросит про загрузку.</li>
<li>Настройки → <b>Профиль загружен</b> → Установить.</li>
</ol>
</section>

<section class="card">
<h2>Браузер, Windows 11, роутер</h2>
<p>DNS через HTTPS (DoH):</p>
<div class="addr"><code id="doh">{doh}</code><button data-copy="doh">Копировать</button></div>
<p>DNS через TLS (DoT): <code>{domain}</code></p>
</section>

<section class="card">
<h2>Роутер с podkop (OpenWrt)</h2>
<ol>
<li>Podkop → «Настройки»: тип DNS — <b>DoT</b>, DNS-сервер — <code>{domain}</code>.</li>
<li>Podkop → «Секции» → добавить секцию, тип подключения <b>Block</b> →
«Внешние списки доменов»:</li>
</ol>
<div class="addr"><code id="pk">https://{domain}/podkop-block.txt</code><button data-copy="pk">Копировать</button></div>
<p class="note">Домены из VPN-списков podkop до DNS не доходят — этот список режет рекламу и в них
(Facebook, TikTok, YouTube, X…). Обновляется сам.</p>
</section>

<section class="card">
<p class="note">С VPN ничего менять не нужно. Под белыми списками мобильного оператора без VPN
зарубежный DNS недоступен — Android покажет «нет интернета»: включи VPN или переключи
Частный DNS на «Автоматически».</p>
</section>
</main>
<script>
document.querySelectorAll("button[data-copy]").forEach(function (b) {{
  b.addEventListener("click", function () {{
    var t = document.getElementById(b.dataset.copy).textContent;
    (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(
      function () {{ b.textContent = "Скопировано"; setTimeout(function () {{ b.textContent = "Копировать"; }}, 1500); }},
      function () {{ window.prompt("Скопируй:", t); }}
    );
  }});
}});
</script>
</body>
</html>
"""


def index_html(cfg: Config) -> str:
    return PAGE.format(
        domain=html.escape(cfg.dns_domain),
        doh=html.escape(cfg.doh_url),
        mobileconfig=MOBILECONFIG,
    )


def write_site(cfg: Config, site_root: Path) -> list[str]:
    """Страница и профиль; podkop-block.txt пишет `lists build`, его не трогаем."""
    site_root.mkdir(parents=True, exist_ok=True)
    changed = []
    for name, body in (("index.html", index_html(cfg)), (MOBILECONFIG, mobileconfig(cfg))):
        path = site_root / name
        if not path.exists() or path.read_text(encoding="utf-8") != body:
            path.write_text(body, encoding="utf-8")
            changed.append(name)
    return changed
