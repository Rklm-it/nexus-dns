#!/usr/bin/env bash
# Установка и обновление Nexus DNS на VPS (Ubuntu 22.04+/Debian 12+).
#
#   git clone https://github.com/Rklm-it/nexus-dns /opt/nexus-dns
#   sudo /opt/nexus-dns/install.sh
#
# Нужен домен у любого регистратора с A-записью «адрес DNS → IP сервера».
# Домен в Cloudflare и токен — необязательно: тогда запись создастся сама.
# Повторный запуск = обновление: настройки берутся из /etc/nexus-dns/nexus-dns.env.
# Без вопросов: DNS_DOMAIN=dns.example.com [CF_API_TOKEN=...] ./install.sh
#
# Скрипт обёрнут в { … }: bash читает его целиком до выполнения, и обрыв
# посреди файла не выполнит половину установки.
{
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR=/etc/nexus-dns
ENV_FILE="$ENV_DIR/nexus-dns.env"
AGH_DIR=/opt/AdGuardHome
AGH_API=http://127.0.0.1:3000
NGINX_INCLUDE_DIR=/etc/nginx/nexus-dns
ACME_ROOT=/var/www/nexus-dns-acme
CERT_NAME=nexus-dns

STEP="подготовка"
FINISHED=0
on_exit() {
    local code=$?
    if [ "$FINISHED" != 1 ]; then
        echo >&2
        echo "✗ Установка не закончена — остановилась на шаге: $STEP (код $code)." >&2
        echo "  Исправь причину выше и запусти ./install.sh ещё раз — он продолжит." >&2
    fi
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

step() { STEP="$*"; printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { echo "✗ $*" >&2; exit 1; }

# «Ключа нет» — это ответ, а не ошибка: под pipefail grep без находки уронил бы скрипт молча.
envget() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true; }

# Ввод только с терминала: проверяем открытием, а не [ -r ] — под curl|bash
# /dev/tty может «читаться» и при этом не открываться.
TTY_OK=0
if exec 3</dev/tty 2>/dev/null; then TTY_OK=1; fi

ask() { # ask VAR "вопрос" [по умолчанию] [secret]
    local var=$1 prompt=$2 def=${3:-} secret=${4:-} val="${!1:-}"
    if [ -z "$val" ] && [ "$TTY_OK" = 1 ]; then
        printf '%s%s: ' "$prompt" "${def:+ [$def]}" >/dev/tty
        if [ -n "$secret" ]; then IFS= read -rs val <&3 || true; echo >/dev/tty
        else IFS= read -r val <&3 || true; fi
    fi
    val=${val:-$def}
    printf -v "$var" '%s' "$val"
}

fetch() { curl -fsSL --connect-timeout 15 --max-time 300 --retry 3 "$@"; }

# ---------------------------------------------------------------------------
step "проверка системы"
[ "$(id -u)" = 0 ] || die "нужен root: sudo $0"
command -v apt-get >/dev/null || die "нужен Ubuntu/Debian (apt-get)"
case "$(uname -m)" in
    x86_64) AGH_ARCH=amd64 ;;
    aarch64|arm64) AGH_ARCH=arm64 ;;
    armv7l) AGH_ARCH=armv7 ;;
    *) die "архитектура $(uname -m) не поддерживается" ;;
esac
mkdir -p "$ENV_DIR"
chmod 700 "$ENV_DIR"

# ---------------------------------------------------------------------------
step "настройки"
DNS_DOMAIN="${DNS_DOMAIN:-$(envget DNS_DOMAIN)}"
CF_API_TOKEN="${CF_API_TOKEN:-$(envget CF_API_TOKEN)}"
ACME_EMAIL="${ACME_EMAIL:-$(envget ACME_EMAIL)}"
PUBLIC_IP="${PUBLIC_IP:-$(envget PUBLIC_IP)}"

if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP="$(curl -4 -fsS --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null \
        || curl -4 -fsS --connect-timeout 5 --max-time 10 https://ifconfig.me/ip 2>/dev/null || true)"
fi
ask DNS_DOMAIN "Адрес DNS-сервера (домен или поддомен, напр. dns.example.com)"
ask CF_API_TOKEN "Токен Cloudflare, если домен там (Enter — пропустить, запись впишешь сам)" "" secret
ask ACME_EMAIL "Почта для Let's Encrypt (можно пусто)"
ask PUBLIC_IP "Публичный IPv4 сервера" "$PUBLIC_IP"

DNS_DOMAIN="$(printf '%s' "$DNS_DOMAIN" | tr 'A-Z' 'a-z')"
[[ "$DNS_DOMAIN" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$ ]] \
    || die "DNS_DOMAIN «$DNS_DOMAIN» — не похоже на домен"
[[ "$PUBLIC_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "PUBLIC_IP «$PUBLIC_IP» — не IPv4"

AGH_USER="$(envget AGH_USER)"; AGH_USER="${AGH_USER:-admin}"
AGH_PASSWORD="$(envget AGH_PASSWORD)"
[ -n "$AGH_PASSWORD" ] || AGH_PASSWORD="$(openssl rand -hex 12)"

umask 077
cat > "$ENV_FILE" <<EOF
# Nexus DNS — пишет install.sh. Права 600: здесь пароль панели и токен Cloudflare.
DNS_DOMAIN=$DNS_DOMAIN
PUBLIC_IP=$PUBLIC_IP
ACME_EMAIL=$ACME_EMAIL
CF_API_TOKEN=$CF_API_TOKEN
AGH_USER=$AGH_USER
AGH_PASSWORD=$AGH_PASSWORD
EOF
umask 022

# ---------------------------------------------------------------------------
step "порты 80, 443 и 853 свободны"
busy="$(ss -Hltnp '( sport = :80 or sport = :443 or sport = :853 )' 2>/dev/null | grep -v -E '"(nginx|AdGuardHome)"' || true)"
[ -z "$busy" ] || die "порты заняты другой программой (нужен отдельный VPS или освободить):
$busy"
if [ -d /etc/nginx ]; then
    other="$(grep -rlE '^[^#]*listen[^;]*\b443\b' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null || true)"
    [ -z "$other" ] || die "в nginx уже есть сайты на 443 ($other) — шлюзу DNS нужен 443 целиком"
fi

# ---------------------------------------------------------------------------
step "пакеты"
export DEBIAN_FRONTEND=noninteractive
timeout 600 apt-get update -q
if ! timeout 900 apt-get install -y -q nginx libnginx-mod-stream certbot \
    python3 curl ca-certificates openssl nftables iproute2; then
    # Без IPv6 стоковый сайт nginx (listen [::]:80) не стартует, и dpkg не
    # доустанавливает пакет. Сайт нам не нужен — убираем и доустанавливаем.
    [ ! -e /proc/net/if_inet6 ] && [ -L /etc/nginx/sites-enabled/default ] \
        || die "apt-get install не прошёл (вывод выше)"
    rm -f /etc/nginx/sites-enabled/default
    dpkg --configure -a
fi
# Стоковая страница nginx на :80 серверу DNS не нужна (и без IPv6 роняет nginx).
rm -f /etc/nginx/sites-enabled/default

# ---------------------------------------------------------------------------
step "файрвол (своя таблица nftables, остальное не трогаем)"
install -m 644 "$REPO_DIR/deploy/firewall.nft" "$ENV_DIR/firewall.nft"
install -m 644 "$REPO_DIR/deploy/nexus-dns-firewall.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable nexus-dns-firewall.service >/dev/null
systemctl restart nexus-dns-firewall.service

# ---------------------------------------------------------------------------
step "адрес $DNS_DOMAIN → $PUBLIC_IP"
if [ -n "$CF_API_TOKEN" ]; then
    CF_API_TOKEN="$CF_API_TOKEN" PYTHONPATH="$REPO_DIR" \
        python3 -m nexusdns cloudflare-records "$DNS_DOMAIN" "$PUBLIC_IP"
fi
PYTHONPATH="$REPO_DIR" python3 -m nexusdns wait-dns "$DNS_DOMAIN" "$PUBLIC_IP" --timeout 900 \
    || die "A-запись $DNS_DOMAIN не указывает на $PUBLIC_IP — поправь у регистратора и запусти ещё раз"

# ---------------------------------------------------------------------------
step "nginx: проверка Let's Encrypt на :80, шлюз на :443"
mkdir -p "$NGINX_INCLUDE_DIR" "$ACME_ROOT"
# Сертификат на одно имя по HTTP-01: ни wildcard, ни API регистратора не нужны.
cat > /etc/nginx/conf.d/nexus-dns-acme.conf <<EOF
# nexus-dns: только проверка Let's Encrypt для $DNS_DOMAIN
server {
    listen 80;
    server_name $DNS_DOMAIN;
    location /.well-known/acme-challenge/ { root $ACME_ROOT; }
    location / { return 404; }
}
EOF
# stream {} живёт на верхнем уровне nginx.conf, не внутри http {}.
grep -qF "include $NGINX_INCLUDE_DIR/*.conf;" /etc/nginx/nginx.conf \
    || printf '\n# nexus-dns: шлюз DNS/прокси на 443\ninclude %s/*.conf;\n' "$NGINX_INCLUDE_DIR" >> /etc/nginx/nginx.conf
nginx -t
systemctl enable nginx >/dev/null
systemctl restart nginx

# ---------------------------------------------------------------------------
step "сертификат Let's Encrypt на $DNS_DOMAIN"
chmod +x "$REPO_DIR/deploy/certbot-deploy-hook.sh"
if [ -n "$ACME_EMAIL" ]; then email_args=(-m "$ACME_EMAIL"); else email_args=(--register-unsafely-without-email); fi
timeout 600 certbot certonly --non-interactive --agree-tos "${email_args[@]}" \
    --webroot -w "$ACME_ROOT" --cert-name "$CERT_NAME" -d "$DNS_DOMAIN" \
    --keep-until-expiring --deploy-hook "$REPO_DIR/deploy/certbot-deploy-hook.sh" \
    || die "Let's Encrypt не выдал сертификат: порт 80 сервера должен быть открыт снаружи (файрвол хостера?)"
systemctl enable --now certbot.timer >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
step "AdGuard Home"
if [ ! -x "$AGH_DIR/AdGuardHome" ] || [ "${AGH_UPGRADE:-0}" = 1 ]; then
    tmp="$(mktemp -d)"
    fetch "https://static.adguard.com/adguardhome/release/AdGuardHome_linux_${AGH_ARCH}.tar.gz" \
        -o "$tmp/agh.tar.gz"
    tar -xzf "$tmp/agh.tar.gz" -C "$tmp"
    systemctl stop AdGuardHome 2>/dev/null || true
    mkdir -p "$AGH_DIR"
    install -m 755 "$tmp/AdGuardHome/AdGuardHome" "$AGH_DIR/AdGuardHome"
    rm -rf "$tmp"
fi
"$AGH_DIR/AdGuardHome" --version
install -m 644 "$REPO_DIR/deploy/AdGuardHome.service" /etc/systemd/system/AdGuardHome.service
systemctl daemon-reload
systemctl enable AdGuardHome >/dev/null
systemctl restart AdGuardHome

for _ in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 "$AGH_API/" && break
    sleep 1
done
curl -s -o /dev/null --max-time 2 "$AGH_API/" || die "AdGuard Home не поднялся: journalctl -u AdGuardHome -n 50"

if [ ! -f "$AGH_DIR/AdGuardHome.yaml" ]; then
    # Первый запуск: мастер настройки через API. Обычный DNS — на 5300, а не
    # на 53: там уже сидит systemd-resolved, и снаружи он всё равно закрыт.
    code="$(curl -s -o /tmp/nexus-dns-agh.out -w '%{http_code}' --max-time 30 -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"web\":{\"ip\":\"127.0.0.1\",\"port\":3000},\"dns\":{\"ip\":\"0.0.0.0\",\"port\":5300},\"username\":\"$AGH_USER\",\"password\":\"$AGH_PASSWORD\"}" \
        "$AGH_API/control/install/configure")"
    [ "$code" = 200 ] || die "мастер AdGuard Home ответил $code: $(cat /tmp/nexus-dns-agh.out)"
    for _ in $(seq 1 30); do
        curl -s -o /dev/null --max-time 2 -u "$AGH_USER:$AGH_PASSWORD" "$AGH_API/control/status" && break
        sleep 1
    done
fi
curl -fs -o /dev/null --max-time 5 -u "$AGH_USER:$AGH_PASSWORD" "$AGH_API/control/status" \
    || die "AdGuard Home не пускает с паролем из $ENV_FILE (менял пароль в панели? впиши его в AGH_PASSWORD)"

# ---------------------------------------------------------------------------
step "команда nexus-dns"
cat > /usr/local/bin/nexus-dns <<EOF
#!/bin/sh
PYTHONPATH="$REPO_DIR" exec python3 -m nexusdns "\$@"
EOF
chmod 755 /usr/local/bin/nexus-dns

step "применяю настройки и списки"
nexus-dns apply

step "самопроверка снаружи"
status_ok=1
nexus-dns status || status_ok=0

FINISHED=1
cat <<EOF

✓ Nexus DNS установлен: $DNS_DOMAIN ($PUBLIC_IP)

  Всем один адрес — вписать один раз (Android: Частный DNS → Имя хоста):
      $DNS_DOMAIN
  Остальные устройства и VPN:  nexus-dns howto

  Панель AdGuard Home (журнал запросов, статистика):
      https://$DNS_DOMAIN/      логин: $AGH_USER   пароль: $AGH_PASSWORD
      (пароль лежит в $ENV_FILE)

  После правки lists/:   nexus-dns apply
  Обновить всё:          cd $REPO_DIR && git pull && ./install.sh
EOF
[ "$status_ok" = 1 ] || echo "
! Самопроверка нашла проблемы (выше). Записи Cloudflare могли ещё не разойтись —
  повтори через пару минут: nexus-dns status"
exit 0
}
