#!/bin/sh
# certbot зовёт после продления сертификата: AdGuard Home читает его только на старте.
systemctl restart AdGuardHome
