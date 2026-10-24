"""Сторожа установщика: правила, за которые уже платили днями разбора."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "install.sh"
TEXT = SCRIPT.read_text(encoding="utf-8")


def _code_lines():
    return [ln for ln in TEXT.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_bash_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_wrapped_in_braces_with_finish_mark():
    # Обрыв посреди файла не должен выполнить половину установки.
    lines = _code_lines()
    assert lines[0] == "{" and lines[-1] == "}"
    assert "FINISHED=1" in TEXT and "trap on_exit EXIT" in TEXT


def test_tty_opened_not_tested_with_r():
    assert "exec 3</dev/tty" in TEXT
    assert "-r /dev/tty" not in TEXT


def test_every_curl_has_timeout():
    for ln in _code_lines():
        # вызов curl (за ним флаг), а не слово curl в списке пакетов
        if re.search(r"(?:^|[\s(;|&])curl\s+-", ln):
            assert "--max-time" in ln or "--connect-timeout" in ln, ln


def test_envget_never_fails():
    assert re.search(r"envget\(\) \{.*\|\| true; \}", TEXT)


def test_deploy_files_exist():
    for name in re.findall(r"\$REPO_DIR/deploy/([\w.-]+)", TEXT):
        assert (ROOT / "deploy" / name).exists(), name


def test_firewall_closes_plain_dns_and_panel():
    nft = (ROOT / "deploy" / "firewall.nft").read_text(encoding="utf-8")
    assert re.search(r"tcp dport \{[^}]*\b53\b[^}]*\b3000\b[^}]*\b5300\b", nft)
    assert re.search(r"udp dport \{[^}]*\b53\b[^}]*\b5300\b", nft)
    assert "policy accept" in nft  # SSH и чужие правила не трогаем


def test_agh_web_bound_to_loopback():
    unit = (ROOT / "deploy" / "AdGuardHome.service").read_text(encoding="utf-8")
    assert "--web-addr 127.0.0.1:3000" in unit
    assert '\\"ip\\":\\"127.0.0.1\\",\\"port\\":3000' in TEXT
