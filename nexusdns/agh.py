"""Клиент HTTP API AdGuard Home (только stdlib — на сервере ничего не ставим)."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from typing import Any


class AGHError(RuntimeError):
    pass


class AGH:
    def __init__(self, url: str, user: str, password: str, timeout: float = 30):
        self.url = url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.auth = f"Basic {token}"
        self.timeout = timeout

    def call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            f"{self.url}/control/{path}",
            data=data,
            method=method,
            headers={"Authorization": self.auth, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            # Причину AdGuard Home отдаёт текстом — её и показываем, а не «ошибка 400».
            detail = e.read().decode(errors="replace").strip()
            raise AGHError(f"AdGuard Home {method} /control/{path}: {e.code} {detail}") from None
        except (urllib.error.URLError, OSError) as e:
            raise AGHError(f"AdGuard Home не отвечает ({self.url}): {e}") from None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode(errors="replace")

    def get(self, path: str) -> Any:
        return self.call("GET", path)

    def post(self, path: str, body: Any = None) -> Any:
        return self.call("POST", path, body if body is not None else {})

    def put(self, path: str, body: Any) -> Any:
        return self.call("PUT", path, body)
