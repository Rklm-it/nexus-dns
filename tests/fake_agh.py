"""AdGuard Home в памяти — ровно то, что трогает apply."""

from typing import Any


class FakeAGH:
    def __init__(self):
        self.access = {"allowed_clients": [], "disallowed_clients": [], "blocked_hosts": []}
        self.filters: list[dict[str, Any]] = []
        self.user_rules: list[str] = []
        self.tls_reply: dict[str, Any] = {"valid_pair": True}
        self.calls: list[tuple[str, str]] = []
        self.configs = {"querylog": {"enabled": False, "interval": 1}, "stats": {"enabled": False, "interval": 1}}

    def get(self, path):
        self.calls.append(("GET", path))
        if path == "access/list":
            return dict(self.access)
        if path == "filtering/status":
            return {"filters": [dict(f) for f in self.filters], "user_rules": list(self.user_rules)}
        if path.endswith("/config"):
            return dict(self.configs[path.split("/")[0]])
        raise AssertionError(f"GET {path}")

    def post(self, path, body=None):
        self.calls.append(("POST", path))
        body = body or {}
        if path == "access/set":
            self.access = dict(body)
        elif path == "filtering/add_url":
            self.filters.append({"id": len(self.filters) + 1, "enabled": True, **body})
        elif path == "filtering/remove_url":
            self.filters = [f for f in self.filters if f["url"] != body["url"]]
        elif path == "filtering/set_url":
            for f in self.filters:
                if f["url"] == body["url"]:
                    f.update(body["data"])
        elif path == "filtering/set_rules":
            self.user_rules = list(body["rules"])
        elif path == "tls/configure":
            return dict(self.tls_reply)
        return None

    def put(self, path, body):
        self.calls.append(("PUT", path))
        self.configs[path.split("/")[0]] = dict(body)
