"""Averigua el nombre que hay detrás de una IP sin bloquear la interfaz."""

from __future__ import annotations

import json
import socket
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from .classifier import unwrap_ip


class NameSource(Protocol):
    def domain_for(self, ip: str) -> str | None: ...


class Resolver:
    """Combina tres fuentes, de más a menos fiable:

    1. Lo que la captura de paquetes vio (respuestas DNS y nombre TLS/SNI).
    2. DNS inverso (``gethostbyaddr``), en segundo plano y con caché.
    3. Opcional y desactivado por defecto: consulta a ipinfo.io para conocer
       la empresa y el país. Solo se activa con ``--online``.
    """

    def __init__(self, capture: NameSource | None = None, online: bool = False, workers: int = 8) -> None:
        self.capture = capture
        self.online = online
        self._rdns: dict[str, str | None] = {}
        self._geo: dict[str, dict | None] = {}
        self._pending: set[tuple[str, str]] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cartero-dns")

    def domain_for(self, ip: str) -> str | None:
        if self.capture:
            name = self.capture.domain_for(ip)
            if name:
                return name
        with self._lock:
            if ip in self._rdns:
                return self._rdns[ip]
            if ("rdns", ip) not in self._pending and self._is_public(ip):
                self._pending.add(("rdns", ip))
                self._pool.submit(self._reverse, ip)
        return None

    def online_info(self, ip: str) -> dict | None:
        if not self.online or not self._is_public(ip):
            return None
        with self._lock:
            if ip in self._geo:
                return self._geo[ip]
            if ("geo", ip) not in self._pending:
                self._pending.add(("geo", ip))
                self._pool.submit(self._lookup_geo, ip)
        return None

    @staticmethod
    def _is_public(ip: str) -> bool:
        addr = unwrap_ip(ip)
        return bool(addr and addr.is_global)

    def _reverse(self, ip: str) -> None:
        try:
            name: str | None = socket.gethostbyaddr(ip)[0].lower()
        except (OSError, UnicodeError):
            name = None
        with self._lock:
            self._rdns[ip] = name
            self._pending.discard(("rdns", ip))

    def _lookup_geo(self, ip: str) -> None:
        info: dict | None = None
        try:
            req = urllib.request.Request(
                f"https://ipinfo.io/{ip}/json", headers={"User-Agent": "cartero", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.load(resp)
            org = data.get("org") or ""
            if org.startswith("AS") and " " in org:  # "AS15169 Google LLC" -> "Google LLC"
                org = org.split(" ", 1)[1]
            info = {"org": org or None, "country": data.get("country")}
        except Exception:  # noqa: BLE001 - la red puede fallar de mil maneras; no es crítico
            info = None
        with self._lock:
            self._geo[ip] = info
            self._pending.discard(("geo", ip))

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
