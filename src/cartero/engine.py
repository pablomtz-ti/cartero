"""El motor: junta fuente de conexiones, captura, resolutor y narrador."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Protocol

from .classifier import Destination, classify_destination
from .knowledge import Knowledge
from .models import Flow, FlowStats, RawConnection
from .narrator import Card, build_cards, verdict
from .resolver import Resolver

log = logging.getLogger(__name__)

MAX_OPEN_EVENTS = 40
LIVE_WINDOW = 60.0  # la vista en vivo enseña lo visto en el último minuto
RETENTION = 180.0


class ConnectionSource(Protocol):
    limited: bool

    def connections(self) -> list[RawConnection]: ...


class StatsSource(Protocol):
    available: bool

    def stats_for(self, proto: str, local_port: int, remote_ip: str, remote_port: int) -> FlowStats | None: ...


class Engine:
    def __init__(
        self,
        source: ConnectionSource,
        kb: Knowledge,
        resolver: Resolver,
        capture: StatsSource | None = None,
        clock: Callable[[], float] = time.time,
        mode: str = "real",
        scan_seconds: float = 30.0,
    ) -> None:
        self.scan_seconds = scan_seconds
        self.source = source
        self.kb = kb
        self.resolver = resolver
        self.capture = capture
        self.clock = clock
        self.mode = mode
        self.flows: dict[tuple[str, str, str, int], Flow] = {}
        self._lock = threading.RLock()
        self._scan: dict | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # --- recogida ----------------------------------------------------
    def tick(self) -> None:
        now = self.clock()
        conns = self.source.connections()
        with self._lock:
            for c in conns:
                key = (c.process, c.proto, c.remote_ip, c.remote_port)
                flow = self.flows.get(key)
                if flow is None:
                    flow = Flow(c.process, c.exe, c.pid, c.proto, c.remote_ip, c.remote_port, now, now)
                    self.flows[key] = flow
                if c.local_port not in flow.local_ports:
                    flow.local_ports.add(c.local_port)
                    flow.open_events.append(now)
                    del flow.open_events[:-MAX_OPEN_EVENTS]
                flow.last_seen = now
                flow.pid = c.pid or flow.pid
                flow.exe = c.exe or flow.exe
            if self.capture is not None and self.capture.available:
                for flow in self.flows.values():
                    flow.stats = self._merge_stats(flow)
            keep_from = now - RETENTION
            if self._scan:
                keep_from = min(keep_from, self._scan["start"])
            self.flows = {k: f for k, f in self.flows.items() if f.last_seen >= keep_from}

    def _merge_stats(self, flow: Flow) -> FlowStats:
        total = FlowStats()
        for port in flow.local_ports:
            st = self.capture.stats_for(flow.proto, port, flow.remote_ip, flow.remote_port)  # type: ignore[union-attr]
            if st is None:
                continue
            total.bytes_up += st.bytes_up
            total.bytes_down += st.bytes_down
            total.small_up_events.extend(st.small_up_events)
            total.open_form |= st.open_form
        total.small_up_events.sort()
        return total

    def start(self, interval: float = 2.0) -> None:
        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.tick()
                except Exception:  # noqa: BLE001 - nunca tumbar el hilo de recogida
                    log.exception("error leyendo conexiones")
                self._stop.wait(interval)

        self._thread = threading.Thread(target=loop, name="cartero-engine", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # --- interpretación ---------------------------------------------
    def resolve(self, flow: Flow) -> Destination:
        domain = self.resolver.domain_for(flow.remote_ip)
        online = self.resolver.online_info(flow.remote_ip)
        return classify_destination(flow.remote_ip, domain, self.kb, online)

    def cards(self, since: float | None = None) -> list[Card]:
        now = self.clock()
        since = now - LIVE_WINDOW if since is None else since
        with self._lock:
            flows = [f for f in self.flows.values() if f.last_seen >= since]
        return build_cards(flows, self.resolve, self.kb, now)

    def live(self, hide_noise: bool = True) -> dict:
        cards = self.cards()
        hidden = [c for c in cards if c.noise]
        shown = [c for c in cards if not (hide_noise and c.noise)]
        return {
            "mode": self.mode,
            "capture": bool(self.capture and self.capture.available),
            "limited": getattr(self.source, "limited", False),
            "hidden_connections": sum(c.connections for c in hidden),
            "hidden_programs": len(hidden),
            "cards": [c.to_dict() for c in shown],
        }

    def find_card(self, card_id: str) -> Card | None:
        return next((c for c in self.cards() if c.id == card_id), None)

    # --- escaneo de 30 segundos -------------------------------------
    def start_scan(self, duration: float | None = None) -> dict:
        with self._lock:
            self._scan = {"start": self.clock(), "duration": duration or self.scan_seconds}
        return self.scan_status()

    def scan_status(self) -> dict:
        with self._lock:
            scan = dict(self._scan) if self._scan else None
        if scan is None:
            return {"state": "idle"}
        elapsed = self.clock() - scan["start"]
        if elapsed < scan["duration"]:
            return {"state": "running", "progress": round(elapsed / scan["duration"], 3),
                    "remaining": round(scan["duration"] - elapsed)}
        cards = self.cards(since=scan["start"])
        result = verdict(cards)
        flagged = [c.to_dict() for c in cards if c.level in ("warn", "danger")]
        return {"state": "done", "progress": 1.0, "finished_ago": round(elapsed - scan["duration"]),
                "verdict": result, "cards": flagged}
