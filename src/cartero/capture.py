"""Captura de paquetes opcional (requiere scapy y permisos de administrador).

Sin captura, Cartero ya sabe *quién* habla con *quién*. Con ella, además sabe:

* cuántos datos sube y baja cada programa (asimetría),
* el nombre real de cada destino (respuestas DNS y el nombre TLS/SNI),
* si se envía un formulario sin cifrar,
* el ritmo exacto de los "latidos".

Privacidad: nunca se guarda el contenido de los paquetes. Solo se cuentan
bytes y se leen los nombres de dominio.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict

from .models import FlowStats

log = logging.getLogger(__name__)

SMALL_PAYLOAD = 300  # bytes
QUIET_GAP = 1.5  # segundos de silencio antes de un envío pequeño para contarlo como latido
MAX_EVENTS = 40

FlowKey = tuple[str, int, str, int]  # (proto, puerto local, ip remota, puerto remoto)


def parse_sni(data: bytes) -> str | None:
    """Extrae el nombre del servidor (SNI) de un TLS ClientHello.

    Es el único texto legible de una conexión HTTPS: el nombre del sitio al
    que vas, igual que la dirección escrita en un sobre cerrado.
    """
    try:
        if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 5 + 4  # cabecera de registro + tipo y longitud del handshake
        pos += 2 + 32  # versión + random
        pos += 1 + data[pos]  # session id
        pos += 2 + int.from_bytes(data[pos : pos + 2], "big")  # cipher suites
        pos += 1 + data[pos]  # métodos de compresión
        end = pos + 2 + int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        while pos + 4 <= min(end, len(data)):
            ext_type = int.from_bytes(data[pos : pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            if ext_type == 0x0000:  # server_name
                name_type = data[pos + 2]
                name_len = int.from_bytes(data[pos + 3 : pos + 5], "big")
                if name_type == 0:
                    name = data[pos + 5 : pos + 5 + name_len].decode("ascii")
                    return name.lower() if name else None
                return None
            pos += ext_len
    except (IndexError, UnicodeDecodeError):
        return None
    return None


def parse_http_request(data: bytes) -> tuple[str | None, bool]:
    """Devuelve (host, es_formulario) para una petición HTTP en claro."""
    if data[:8].split(b" ", 1)[0] not in (b"GET", b"POST", b"PUT", b"HEAD"):
        return None, False
    head = data[:4096].split(b"\r\n\r\n", 1)[0].lower()
    host = None
    for line in head.split(b"\r\n")[1:]:
        if line.startswith(b"host:"):
            host = line[5:].strip().split(b":")[0].decode("ascii", "replace") or None
    is_form = data.startswith(b"POST ") and (
        b"application/x-www-form-urlencoded" in head or b"multipart/form-data" in head
    )
    return host, is_form


class PacketCapture:
    """Escucha la tarjeta de red y acumula estadísticas por conexión."""

    def __init__(self) -> None:
        self.available = False
        self.error: str | None = None
        self._stats: dict[FlowKey, FlowStats] = defaultdict(FlowStats)
        self._last_up: dict[FlowKey, float] = {}
        self._names: dict[str, str] = {}
        self._local_ips: set[str] = set()
        self._lock = threading.Lock()
        self._sniffer = None

    def start(self) -> bool:
        try:
            import psutil
            from scapy.all import AsyncSniffer  # noqa: F401  (comprobación de disponibilidad)
        except ImportError:
            self.error = "Falta scapy. Instálalo con: pip install 'cartero[captura]'"
            return False
        self._local_ips = {
            a.address.split("%")[0] for addrs in psutil.net_if_addrs().values() for a in addrs
        }
        try:
            from scapy.all import AsyncSniffer

            self._sniffer = AsyncSniffer(store=False, prn=self._on_packet, filter="ip or ip6")
            self._sniffer.start()
            time.sleep(0.3)
            if not getattr(self._sniffer, "running", True):
                raise PermissionError
        except (PermissionError, OSError) as exc:
            self.error = "La captura necesita permisos de administrador (sudo)."
            log.debug("captura no disponible: %s", exc)
            return False
        self.available = True
        return True

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001
                pass

    # --- consultas desde el motor ------------------------------------
    def domain_for(self, ip: str) -> str | None:
        with self._lock:
            return self._names.get(ip)

    def stats_for(self, proto: str, local_port: int, remote_ip: str, remote_port: int) -> FlowStats | None:
        with self._lock:
            st = self._stats.get((proto, local_port, remote_ip, remote_port))
            if st is None:
                return None
            return FlowStats(st.bytes_up, st.bytes_down, list(st.small_up_events), st.open_form)

    # --- procesado de paquetes ---------------------------------------
    def _on_packet(self, pkt) -> None:  # pragma: no cover - requiere tráfico real
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip_layer is None:
            return
        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if l4 is None:
            return
        proto = "tcp" if isinstance(l4, TCP) else "udp"
        src, dst = ip_layer.src, ip_layer.dst
        outgoing = src in self._local_ips
        if outgoing:
            key = (proto, l4.sport, dst, l4.dport)
        else:
            key = (proto, l4.dport, src, l4.sport)
        payload = bytes(l4.payload)
        now = time.time()

        with self._lock:
            st = self._stats[key]
            if outgoing:
                st.bytes_up += len(pkt)
                if 0 < len(payload) < SMALL_PAYLOAD and now - self._last_up.get(key, 0) > QUIET_GAP:
                    st.small_up_events.append(now)
                    del st.small_up_events[:-MAX_EVENTS]
                if payload:
                    self._last_up[key] = now
            else:
                st.bytes_down += len(pkt)

        if proto == "udp" and not outgoing and l4.sport == 53 and pkt.haslayer(DNS):
            self._learn_dns(pkt[DNS])
        elif proto == "tcp" and outgoing and payload:
            if l4.dport in (443, 8443):
                name = parse_sni(payload)
                if name:
                    with self._lock:
                        self._names[dst] = name
            else:
                host, is_form = parse_http_request(payload)
                with self._lock:
                    if host:
                        self._names[dst] = host.lower()
                    if is_form:
                        self._stats[key].open_form = True

    def _learn_dns(self, dns) -> None:  # pragma: no cover - requiere tráfico real
        if not dns.qd or not dns.an:
            return
        qname = dns.qd.qname.decode("ascii", "replace").rstrip(".").lower()
        answers = dns.an if isinstance(dns.an, list) else [dns.an[i] for i in range(dns.ancount)]
        with self._lock:
            for rr in answers:
                if getattr(rr, "type", None) in (1, 28):  # A / AAAA
                    self._names[str(rr.rdata)] = qname
