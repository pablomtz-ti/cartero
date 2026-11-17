"""Clasifica destinos y vías de transporte en categorías comprensibles."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .knowledge import Knowledge, country_name

# kind de un destino:
#   self       -> el propio ordenador
#   local      -> un aparato de tu red de casa
#   tracker    -> rastreador de publicidad / analítica
#   telemetry  -> estadísticas de uso hacia el fabricante
#   service | cdn | os | cert | security | time -> infraestructura conocida
#   named      -> tiene nombre pero no está en nuestra lista
#   unknown    -> ni nombre, ni empresa conocida
NORMAL_KINDS = {"cdn", "os", "cert", "security", "time"}

SUSPICIOUS_PORTS: dict[int, str] = {
    4444: "es el que usan por defecto muchas herramientas de control remoto",
    1337: "es un número típico de programas hechos por atacantes",
    31337: "es un número típico de programas hechos por atacantes",
    12345: "lo usaban antiguos programas espía (troyanos)",
    6666: "se usa para canales de chat IRC, a veces controlados por virus",
    6667: "se usa para canales de chat IRC, a veces controlados por virus",
    5555: "sirve para controlar móviles Android a distancia",
    3389: "sirve para controlar un ordenador Windows a distancia (Escritorio remoto)",
    5900: "sirve para ver y controlar una pantalla a distancia (VNC)",
}

TWO_LEVEL_SLDS = {"co", "com", "org", "net", "gov", "edu", "ac", "gob", "nom"}


@dataclass(frozen=True)
class Destination:
    ip: str
    domain: str | None
    name: str  # nombre humano: "Google", "Sitio web ejemplo.com", "Un servidor sin nombre conocido"
    country: str | None  # nombre del país en español
    trusted: bool
    kind: str
    tracker: str | None = None

    @property
    def is_known(self) -> bool:
        return self.kind not in {"unknown"}

    @property
    def is_local(self) -> bool:
        return self.kind in {"self", "local"}

    @property
    def label(self) -> str:
        return f"{self.name} ({self.country})" if self.country else self.name


@dataclass(frozen=True)
class Transport:
    sealed: bool | None  # True = sobre cerrado, False = postal abierta, None = no lo sabemos
    purpose: str  # web | dns | mail | call | time | discovery | remote | vpn | push | other
    suspicious: str | None = None  # explicación si el puerto es raro


def unwrap_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def site_name(domain: str) -> str:
    """``www.tienda.example.co.uk`` -> ``example.co.uk``."""
    labels = domain.rstrip(".").lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in TWO_LEVEL_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def classify_destination(
    ip: str,
    domain: str | None,
    kb: Knowledge,
    online: dict | None = None,
) -> Destination:
    addr = unwrap_ip(ip)
    if addr is not None:
        if addr.is_loopback or addr.is_unspecified:
            return Destination(ip, domain, "Tu propio ordenador", None, True, "self")
        if addr.is_multicast:
            return Destination(ip, domain, "Todos los aparatos de tu red", None, True, "local")
        if addr.is_private or addr.is_link_local:
            return Destination(ip, domain, "Un aparato de tu red de casa", None, True, "local")

    tracker = kb.tracker_for(domain)
    if tracker:
        info = kb.domain_info(domain)
        return Destination(
            ip, domain, tracker, info.country_name if info else None, False, "tracker", tracker
        )

    info = kb.domain_info(domain) or kb.ip_info(ip)
    if info:
        return Destination(ip, domain, info.org, info.country_name, info.trusted, info.kind)

    country = country_name(online.get("country")) if online else None
    org = (online or {}).get("org")
    if org:
        return Destination(ip, domain, org, country, False, "named")
    if domain:
        return Destination(ip, domain, f"Sitio web {site_name(domain)}", country, False, "named")
    name = f"Un servidor sin nombre en {country}" if country else "Un servidor sin nombre conocido"
    return Destination(ip, None, name, None, False, "unknown")


def classify_transport(proto: str, port: int) -> Transport:
    if port in SUSPICIOUS_PORTS:
        return Transport(None, "remote", SUSPICIOUS_PORTS[port])
    if port in (443, 8443):
        return Transport(True, "web")  # TLS sobre TCP o QUIC sobre UDP
    if port in (80, 8080):
        return Transport(False, "web")
    if port == 53:
        return Transport(False, "dns")
    if port == 853:
        return Transport(True, "dns")
    if port in (993, 995, 465, 587):
        return Transport(True, "mail")
    if port in (25, 110, 143):
        return Transport(False, "mail")
    if port == 123:
        return Transport(False, "time")
    if port in (5353, 1900, 5355, 137, 138):
        return Transport(False, "discovery")
    if port == 22:
        return Transport(True, "remote")
    if port in (21, 23):
        return Transport(False, "remote")
    if port in (5222, 5223, 5228):
        return Transport(True, "push")
    if port in (1194, 51820, 500, 4500):
        return Transport(True, "vpn")
    if proto == "udp" and (3478 <= port <= 3481 or 19302 <= port <= 19309 or 8801 <= port <= 8810):
        return Transport(True, "call")  # STUN/TURN, Google Meet, Zoom: van cifradas (SRTP)
    return Transport(None, "other")
