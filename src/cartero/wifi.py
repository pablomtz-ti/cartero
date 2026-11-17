"""¿Quién está conectado a mi Wi-Fi?

Leemos la "agenda de vecinos" del sistema (tabla ARP/NDP), que guarda los
aparatos de tu red con los que tu ordenador ha hablado hace poco. La
búsqueda a fondo envía un saludo vacío a cada dirección de tu red para que
todos los aparatos encendidos aparezcan en esa agenda.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass

import psutil

from .knowledge import Knowledge

MAC_RE = re.compile(r"(?<![0-9a-f])((?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2})(?![0-9a-f])", re.I)
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
HOST_SUFFIXES = (".local", ".lan", ".home", ".fritz.box", ".localdomain", ".home.arpa", ".router")

# palabra clave en el fabricante -> (tipo, icono, nombre amigable)
VENDOR_HINTS: list[tuple[str, str, str, str]] = [
    ("apple", "phone", "📱", "Dispositivo Apple (iPhone, iPad o Mac)"),
    ("samsung", "phone", "📱", "Dispositivo Samsung (móvil o televisor)"),
    ("xiaomi", "phone", "📱", "Dispositivo Xiaomi"),
    ("huawei", "phone", "📱", "Dispositivo Huawei"),
    ("oneplus", "phone", "📱", "Móvil OnePlus"),
    ("oppo", "phone", "📱", "Móvil Oppo"),
    ("motorola", "phone", "📱", "Móvil Motorola"),
    ("lg electronics", "tv", "📺", "Dispositivo LG (televisor o móvil)"),
    ("sony", "tv", "🎮", "Dispositivo Sony (PlayStation o televisor)"),
    ("nintendo", "console", "🎮", "Consola Nintendo"),
    ("microsoft", "console", "🎮", "Dispositivo Microsoft (Xbox o Surface)"),
    ("roku", "tv", "📺", "Reproductor Roku"),
    ("amazon", "speaker", "🔊", "Dispositivo Amazon (Echo, Fire TV o Kindle)"),
    ("google", "speaker", "🔊", "Dispositivo Google (Chromecast o Nest)"),
    ("sonos", "speaker", "🔊", "Altavoz Sonos"),
    ("espressif", "iot", "💡", "Aparato inteligente (enchufe, bombilla, cámara…)"),
    ("tuya", "iot", "💡", "Aparato inteligente (enchufe, bombilla, cámara…)"),
    ("shelly", "iot", "💡", "Aparato inteligente Shelly"),
    ("philips", "iot", "💡", "Luces Philips Hue"),
    ("signify", "iot", "💡", "Luces Philips Hue"),
    ("raspberry", "computer", "🖥️", "Mini-ordenador Raspberry Pi"),
    ("hewlett", "printer", "🖨️", "Impresora HP"),
    ("canon", "printer", "🖨️", "Impresora Canon"),
    ("epson", "printer", "🖨️", "Impresora Epson"),
    ("brother", "printer", "🖨️", "Impresora Brother"),
    ("intel", "computer", "💻", "Ordenador (portátil o PC)"),
    ("realtek", "computer", "💻", "Ordenador (portátil o PC)"),
    ("liteon", "computer", "💻", "Ordenador (portátil o PC)"),
    ("azurewave", "computer", "💻", "Ordenador (portátil o PC)"),
    ("dell", "computer", "💻", "Ordenador Dell"),
    ("lenovo", "computer", "💻", "Ordenador Lenovo"),
    ("asustek", "computer", "💻", "Dispositivo ASUS"),
    ("tp-link", "network", "📶", "Router o repetidor TP-Link"),
    ("netgear", "network", "📶", "Router o repetidor Netgear"),
    ("ubiquiti", "network", "📶", "Punto de acceso Wi-Fi Ubiquiti"),
    ("avm", "network", "📶", "Router FRITZ!Box"),
    ("vmware", "computer", "🖥️", "Máquina virtual"),
    ("virtualbox", "computer", "🖥️", "Máquina virtual"),
]
HOST_HINTS: list[tuple[str, str, str]] = [
    ("iphone", "phone", "📱"), ("ipad", "phone", "📱"), ("android", "phone", "📱"),
    ("galaxy", "phone", "📱"), ("pixel", "phone", "📱"), ("macbook", "computer", "💻"),
    ("imac", "computer", "🖥️"), ("tv", "tv", "📺"), ("chromecast", "tv", "📺"),
    ("echo", "speaker", "🔊"), ("printer", "printer", "🖨️"), ("impresora", "printer", "🖨️"),
    ("playstation", "console", "🎮"), ("ps5", "console", "🎮"), ("xbox", "console", "🎮"),
    ("switch", "console", "🎮"), ("raspberry", "computer", "🖥️"), ("desktop", "computer", "🖥️"),
    ("laptop", "computer", "💻"), ("portatil", "computer", "💻"), ("pc", "computer", "💻"),
]


@dataclass
class Device:
    ip: str
    mac: str
    name: str
    icon: str
    kind: str
    vendor: str | None
    hostname: str | None
    is_router: bool
    is_me: bool
    private_mac: bool
    note: str | None

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_mac(mac: str) -> str:
    parts = re.split(r"[:-]", mac.lower())
    return ":".join(p.zfill(2) for p in parts)


def is_private_mac(mac: str) -> bool:
    """Los móviles inventan una MAC "local" (bit 2 del primer byte) para no ser rastreados."""
    try:
        return bool(int(normalize_mac(mac)[:2], 16) & 0x02)
    except ValueError:
        return False


def pretty_hostname(host: str | None) -> str | None:
    if not host:
        return None
    host = host.rstrip(".")
    for suffix in HOST_SUFFIXES:
        if host.lower().endswith(suffix):
            host = host[: -len(suffix)]
    host = host.split(".")[0]
    if not host or re.fullmatch(r"[\d-]+", host) or re.fullmatch(r"[0-9a-f]{12,}", host, re.I):
        return None
    if host.lower().startswith("android-"):
        return "Móvil Android"
    return re.sub(r"[-_]+", " ", host).strip()


def describe_device(
    ip: str,
    mac: str,
    vendor: str | None,
    hostname: str | None,
    gateway: str | None,
    my_ips: set[str],
) -> Device:
    is_router = ip == gateway
    is_me = ip in my_ips
    private = is_private_mac(mac)
    pretty = pretty_hostname(hostname)
    kind, icon, name, note = "unknown", "❔", "Dispositivo desconocido", None

    low_vendor = (vendor or "").lower()
    for key, k, i, n in VENDOR_HINTS:
        if key in low_vendor:
            kind, icon, name = k, i, n
            break
    if pretty:
        low = pretty.lower()
        for key, k, i in HOST_HINTS:
            if key in low:
                kind, icon = k, i
                break
        name = pretty
    if private and kind == "unknown":
        kind, icon = "phone", "📱"
        if not pretty:
            name = "Móvil o tablet con dirección privada"
        note = ("Usa una dirección privada: los móviles modernos se inventan una distinta en cada Wi-Fi "
                "para que no puedan seguirte. Es normal.")
    if kind == "unknown" and not pretty:
        note = ("No sabemos qué es. Si no reconoces ningún aparato así en casa, cambia la contraseña "
                "de tu Wi-Fi.")
    if is_router:
        kind, icon, name = "router", "📶", "Tu router (la caja de Internet)"
        note = None
    if is_me:
        kind, icon, name = "me", "🏠", "Este ordenador (tú)"
        note = None
    return Device(ip, normalize_mac(mac), name, icon, kind, vendor, pretty, is_router, is_me, private, note)


def parse_neighbors(output: str) -> list[tuple[str, str]]:
    """Extrae pares (ip, mac) de la salida de ``ip neigh`` o ``arp -a`` (Linux, macOS, Windows)."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        if re.search(r"FAILED|INCOMPLETE|incomplete", line):
            continue
        ip_m, mac_m = IPV4_RE.search(line), MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        ip, mac = ip_m.group(1), normalize_mac(mac_m.group(1))
        addr = ipaddress.ip_address(ip)
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or addr.is_multicast or ip.endswith(".255"):
            continue
        if ip not in seen:
            seen.add(ip)
            out.append((ip, mac))
    return out


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def read_neighbors() -> list[tuple[str, str]]:
    if platform.system() == "Linux":
        found = parse_neighbors(_run(["ip", "-4", "neigh", "show"]))
        if found:
            return found
    return parse_neighbors(_run(["arp", "-a"]))


def default_gateway() -> str | None:
    system = platform.system()
    if system == "Linux":
        text = _run(["ip", "-4", "route", "show", "default"])
    elif system == "Darwin":
        text = _run(["route", "-n", "get", "default"])
    else:
        text = _run(["route", "print", "0.0.0.0"])
    for line in text.splitlines():
        if "default" in line or "gateway" in line or line.strip().startswith("0.0.0.0"):
            ips = [ip for ip in IPV4_RE.findall(line) if ip != "0.0.0.0"]
            if ips:
                return ips[0]
    return None


def local_networks() -> list[tuple[str, ipaddress.IPv4Network, str]]:
    """(ip, red, mac) de cada interfaz con una dirección privada IPv4.

    Si conocemos el router, nos quedamos solo con la red en la que está, para
    no confundir redes virtuales (Docker, VPN…) con tu Wi-Fi.
    """
    nets = []
    for addrs in psutil.net_if_addrs().values():
        mac = next((normalize_mac(a.address) for a in addrs if a.family == psutil.AF_LINK and a.address), "")
        for a in addrs:
            if a.family == socket.AF_INET and a.netmask and not a.address.startswith("127."):
                net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
                if net.is_private:
                    nets.append((a.address, net, mac))
    gateway = default_gateway()
    if gateway:
        same = [n for n in nets if ipaddress.ip_address(gateway) in n[1]]
        nets = same or nets
    return nets


def wake_up_network(max_hosts: int = 512) -> None:
    """Envía un datagrama vacío a cada vecino para que aparezca en la tabla ARP."""
    targets: list[str] = []
    for _, net, _ in local_networks():
        if net.num_addresses > max_hosts:  # redes enormes: solo nuestra /24
            continue
        targets.extend(str(h) for h in net.hosts())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        for ip in targets[:max_hosts]:
            try:
                sock.sendto(b"", (ip, 9))  # puerto "discard": nadie responde, pero se resuelve la MAC
            except OSError:
                continue
    time.sleep(1.5)


def _hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def scan_devices(kb: Knowledge, deep: bool = False) -> list[Device]:
    if deep:
        wake_up_network()
    neighbors = read_neighbors()
    nets = local_networks()
    my_ips = {ip for ip, _, _ in nets}
    gateway = default_gateway()
    known = {ip for ip, _ in neighbors}
    neighbors += [(ip, mac or "00:00:00:00:00:00") for ip, _, mac in nets if ip not in known]
    with ThreadPoolExecutor(max_workers=16) as pool:
        names = dict(zip([ip for ip, _ in neighbors], pool.map(_hostname, [ip for ip, _ in neighbors]), strict=False))
    devices = [
        describe_device(ip, mac, kb.vendor_for_mac(mac), names.get(ip), gateway, my_ips)
        for ip, mac in neighbors
    ]
    return sort_devices(devices)


def sort_devices(devices: list[Device]) -> list[Device]:
    return sorted(
        devices,
        key=lambda d: (not d.is_router, not d.is_me, d.kind == "unknown", tuple(int(x) for x in d.ip.split("."))),
    )
