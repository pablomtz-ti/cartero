"""Base de conocimiento local: quién es quién en Internet.

Todo se carga desde ficheros JSON incluidos en el paquete (``cartero/data``)
y, si existen, desde listas ampliadas descargadas con ``cartero update-data``
(guardadas en ``~/.local/share/cartero``). Nada sale de tu ordenador.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

PACKAGE_DATA = Path(__file__).parent / "data"
USER_DATA = Path(os.environ.get("CARTERO_DATA_DIR", Path.home() / ".local" / "share" / "cartero"))

# Bases de datos de fabricantes de tarjetas de red que suelen venir con el sistema.
SYSTEM_OUI_FILES = (
    Path("/usr/share/ieee-data/oui.txt"),
    Path("/usr/share/wireshark/manuf"),
    Path("/usr/share/nmap/nmap-mac-prefixes"),
)

COUNTRIES = {
    "US": "EE. UU.", "ES": "España", "GB": "Reino Unido", "IE": "Irlanda", "FR": "Francia",
    "DE": "Alemania", "NL": "Países Bajos", "BE": "Bélgica", "IT": "Italia", "PT": "Portugal",
    "SE": "Suecia", "NO": "Noruega", "FI": "Finlandia", "DK": "Dinamarca", "CH": "Suiza",
    "AT": "Austria", "PL": "Polonia", "CZ": "Chequia", "SK": "Eslovaquia", "RO": "Rumanía",
    "RU": "Rusia", "UA": "Ucrania", "BY": "Bielorrusia", "TR": "Turquía", "CN": "China",
    "HK": "Hong Kong", "TW": "Taiwán", "JP": "Japón", "KR": "Corea del Sur", "KP": "Corea del Norte",
    "SG": "Singapur", "IN": "India", "IR": "Irán", "IL": "Israel", "AE": "Emiratos Árabes",
    "SA": "Arabia Saudí", "BR": "Brasil", "AR": "Argentina", "MX": "México", "CL": "Chile",
    "CO": "Colombia", "PE": "Perú", "CA": "Canadá", "AU": "Australia", "NZ": "Nueva Zelanda",
    "ZA": "Sudáfrica", "NG": "Nigeria", "VN": "Vietnam", "ID": "Indonesia", "TH": "Tailandia",
    "SC": "Seychelles", "PA": "Panamá", "BG": "Bulgaria", "MD": "Moldavia", "LU": "Luxemburgo",
}


@dataclass(frozen=True)
class OrgInfo:
    """Quién está detrás de un dominio o de un rango de IP."""

    org: str
    country: str | None  # código ISO de dos letras
    kind: str  # service | cdn | os | telemetry | cert | security | time
    trusted: bool

    @property
    def country_name(self) -> str | None:
        return country_name(self.country)


@dataclass(frozen=True)
class ProcessInfo:
    name: str
    category: str
    known: bool = True


def country_name(code: str | None) -> str | None:
    if not code:
        return None
    return COUNTRIES.get(code.upper(), code.upper())


def normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def match_suffix(domain: str, table: dict[str, Any]) -> Any | None:
    """Busca el sufijo de dominio más largo presente en ``table``.

    ``a.b.example.com`` comprueba ``a.b.example.com``, ``b.example.com``,
    ``example.com`` y ``com`` (en ese orden) respetando los puntos, de modo que
    ``notgoogle.com`` nunca coincide con ``google.com``.
    """
    labels = normalize_domain(domain).split(".")
    for i in range(len(labels)):
        value = table.get(".".join(labels[i:]))
        if value is not None:
            return value
    return None


def normalize_process(name: str) -> str:
    name = name.strip().lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _load_json(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {k: v for k, v in data.items() if not k.startswith("_")}


class Knowledge:
    """Agrupa todas las listas y ofrece búsquedas rápidas."""

    def __init__(self, data_dir: Path = PACKAGE_DATA, user_dir: Path = USER_DATA) -> None:
        self.data_dir = data_dir
        self.user_dir = user_dir
        self.domains: dict[str, OrgInfo] = {
            k: OrgInfo(**v) for k, v in _load_json(data_dir / "known_domains.json").items()
        }
        self.networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, OrgInfo]] = sorted(
            (
                (ipaddress.ip_network(k), OrgInfo(**v))
                for k, v in _load_json(data_dir / "ip_ranges.json").items()
            ),
            key=lambda item: item[0].prefixlen,
            reverse=True,  # el rango más específico primero
        )
        self.trackers: dict[str, str] = _load_json(data_dir / "trackers.json")
        extra = user_dir / "trackers.json"
        if extra.exists():
            try:
                self.trackers.update(_load_json(extra))
            except (OSError, ValueError):
                pass
        self.processes: dict[str, ProcessInfo] = {
            k: ProcessInfo(**v) for k, v in _load_json(data_dir / "processes.json").items()
        }
        self.glossary: dict[str, str] = _load_json(data_dir / "glossary.json")

    # --- dominios e IPs -------------------------------------------------
    def domain_info(self, domain: str | None) -> OrgInfo | None:
        return match_suffix(domain, self.domains) if domain else None

    def tracker_for(self, domain: str | None) -> str | None:
        return match_suffix(domain, self.trackers) if domain else None

    def ip_info(self, ip: str) -> OrgInfo | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, info in self.networks:
            if addr.version == net.version and addr in net:
                return info
        return None

    # --- programas ------------------------------------------------------
    def process_info(self, process: str) -> ProcessInfo:
        key = normalize_process(process)
        if key in self.processes:
            return self.processes[key]
        # "Discord Helper (Renderer)", "firefox-esr", "chrome_crashpad_handler"…
        first = re.split(r"[\s\-_.(]", key, maxsplit=1)[0]
        if first in self.processes:
            return self.processes[first]
        return ProcessInfo(name=process or "Programa sin nombre", category="unknown", known=False)

    # --- fabricantes de dispositivos -----------------------------------
    @cached_property
    def oui(self) -> dict[str, str]:
        """Prefijo MAC (6 hex en mayúsculas) -> fabricante."""
        table: dict[str, str] = {}
        candidates = [self.user_dir / "oui.csv", *SYSTEM_OUI_FILES]
        for path in candidates:
            if path.exists():
                try:
                    table.update(parse_oui_file(path))
                except OSError:
                    continue
                if table:
                    break
        table.update(_load_json(self.data_dir / "oui_min.json"))
        return table

    def vendor_for_mac(self, mac: str) -> str | None:
        prefix = re.sub(r"[^0-9A-Fa-f]", "", mac)[:6].upper()
        return self.oui.get(prefix) if len(prefix) == 6 else None


def parse_oui_file(path: Path) -> dict[str, str]:
    """Lee los formatos de IEEE (txt/csv), Wireshark y Nmap."""
    table: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        if path.suffix == ".csv":
            for row in csv.reader(fh):
                if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1]):
                    table[row[1].upper()] = row[2].strip()
            return table
        for line in fh:
            if "(hex)" in line:  # IEEE oui.txt: "00-1B-63   (hex)		Apple, Inc."
                prefix, _, vendor = line.partition("(hex)")
                key = prefix.strip().replace("-", "").upper()
                if len(key) == 6:
                    table[key] = vendor.strip()
                continue
            if line.startswith("#") or not line.strip() or "(base 16)" in line:
                continue
            parts = re.split(r"\s+", line.strip(), maxsplit=2)
            raw = parts[0]
            if "/" in raw:  # prefijos más cortos/largos de Wireshark: los ignoramos
                continue
            key = raw.replace(":", "").replace("-", "").upper()
            if len(key) != 6 or not re.fullmatch(r"[0-9A-F]{6}", key) or len(parts) < 2:
                continue
            if ":" in raw or "-" in raw:  # Wireshark: "00:1B:63<TAB>Apple<TAB>Apple, Inc."
                table[key] = parts[-1].strip()
            else:  # Nmap: "001B63 Apple"
                table[key] = line.strip()[len(raw):].strip()
    return table
