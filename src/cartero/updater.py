"""``cartero update-data``: descarga listas públicas ampliadas.

* Rastreadores: lista de Disconnect.me (la que usa Firefox).
* Fabricantes de tarjetas de red: registro oficial OUI del IEEE.

Se guardan en ``~/.local/share/cartero`` y se usan en el siguiente arranque.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from .knowledge import USER_DATA

DISCONNECT_URL = (
    "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json"
)
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
TRACKING_CATEGORIES = {"Advertising", "Analytics", "Social", "FingerprintingInvasive", "Cryptomining"}


def parse_disconnect(data: dict) -> dict[str, str]:
    """``{"categories": {"Advertising": [{"Empresa": {"https://web": ["dominio", ...]}}]}}``."""
    out: dict[str, str] = {}
    for category, entries in data.get("categories", {}).items():
        if category not in TRACKING_CATEGORIES:
            continue
        for entry in entries:
            for company, sites in entry.items():
                for value in sites.values():
                    if isinstance(value, list):
                        for domain in value:
                            out.setdefault(domain.lower(), company)
    return out


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "cartero-update"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def update_data(target: Path = USER_DATA) -> list[str]:
    target.mkdir(parents=True, exist_ok=True)
    report = []
    trackers = parse_disconnect(json.loads(_download(DISCONNECT_URL)))
    (target / "trackers.json").write_text(json.dumps(trackers, ensure_ascii=False, indent=0), encoding="utf-8")
    report.append(f"✔ {len(trackers)} dominios de rastreadores (Disconnect.me)")
    oui = _download(IEEE_OUI_URL)
    (target / "oui.csv").write_bytes(oui)
    vendors = oui.count(b"\n") - 1
    report.append(f"✔ {vendors} fabricantes de dispositivos (IEEE)")
    return report
