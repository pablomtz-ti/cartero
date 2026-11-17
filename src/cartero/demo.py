"""Modo demostración: un ordenador ficticio con situaciones típicas.

Sirve para probar la interfaz sin permisos de administrador, para hacer
capturas de pantalla y para los tests. Todo pasa por el mismo motor que el
modo real; solo cambia de dónde salen las conexiones.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from .models import FlowStats, RawConnection
from .resolver import Resolver
from .wifi import Device

WARMUP = 300.0  # segundos "vividos" antes de arrancar, para que haya historia


@dataclass(frozen=True)
class DemoConn:
    pid: int
    process: str
    exe: str
    proto: str
    ip: str
    port: int
    domain: str | None
    up_rate: float = 0.0  # bytes/s
    down_rate: float = 0.0
    heartbeat: float | None = None  # segundos entre latidos
    open_form: bool = False
    country: str | None = None
    local_port: int = 0


WIN = r"C:\Program Files"
SCENARIO: list[DemoConn] = [
    DemoConn(4120, "chrome.exe", rf"{WIN}\Google\Chrome\Application\chrome.exe", "tcp",
             "142.250.184.14", 443, "www.google.com", 300, 9_000, local_port=51010),
    DemoConn(4120, "chrome.exe", rf"{WIN}\Google\Chrome\Application\chrome.exe", "udp",
             "142.250.200.110", 443, "rr3---sn-h5q7knes.googlevideo.com", 900, 160_000, local_port=51011),
    DemoConn(4120, "chrome.exe", rf"{WIN}\Google\Chrome\Application\chrome.exe", "tcp",
             "142.250.75.226", 443, "stats.g.doubleclick.net", 80, 120, local_port=51012),
    DemoConn(4120, "chrome.exe", rf"{WIN}\Google\Chrome\Application\chrome.exe", "tcp",
             "216.58.209.78", 443, "www.google-analytics.com", 60, 90, local_port=51013),
    DemoConn(4120, "chrome.exe", rf"{WIN}\Google\Chrome\Application\chrome.exe", "tcp",
             "93.184.215.14", 80, "ejemplo.com", 40, 1_500, local_port=51014),
    DemoConn(6011, "firefox.exe", rf"{WIN}\Mozilla Firefox\firefox.exe", "tcp",
             "185.53.177.20", 80, "login.tienda-antigua.es", 60, 800, open_form=True, local_port=52020),
    DemoConn(6011, "firefox.exe", rf"{WIN}\Mozilla Firefox\firefox.exe", "tcp",
             "34.107.243.93", 443, "incoming.telemetry.mozilla.org", 50, 20, local_port=52021),
    DemoConn(7788, "Spotify.exe", r"C:\Users\ana\AppData\Roaming\Spotify\Spotify.exe", "tcp",
             "35.186.224.47", 443, "spclient.wg.spotify.com", 40, 1_000, local_port=53030),
    DemoConn(7788, "Spotify.exe", r"C:\Users\ana\AppData\Roaming\Spotify\Spotify.exe", "tcp",
             "151.101.2.248", 443, "audio-ak.spotifycdn.com", 10, 50_000, local_port=53031),
    DemoConn(4401, "Discord.exe", r"C:\Users\ana\AppData\Local\Discord\app-1.0.9\Discord.exe", "tcp",
             "162.159.135.232", 443, "gateway.discord.gg", 2, 6, heartbeat=41.25, local_port=54040),
    DemoConn(5550, "Zoom.exe", r"C:\Users\ana\AppData\Roaming\Zoom\bin\Zoom.exe", "udp",
             "170.114.10.85", 8801, "zoomfrn85mmr.fra.zoom.us", 160_000, 190_000, local_port=55050),
    DemoConn(9132, "updater_service.exe", r"C:\ProgramData\SysUpd\updater_service.exe", "tcp",
             "95.161.76.100", 443, None, 4, 2, heartbeat=10.0, country="RU", local_port=56060),
    DemoConn(6666, "winupd32.exe", r"C:\Users\ana\AppData\Local\Temp\winupd32.exe", "tcp",
             "185.220.101.47", 4444, None, 30, 15, heartbeat=5.0, local_port=57070),
    DemoConn(1204, "svchost.exe", r"C:\Windows\System32\svchost.exe", "tcp",
             "20.42.65.92", 443, "v10.events.data.microsoft.com", 150, 40, local_port=58080),
    DemoConn(1204, "svchost.exe", r"C:\Windows\System32\svchost.exe", "tcp",
             "13.107.4.50", 443, "fe3cr.delivery.mp.microsoft.com", 20, 400, local_port=58081),
    DemoConn(3300, "MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe", "tcp",
             "52.182.143.212", 443, "wdcp.microsoft.com", 30, 200, local_port=59090),
    DemoConn(8800, "OneDrive.exe", r"C:\Users\ana\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "tcp",
             "13.107.42.12", 443, "my.microsoftpersonalcontent.sharepoint.com", 400, 600, local_port=60100),
    DemoConn(2120, "SearchHost.exe", r"C:\Windows\SystemApps\SearchHost.exe", "tcp",
             "13.107.21.200", 443, "www.bing.com", 50, 300, local_port=60200),
    DemoConn(1500, "svchost.exe", r"C:\Windows\System32\svchost.exe", "udp",
             "224.0.0.251", 5353, None, 5, 5, local_port=5353),
]


class DemoWorld:
    """Fuente de conexiones + estadísticas de captura + resolutor, todo ficticio."""

    limited = False
    available = True

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self.start = clock() - WARMUP
        self._by_key = {(c.proto, c.local_port, c.ip, c.port): c for c in SCENARIO}
        self._names = {c.ip: c.domain for c in SCENARIO if c.domain}
        self._countries = {c.ip: c.country for c in SCENARIO if c.country}

    def connections(self) -> list[RawConnection]:
        return [
            RawConnection(c.pid, c.process, c.exe, c.proto, "192.168.1.34", c.local_port, c.ip, c.port,
                          "ESTABLISHED" if c.proto == "tcp" else "NONE")
            for c in SCENARIO
        ]

    def stats_for(self, proto: str, local_port: int, remote_ip: str, remote_port: int) -> FlowStats | None:
        c = self._by_key.get((proto, local_port, remote_ip, remote_port))
        if c is None:
            return None
        now = self.clock()
        alive = now - self.start
        events: list[float] = []
        if c.heartbeat:
            t = self.start
            while t <= now:
                events.append(t)
                t += c.heartbeat
        return FlowStats(int(c.up_rate * alive), int(c.down_rate * alive), events[-40:], c.open_form)

    def domain_for(self, ip: str) -> str | None:
        return self._names.get(ip)

    def online_info(self, ip: str) -> dict | None:
        country = self._countries.get(ip)
        return {"org": None, "country": country} if country else None


class DemoResolver(Resolver):
    def __init__(self, world: DemoWorld) -> None:
        super().__init__(capture=world, online=False, workers=1)
        self.world = world

    def domain_for(self, ip: str) -> str | None:
        return self.world.domain_for(ip)

    def online_info(self, ip: str) -> dict | None:
        return self.world.online_info(ip)


def demo_devices() -> list[Device]:
    from .wifi import describe_device

    raw = [
        ("192.168.1.1", "e4:ab:89:12:34:56", "Sagemcom Broadband SAS", None),
        ("192.168.1.34", "3c:58:c2:aa:bb:cc", "Intel Corporate", "portatil-ana"),
        ("192.168.1.20", "f2:6d:11:22:33:44", None, "iPhone-de-Juan"),
        ("192.168.1.21", "8c:79:f5:01:02:03", "Samsung Electronics Co.,Ltd", "Samsung-TV"),
        ("192.168.1.40", "24:0a:c4:55:66:77", "Espressif Inc.", None),
        ("192.168.1.52", "b8:27:eb:98:76:54", "Raspberry Pi Foundation", "raspberrypi"),
        ("192.168.1.66", "00:11:22:33:44:55", None, None),
    ]
    return [
        describe_device(ip, mac, vendor, host, gateway="192.168.1.1", my_ips={"192.168.1.34"})
        for ip, mac, vendor, host in raw
    ]
