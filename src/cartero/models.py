"""Estructuras de datos compartidas por todo el motor."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RawConnection:
    """Una conexión tal y como la ve el sistema operativo en un instante."""

    pid: int | None
    process: str  # nombre del ejecutable ("" si no tenemos permisos para verlo)
    exe: str
    proto: str  # "tcp" | "udp"
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str = ""


@dataclass
class FlowStats:
    """Lo que la captura de paquetes (opcional) sabe de una conexión."""

    bytes_up: int = 0
    bytes_down: int = 0
    small_up_events: list[float] = field(default_factory=list)  # envíos diminutos tras un silencio
    open_form: bool = False  # se vio un formulario enviado sin cifrar


@dataclass
class Flow:
    """Un "envío" agrupado: un programa hablando con un destino por una vía.

    Varias conexiones TCP sucesivas hacia el mismo destino se agrupan en el
    mismo flujo; cada vez que aparece un puerto local nuevo lo anotamos en
    ``open_events``, lo que permite detectar latidos aunque no haya captura.
    """

    process: str
    exe: str
    pid: int | None
    proto: str
    remote_ip: str
    remote_port: int
    first_seen: float
    last_seen: float
    local_ports: set[int] = field(default_factory=set)
    open_events: list[float] = field(default_factory=list)
    stats: FlowStats = field(default_factory=FlowStats)

    @property
    def key(self) -> tuple[str, str, str, int]:
        return (self.process, self.proto, self.remote_ip, self.remote_port)
