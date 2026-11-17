"""Lee las conexiones abiertas del sistema operativo con psutil."""

from __future__ import annotations

import socket

import psutil

from .models import RawConnection

INTERESTING_STATUS = {psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT, psutil.CONN_NONE}


class SystemSource:
    """Fuente real: una "foto" de las conexiones cada vez que se llama."""

    def __init__(self) -> None:
        self._names: dict[int, tuple[float, str, str]] = {}  # pid -> (create_time, nombre, ruta)
        self.limited = False  # True si el sistema no nos deja ver los procesos de otros usuarios

    def connections(self) -> list[RawConnection]:
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:  # macOS sin sudo: vamos proceso a proceso
            self.limited = True
            conns = []
            for proc in psutil.process_iter(["pid"]):
                try:
                    conns.extend(
                        c._replace(pid=proc.pid) for c in proc.net_connections(kind="inet")
                    )
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
        out: list[RawConnection] = []
        for c in conns:
            if not c.raddr or c.status not in INTERESTING_STATUS:
                continue
            name, exe = self._process(c.pid)
            if c.pid is None:
                self.limited = True
            out.append(
                RawConnection(
                    pid=c.pid,
                    process=name,
                    exe=exe,
                    proto="tcp" if c.type == socket.SOCK_STREAM else "udp",
                    local_ip=c.laddr.ip if c.laddr else "",
                    local_port=c.laddr.port if c.laddr else 0,
                    remote_ip=c.raddr.ip,
                    remote_port=c.raddr.port,
                    status=c.status,
                )
            )
        return out

    def _process(self, pid: int | None) -> tuple[str, str]:
        if not pid:
            return "", ""
        try:
            proc = psutil.Process(pid)
            created = proc.create_time()
            cached = self._names.get(pid)
            if cached and cached[0] == created:
                return cached[1], cached[2]
            name = proc.name()
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                exe = ""
            self._names[pid] = (created, name, exe)
            return name, exe
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "", ""
