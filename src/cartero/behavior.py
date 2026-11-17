"""Detección de patrones de comportamiento y formateo de cantidades."""

from __future__ import annotations

from statistics import mean, pstdev


def periodic_interval(
    timestamps: list[float],
    min_events: int = 4,
    max_cv: float = 0.25,
    min_interval: float = 2.0,
) -> float | None:
    """Devuelve el intervalo medio si los eventos ocurren a ritmo constante.

    Un programa que "da latidos" (heartbeat) envía algo pequeño cada X
    segundos exactos. Medimos la regularidad con el coeficiente de variación
    (desviación típica / media) de los huecos entre eventos.
    """
    if len(timestamps) < min_events:
        return None
    ts = sorted(timestamps)[-13:]
    gaps = [b - a for a, b in zip(ts, ts[1:], strict=False) if b - a > 0.5]
    if len(gaps) < min_events - 1:
        return None
    avg = mean(gaps)
    if avg < min_interval:
        return None
    if pstdev(gaps) / avg > max_cv:
        return None
    return avg


def traffic_pattern(up: int, down: int) -> str | None:
    """Clasifica la asimetría de datos de subida y bajada."""
    total = up + down
    if total < 200_000:
        return None
    if down >= 4 * up:
        return "consuming"  # mucho baja, poco sube
    if up >= 4 * down:
        return "uploading"  # mucho sube, poco baja
    return "both"


def human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} bytes"
    for unit in ("KB", "MB", "GB"):
        n /= 1024
        if n < 1024 or unit == "GB":
            text = f"{n:.0f}" if n >= 10 else f"{n:.1f}".replace(".", ",")
            return f"{text} {unit}"
    raise AssertionError("unreachable")


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} segundos" if seconds != 1 else "1 segundo"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minutos" if minutes != 1 else "1 minuto"
    hours = minutes // 60
    return f"{hours} horas" if hours != 1 else "1 hora"


def join_es(items: list[str]) -> str:
    """["a", "b", "c"] -> "a, b y c"."""
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " y " + items[-1]
