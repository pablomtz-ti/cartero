"""El "motor de traducción": convierte flujos de red en tarjetas en lenguaje cotidiano.

Ningún término técnico (IP, puerto, TCP, DNS…) aparece en los textos
principales; solo dentro de la sección plegada de "detalles técnicos".
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from urllib.parse import quote

from .behavior import human_bytes, human_duration, join_es, periodic_interval, traffic_pattern
from .classifier import NORMAL_KINDS, Destination, Transport, classify_transport
from .knowledge import Knowledge, ProcessInfo
from .models import Flow

LEVEL_ORDER = {"ok": 0, "info": 1, "warn": 2, "danger": 3}
LEVEL_LABELS = {
    "ok": "Todo normal",
    "info": "Normal, con algún detalle",
    "warn": "Para revisar",
    "danger": "¡Atención!",
}
# Categorías de programas cuyo tráfico rutinario se oculta con "Silenciar ruido normal".
QUIET_CATEGORIES = {"system", "security", "network", "cloud"}

DEFAULT_ACTIVITY = {
    "browser": "Navegando por webs",
    "media": "Reproduciendo o sincronizando música y vídeo",
    "chat": "Manteniendo tus chats conectados",
    "call": "Preparado para llamadas y reuniones",
    "cloud": "Sincronizando tus archivos con la nube",
    "system": "Haciendo tareas internas del sistema",
    "security": "Descargando actualizaciones de seguridad",
    "network": "Manteniendo tu conexión a Internet funcionando",
    "dev": "Herramienta de programación conectada a Internet",
    "game": "Tienda o juego conectado a Internet",
    "office": "Sincronizando tus documentos o correo",
}


@dataclass
class Alert:
    level: str
    icon: str
    title: str
    what: str
    why: str
    todo: str


@dataclass
class Card:
    id: str
    program: str
    file: str
    category: str
    known_program: bool
    level: str
    level_label: str
    talks_to: list[dict]
    doing: str
    fact: str
    alerts: list[Alert]
    technical: list[dict]
    noise: bool
    connections: int
    lookup: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


Resolve = Callable[[Flow], Destination]


def card_id(process: str) -> str:
    return hashlib.sha1(process.encode("utf-8")).hexdigest()[:10]


def build_cards(flows: list[Flow], resolve: Resolve, kb: Knowledge, now: float) -> list[Card]:
    groups: dict[str, list[Flow]] = {}
    for flow in flows:
        groups.setdefault(flow.process, []).append(flow)
    cards = [c for proc, fl in groups.items() if (c := _build_card(proc, fl, resolve, kb, now))]
    cards.sort(key=lambda c: (-LEVEL_ORDER[c.level], c.noise, c.program.lower()))
    return cards


def _process_info(process: str, kb: Knowledge) -> ProcessInfo:
    if not process:
        return ProcessInfo("Programas protegidos del sistema", "hidden", known=True)
    return kb.process_info(process)


def _build_card(process: str, flows: list[Flow], resolve: Resolve, kb: Knowledge, now: float) -> Card | None:
    pinfo = _process_info(process, kb)
    rows: list[tuple[Flow, Destination, Transport]] = []
    for flow in flows:
        dest = resolve(flow)
        if dest.kind == "self":  # un programa hablando consigo mismo: no es un envío
            continue
        rows.append((flow, dest, classify_transport(flow.proto, flow.remote_port)))
    if not rows:
        return None
    rows.sort(key=lambda r: -(r[0].stats.bytes_up + r[0].stats.bytes_down))

    program = pinfo.name if pinfo.known else f"Programa desconocido ({process})"
    heartbeat = _heartbeat(rows)
    alerts = _alerts(program, pinfo, rows, heartbeat)
    level = max((a.level for a in alerts), key=LEVEL_ORDER.__getitem__, default="ok")

    if pinfo.category == "hidden":
        noise = level == "ok" and all(d.kind in NORMAL_KINDS | {"local", "service"} for _, d, _ in rows)
    else:
        noise = level == "ok" and pinfo.category in QUIET_CATEGORIES

    exe = next((f.exe for f in flows if f.exe), "")
    unknown_ip = next((d.ip for _, d, _ in rows if d.kind == "unknown"), rows[0][1].ip)
    return Card(
        id=card_id(process),
        program=program,
        file=process,
        category=pinfo.category,
        known_program=pinfo.known,
        level=level,
        level_label=LEVEL_LABELS[level],
        talks_to=_talks_to(rows),
        doing=_doing(pinfo, rows, heartbeat),
        fact=_fact(rows, now),
        alerts=alerts,
        technical=[_technical(f, d, now) for f, d, _ in rows],
        noise=noise,
        connections=len(rows),
        lookup={
            "explanation": explain(process, pinfo, rows, heartbeat),
            "exe": exe,
            "links": _links(process, unknown_ip),
        },
    )


def _heartbeat(rows: list[tuple[Flow, Destination, Transport]]) -> tuple[float, Destination] | None:
    for flow, dest, _ in rows:
        interval = periodic_interval(flow.stats.small_up_events) or periodic_interval(flow.open_events)
        if interval:
            return interval, dest
    return None


def _alerts(
    program: str,
    pinfo: ProcessInfo,
    rows: list[tuple[Flow, Destination, Transport]],
    heartbeat: tuple[float, Destination] | None,
) -> list[Alert]:
    alerts: list[Alert] = []
    open_sites: list[str] = []
    form_sites: list[str] = []
    trackers: list[str] = []
    telemetry: list[str] = []
    seen_unknown = False

    for flow, dest, tr in rows:
        site = dest.domain or dest.name
        if tr.suspicious and not dest.trusted:
            rare = dest.kind == "unknown"
            alerts.append(
                Alert(
                    level="danger" if rare else "warn",
                    icon="🚨" if rare else "⚠️",
                    title="Conexión rara a un destino sin nombre conocido"
                    if rare
                    else f"Conexión por una puerta poco habitual hacia {dest.name}",
                    what=f"{program} está conectado a {dest.label} usando una puerta de entrada poco "
                    f"habitual (la número {flow.remote_port}), que {tr.suspicious}.",
                    why="Los programas normales casi nunca usan esa puerta. Puede ser una herramienta "
                    "que instalaste tú a propósito, pero también un programa malicioso que permite que "
                    "otra persona controle tu ordenador.",
                    todo="Si no reconoces el programa, desconecta el Wi-Fi, pasa un antivirus completo y "
                    "pulsa «¿Qué es esto?» para buscar su nombre. Si es una herramienta que usas tú, "
                    "puedes ignorar este aviso.",
                )
            )
        if flow.stats.open_form and not tr.sealed:
            form_sites.append(site)
        # Las actualizaciones y listas de certificados viajan sin cifrar pero van firmadas: no avisamos.
        elif tr.sealed is False and tr.purpose == "web" and not dest.is_local and dest.kind not in NORMAL_KINDS:
            open_sites.append(site)
        elif tr.sealed is False and tr.purpose == "remote" and not dest.is_local:
            alerts.append(
                Alert(
                    "warn", "⚠️", f"Conexión remota sin candado hacia {dest.name}",
                    what=f"{program} está usando un sistema antiguo de acceso remoto o de envío de "
                    "archivos que no tiene candado de seguridad.",
                    why="Todo lo que se envía, incluidas las contraseñas, viaja como una postal abierta "
                    "que cualquiera en la misma red puede leer.",
                    todo="Si eres tú quien lo usa, cambia a la versión segura (SSH o SFTP). Si no sabes "
                    "qué es, revisa el programa con «¿Qué es esto?».",
                )
            )
        if dest.kind == "tracker" and dest.tracker:
            trackers.append(dest.tracker)
        if dest.kind == "telemetry":
            telemetry.append(dest.name)
        if not pinfo.known and dest.kind == "unknown" and not seen_unknown and not tr.suspicious:
            seen_unknown = True
            rhythm = (
                f" Además, envía datos pequeños cada {heartbeat[0]:.0f} segundos, como si esperase órdenes."
                if heartbeat
                else ""
            )
            alerts.append(
                Alert(
                    "warn", "🟡", "Programa desconocido hablando con un servidor sin nombre",
                    what=f"Un programa que no conocemos ({pinfo.name}) está conectado a "
                    f"{dest.name[0].lower() + dest.name[1:]}.{rhythm}",
                    why="Los servicios legítimos casi siempre tienen un nombre público (como "
                    "google.com). Un programa desconocido que habla con un servidor anónimo puede ser "
                    "un actualizador poco conocido… o un programa no deseado.",
                    todo="Pulsa «¿Qué es esto?» para buscar el nombre del archivo. Si no lo instalaste "
                    "tú y nadie lo reconoce, desinstálalo y pasa un antivirus.",
                )
            )

    if form_sites:
        alerts.append(
            Alert(
                "danger", "⚠️", "Enviando un formulario abierto (¡cuidado si escribiste contraseñas!)",
                what=f"{program} acaba de enviar un formulario a {join_es(_unique(form_sites))} sin "
                "candado de seguridad.",
                why="Lo que escribiste en ese formulario viajó como una postal abierta: cualquiera en "
                "tu misma red Wi-Fi podría haberlo leído.",
                todo="Si escribiste una contraseña, cámbiala cuanto antes desde una conexión segura y "
                "no la reutilices en otras webs. No vuelvas a escribir datos en esa página.",
            )
        )
    if open_sites:
        sites = join_es(_unique(open_sites)[:3])
        alerts.append(
            Alert(
                "warn", "🔓", "Página web sin candado",
                what=f"{program} entró a una página web antigua ({sites}) que no tiene candado de "
                "seguridad.",
                why="Si estás en el Wi-Fi de una cafetería, un hotel o el aeropuerto, otras personas "
                "conectadas podrían ver qué páginas miras o qué escribes ahí.",
                todo="No escribas contraseñas ni datos bancarios en esa página. Si solo estás leyendo "
                "noticias, no pasa nada.",
            )
        )
    if trackers:
        alerts.append(
            Alert(
                "info", "👁️", "Rastreador de publicidad observando qué página visitas",
                what=f"Mientras usas {program}, {join_es(_unique(trackers)[:4])} reciben aviso de lo "
                "que visitas.",
                why="Así construyen un perfil de tus gustos para mostrarte anuncios. No es un virus, "
                "pero sí afecta a tu privacidad.",
                todo="Si te molesta, instala un bloqueador como uBlock Origin o activa la protección "
                "contra rastreo de tu navegador.",
            )
        )
    if telemetry:
        alerts.append(
            Alert(
                "info", "📊", f"{program} enviando estadísticas de uso en silencio",
                what=f"{program} está enviando a {join_es(_unique(telemetry))} información sobre cómo "
                "usas el ordenador.",
                why="Es algo habitual y no es peligroso: los fabricantes lo usan para detectar fallos. "
                "Pero son datos tuyos que salen sin que lo pidas.",
                todo="Puedes reducirlo en la configuración de privacidad de tu sistema (en Windows: "
                "Configuración › Privacidad › Diagnóstico).",
            )
        )
    return alerts


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _talks_to(rows: list[tuple[Flow, Destination, Transport]]) -> list[dict]:
    out: dict[str, dict] = {}
    for _, dest, _ in rows:
        out.setdefault(
            dest.label,
            {"name": dest.name, "country": dest.country, "trusted": dest.trusted, "kind": dest.kind},
        )
    return list(out.values())


def _doing(pinfo: ProcessInfo, rows: list[tuple[Flow, Destination, Transport]], heartbeat) -> str:
    up = sum(f.stats.bytes_up for f, _, _ in rows)
    down = sum(f.stats.bytes_down for f, _, _ in rows)
    pattern = traffic_pattern(up, down)
    purposes = {t.purpose for _, _, t in rows}
    remote = [(d, t) for _, d, t in rows if not d.is_local]
    udp_heavy = any(f.proto == "udp" and f.stats.bytes_up + f.stats.bytes_down > 500_000 for f, _, _ in rows)

    if not remote:
        if purposes <= {"discovery"}:
            return "Buscando impresoras, televisores y otros aparatos en tu Wi-Fi"
        return "Hablando con aparatos de tu red de casa"
    if "call" in purposes or (pattern == "both" and udp_heavy):
        activity = "Llamada de voz o vídeo, o transmisión en directo"
    elif pattern == "consuming":
        activity = {
            "media": "Descargando música o vídeo",
            "browser": "Cargando páginas, vídeos o imágenes",
        }.get(pinfo.category, "Recibiendo contenido (vídeo, música o webs)")
    elif pattern == "uploading":
        activity = "Subiendo archivos, haciendo una copia de seguridad o en videollamada"
    elif heartbeat:
        activity = f"Enviando datos pequeños cada {heartbeat[0]:.0f} segundos en segundo plano"
    elif purposes <= {"dns"}:
        activity = "Preguntando direcciones de páginas web"
    elif purposes <= {"time"}:
        activity = "Poniendo en hora el reloj del ordenador"
    else:
        activity = DEFAULT_ACTIVITY.get(pinfo.category, "Conectado a Internet")

    sealed = [t.sealed for _, t in remote]
    if all(s is True for s in sealed):
        return f"{activity}, de forma privada (con candado)."
    if any(s is False for s in sealed):
        return f"{activity}. Ojo: parte de lo que envía va sin candado."
    return f"{activity}."


def _fact(rows: list[tuple[Flow, Destination, Transport]], now: float) -> str:
    up = sum(f.stats.bytes_up for f, _, _ in rows)
    down = sum(f.stats.bytes_down for f, _, _ in rows)
    if up or down:
        pattern = traffic_pattern(up, down)
        if pattern == "consuming":
            return (
                f"Ha enviado muy poca información tuya ({human_bytes(up)}) y ha descargado mucha "
                f"({human_bytes(down)})."
            )
        if pattern == "uploading":
            return f"Ha enviado mucha información ({human_bytes(up)}) y ha recibido poca ({human_bytes(down)})."
        return f"Ha enviado {human_bytes(up)} y ha recibido {human_bytes(down)}."
    since = min(f.first_seen for f, _, _ in rows)
    places = len({d.label for _, d, _ in rows})
    where = "1 sitio" if places == 1 else f"{places} sitios distintos"
    return f"Lleva al menos {human_duration(now - since)} conectado a {where}."


def _technical(flow: Flow, dest: Destination, now: float) -> dict:
    host = f"[{flow.remote_ip}]" if ":" in flow.remote_ip else flow.remote_ip
    return {
        "remote": f"{host}:{flow.remote_port}",
        "proto": flow.proto.upper(),
        "domain": dest.domain,
        "pid": flow.pid,
        "since": human_duration(now - flow.first_seen),
        "up": human_bytes(flow.stats.bytes_up) if flow.stats.bytes_up else None,
        "down": human_bytes(flow.stats.bytes_down) if flow.stats.bytes_down else None,
    }


def _links(process: str, ip: str) -> list[dict]:
    links = []
    if process:
        links.append(
            {"label": f"Buscar «{process}» en Google",
             "url": f"https://www.google.com/search?q={quote(process + ' qué es')}"}
        )
    links.append({"label": "Ver la reputación del destino en VirusTotal",
                  "url": f"https://www.virustotal.com/gui/ip-address/{quote(ip)}"})
    return links


def explain(process: str, pinfo: ProcessInfo, rows, heartbeat) -> list[str]:
    """Respuesta de dos líneas para el botón «¿Qué es esto?»."""
    if not process:
        first = ("Son programas del sistema que Cartero no tiene permiso para identificar. "
                 "Si abres Cartero como administrador verás sus nombres.")
    elif pinfo.known:
        first = f"«{process}» es {pinfo.name[0].lower() + pinfo.name[1:]}. Es un programa conocido."
    else:
        first = (f"«{process}» no está en nuestra lista de programas conocidos. Eso no significa que "
                 "sea malo: muchos programas pequeños tienen nombres raros.")
    unknown = [d for _, d, _ in rows if d.kind == "unknown"]
    if unknown:
        where = f" en {unknown[0].country}" if unknown[0].country else ""
        second = (f"Habla con un servidor sin nombre público{where}; los servicios legítimos casi siempre "
                  "tienen uno. Comprueba su reputación con el enlace de abajo.")
    else:
        names = join_es(_unique([d.name for _, d, _ in rows])[:3])
        second = f"Habla con {names}, destinos con nombre conocido."
    if heartbeat:
        second += f" Da señales de vida cada {heartbeat[0]:.0f} segundos."
    return [first, second]


def verdict(cards: list[Card]) -> dict:
    danger = [c for c in cards if c.level == "danger"]
    warn = [c for c in cards if c.level == "warn"]
    trackers = sum(1 for c in cards for a in c.alerts if a.icon == "👁️")
    programs = len(cards)
    if danger:
        level, title = "danger", "Hemos encontrado algo raro"
        message = (f"{len(danger)} {'programa hace' if len(danger) == 1 else 'programas hacen'} cosas que "
                   "conviene revisar ya. Te explicamos qué pasa y qué hacer.")
    elif warn:
        level, title = "warn", f"Todo bien, salvo {len(warn)} {'cosa' if len(warn) == 1 else 'cosas'} para revisar"
        message = "No parece nada grave, pero échale un vistazo a lo que marcamos en amarillo."
    else:
        level, title = "ok", "Todo tranquilo"
        message = "No hemos visto nada raro. Tus programas hablan con empresas conocidas."
    return {
        "level": level,
        "title": title,
        "message": message,
        "programs": programs,
        "connections": sum(c.connections for c in cards),
        "trackers": trackers,
        "to_review": [c.id for c in danger + warn],
    }
