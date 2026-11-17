"""Punto de entrada: ``cartero`` arranca la app y abre el navegador."""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import webbrowser

from . import __version__
from .knowledge import Knowledge


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cartero",
        description="Mira qué cartas envía tu ordenador por Internet, explicado para humanos.",
    )
    p.add_argument("--version", action="version", version=f"cartero {__version__}")
    p.add_argument("--demo", action="store_true", help="usar un ordenador ficticio (no necesita permisos)")
    p.add_argument("--captura", "--capture", dest="capture", action="store_true",
                   help="analizar paquetes para medir datos y nombres reales (requiere scapy y sudo)")
    p.add_argument("--online", action="store_true",
                   help="consultar ipinfo.io el país/empresa de destinos sin nombre (envía esas IP a un tercero)")
    p.add_argument("--puerto", "--port", dest="port", type=int, default=8765, help="puerto local (8765)")
    p.add_argument("--sin-navegador", "--no-browser", dest="no_browser", action="store_true",
                   help="no abrir el navegador automáticamente")
    p.add_argument("--duracion-escaneo", dest="scan_seconds", type=float, default=30.0, help=argparse.SUPPRESS)
    p.add_argument("-v", "--verbose", action="store_true", help="mostrar mensajes de depuración")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("update-data", help="descargar listas ampliadas de rastreadores y fabricantes")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.command == "update-data":
        from .updater import update_data

        try:
            for line in update_data():
                print(line)
        except OSError as exc:
            print(f"No se pudieron descargar las listas: {exc}", file=sys.stderr)
            return 1
        return 0

    from .engine import Engine
    from .resolver import Resolver
    from .server import App, serve

    kb = Knowledge()
    if args.demo:
        from .demo import DemoResolver, DemoWorld, demo_devices
        from .wifi import sort_devices

        world = DemoWorld()
        engine = Engine(world, kb, DemoResolver(world), capture=world, mode="demo",
                        scan_seconds=args.scan_seconds)
        devices = lambda deep: sort_devices(demo_devices())  # noqa: E731
    else:
        from .collector import SystemSource
        from .wifi import scan_devices

        capture = None
        if args.capture:
            from .capture import PacketCapture

            capture = PacketCapture()
            if not capture.start():
                print(f"⚠ Captura desactivada: {capture.error}", file=sys.stderr)
        engine = Engine(SystemSource(), kb, Resolver(capture=capture if capture and capture.available else None,
                                                     online=args.online), capture=capture,
                        scan_seconds=args.scan_seconds)
        devices = lambda deep: scan_devices(kb, deep)  # noqa: E731

    engine.tick()
    engine.start()
    try:
        httpd = serve(App(engine, kb, devices), port=args.port)
    except OSError as exc:
        print(f"No se pudo abrir el puerto {args.port}: {exc}. Prueba con --puerto 8766", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{args.port}/"
    print(f"✉  Cartero {'(modo demo) ' if args.demo else ''}está en marcha: {url}")
    print("   Pulsa Ctrl+C para cerrarlo.")
    if not args.no_browser:
        threading.Timer(0.6, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nHasta luego 👋")
    finally:
        httpd.server_close()
        engine.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
