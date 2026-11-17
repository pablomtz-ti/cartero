"""El escenario de demostración cubre todas las reglas de la especificación."""

import pytest

from cartero.demo import DemoResolver, DemoWorld
from cartero.engine import Engine


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def engine(kb):
    clock = Clock()
    world = DemoWorld(clock)
    e = Engine(world, kb, DemoResolver(world), capture=world, clock=clock, mode="demo")
    e.tick()
    return e


def by_file(engine, all_=False):
    return {c["file"]: c for c in engine.live(hide_noise=not all_)["cards"]}


def test_spotify_is_green_and_consuming(engine):
    c = by_file(engine)["Spotify.exe"]
    assert c["level"] == "ok"
    assert c["talks_to"][0]["name"] == "Spotify" and c["talks_to"][0]["trusted"]
    assert "con candado" in c["doing"]
    assert c["fact"].startswith("Ha enviado muy poca información tuya")


def test_unknown_program_with_heartbeat_to_russia(engine):
    c = by_file(engine)["updater_service.exe"]
    assert c["level"] == "warn"
    assert c["program"] == "Programa desconocido (updater_service.exe)"
    assert c["talks_to"][0]["name"] == "Un servidor sin nombre en Rusia"
    assert "cada 10 segundos" in c["doing"]
    assert "cada 10 segundos" in c["alerts"][0]["what"]


def test_suspicious_port_is_red(engine):
    c = by_file(engine)["winupd32.exe"]
    assert c["level"] == "danger"
    assert c["alerts"][0]["title"] == "Conexión rara a un destino sin nombre conocido"


def test_open_form_and_open_page(engine):
    cards = by_file(engine)
    assert cards["firefox.exe"]["level"] == "danger"
    assert any("formulario" in a["title"] for a in cards["firefox.exe"]["alerts"])
    titles = [a["title"] for a in cards["chrome.exe"]["alerts"]]
    assert "Página web sin candado" in titles
    assert "Rastreador de publicidad observando qué página visitas" in titles


def test_every_alert_answers_three_questions(engine):
    for card in by_file(engine, all_=True).values():
        for a in card["alerts"]:
            assert a["what"] and a["why"] and a["todo"]


def test_noise_is_hidden_by_default(engine):
    live = engine.live()
    files = {c["file"] for c in live["cards"]}
    assert "MsMpEng.exe" not in files and "OneDrive.exe" not in files
    assert live["hidden_connections"] >= 2
    assert "MsMpEng.exe" in by_file(engine, all_=True)


def test_telemetry_is_reported(engine):
    svchost = by_file(engine)["svchost.exe"]
    assert any("estadísticas" in a["title"] for a in svchost["alerts"])


def test_trusted_heartbeat_is_not_an_alert(engine):
    discord = by_file(engine)["Discord.exe"]
    assert discord["level"] == "ok" and "cada 41 segundos" in discord["doing"]


def test_no_technical_terms_in_main_text(engine):
    banned = ["TCP", "UDP", "DNS", "IP ", "puerto", "TLS", "HTTP"]
    for card in by_file(engine, all_=True).values():
        text = " ".join([card["doing"], card["fact"]] + [a["title"] for a in card["alerts"]])
        for word in banned:
            assert word not in text, (card["file"], word)


def test_scan_produces_verdict(engine):
    engine.start_scan(duration=30)
    assert engine.scan_status()["state"] == "running"
    engine.clock.t += 31
    engine.tick()
    status = engine.scan_status()
    assert status["state"] == "done"
    assert status["verdict"]["level"] == "danger"
    assert {c["file"] for c in status["cards"]} >= {"winupd32.exe", "updater_service.exe"}
