import http.client
import json
import threading

import pytest

from cartero.demo import DemoResolver, DemoWorld, demo_devices
from cartero.engine import Engine
from cartero.server import App, serve


@pytest.fixture
def server(kb):
    world = DemoWorld()
    engine = Engine(world, kb, DemoResolver(world), capture=world, mode="demo")
    engine.tick()
    httpd = serve(App(engine, kb, lambda deep: demo_devices()), port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown()


def get(port, path, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Host": host or f"127.0.0.1:{port}"})
    res = conn.getresponse()
    return res.status, res.getheader("Content-Type"), res.read()


def test_live_endpoint(server):
    status, ctype, body = get(server, "/api/live")
    assert status == 200 and ctype.startswith("application/json")
    assert json.loads(body)["mode"] == "demo"


def test_static_and_traversal(server):
    assert get(server, "/")[0] == 200
    assert get(server, "/app.js")[0] == 200
    assert get(server, "/../server.py")[0] == 404
    assert get(server, "/%2e%2e/server.py")[0] == 404


def test_rejects_foreign_host_header(server):
    """Una web maliciosa que apunte su dominio a 127.0.0.1 (DNS rebinding) no puede leer la API."""
    assert get(server, "/api/live", host="evil.example:8765")[0] == 403


def test_wifi_endpoint(server):
    devices = json.loads(get(server, "/api/wifi")[2])["devices"]
    assert any(d["kind"] == "router" for d in devices)
