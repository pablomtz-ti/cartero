import struct

from cartero.capture import parse_http_request, parse_sni


def client_hello(server_name: str) -> bytes:
    name = server_name.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack("!HH", 0x000A, 4) + b"\x00\x02\x00\x1d"  # otra extensión antes
    ext += struct.pack("!HH", 0x0000, len(sni)) + sni
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_parse_sni():
    assert parse_sni(client_hello("api.TikTok.com")) == "api.tiktok.com"


def test_parse_sni_rejects_garbage():
    assert parse_sni(b"") is None
    assert parse_sni(b"GET / HTTP/1.1\r\n" * 4) is None
    assert parse_sni(client_hello("x.com")[:50]) is None


def test_parse_http_form():
    req = (b"POST /login.php HTTP/1.1\r\nHost: tienda-antigua.es\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&pass=b")
    assert parse_http_request(req) == ("tienda-antigua.es", True)
    assert parse_http_request(b"GET / HTTP/1.1\r\nHost: ejemplo.com:8080\r\n\r\n") == ("ejemplo.com", False)
    assert parse_http_request(b"\x16\x03\x01binary") == (None, False)
