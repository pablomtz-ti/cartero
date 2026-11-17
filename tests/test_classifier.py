from cartero.classifier import classify_destination, classify_transport, site_name


def test_local_and_self(kb):
    assert classify_destination("127.0.0.1", None, kb).kind == "self"
    assert classify_destination("::ffff:127.0.0.1", None, kb).kind == "self"
    assert classify_destination("192.168.1.1", None, kb).kind == "local"
    assert classify_destination("224.0.0.251", None, kb).kind == "local"


def test_known_company_is_verified(kb):
    d = classify_destination("35.186.224.47", "spclient.wg.spotify.com", kb)
    assert (d.name, d.country, d.trusted) == ("Spotify", "Suecia", True)
    assert d.label == "Spotify (Suecia)"


def test_tracker_wins_over_company(kb):
    d = classify_destination("142.250.75.226", "stats.g.doubleclick.net", kb)
    assert d.kind == "tracker" and not d.trusted


def test_unknown_with_and_without_country(kb):
    assert classify_destination("95.161.76.100", None, kb).name == "Un servidor sin nombre conocido"
    d = classify_destination("95.161.76.100", None, kb, online={"org": None, "country": "RU"})
    assert d.name == "Un servidor sin nombre en Rusia" and d.kind == "unknown"
    named = classify_destination("95.161.76.100", None, kb, online={"org": "Hosting SA", "country": "RU"})
    assert named.kind == "named" and named.country == "Rusia"


def test_unlisted_domain_gets_site_name(kb):
    d = classify_destination("93.184.215.14", "www.tienda.example.co.uk", kb)
    assert d.name == "Sitio web example.co.uk"
    assert site_name("a.b.ejemplo.es") == "ejemplo.es"


def test_transport():
    assert classify_transport("tcp", 443).sealed is True
    assert classify_transport("udp", 443).sealed is True  # QUIC
    assert classify_transport("tcp", 80).sealed is False
    assert classify_transport("tcp", 4444).suspicious
    assert classify_transport("udp", 8801).purpose == "call"
    assert classify_transport("tcp", 31000).sealed is None
