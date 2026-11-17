from cartero.behavior import human_bytes, human_duration, join_es, periodic_interval, traffic_pattern


def test_periodic_detects_heartbeat():
    assert round(periodic_interval([0, 10, 20.2, 29.9, 40, 50.1])) == 10


def test_periodic_rejects_irregular_and_short():
    assert periodic_interval([0, 3, 15, 16, 40, 41]) is None
    assert periodic_interval([0, 10, 20]) is None
    assert periodic_interval([0, 0.6, 1.2, 1.8, 2.4]) is None  # demasiado rápido: es tráfico normal


def test_traffic_pattern():
    assert traffic_pattern(12_000, 15_000_000) == "consuming"
    assert traffic_pattern(5_000_000, 100_000) == "uploading"
    assert traffic_pattern(2_000_000, 2_500_000) == "both"
    assert traffic_pattern(100, 900) is None


def test_human_formatting():
    assert human_bytes(512) == "512 bytes"
    assert human_bytes(12 * 1024) == "12 KB"
    assert human_bytes(int(1.5 * 1024 * 1024)) == "1,5 MB"
    assert human_duration(1) == "1 segundo"
    assert human_duration(125) == "2 minutos"
    assert join_es(["a", "b", "c"]) == "a, b y c"
