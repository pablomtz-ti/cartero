from cartero.wifi import describe_device, is_private_mac, parse_neighbors, pretty_hostname

LINUX = """192.168.1.1 dev wlp2s0 lladdr e4:ab:89:12:34:56 REACHABLE
192.168.1.20 dev wlp2s0 lladdr f2:6d:11:22:33:44 STALE
192.168.1.99 dev wlp2s0  FAILED
"""
MAC = """? (192.168.1.1) at e4:ab:89:12:34:56 on en0 ifscope [ethernet]
? (192.168.1.21) at 8c:79:f5:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""
WINDOWS = """Interface: 192.168.1.34 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           e4-ab-89-12-34-56     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
"""


def test_parse_all_platforms():
    assert parse_neighbors(LINUX) == [("192.168.1.1", "e4:ab:89:12:34:56"), ("192.168.1.20", "f2:6d:11:22:33:44")]
    assert parse_neighbors(MAC) == [("192.168.1.1", "e4:ab:89:12:34:56"), ("192.168.1.21", "8c:79:f5:01:02:03")]
    assert parse_neighbors(WINDOWS) == [("192.168.1.1", "e4:ab:89:12:34:56")]


def test_private_mac():
    assert is_private_mac("f2:6d:11:22:33:44")
    assert not is_private_mac("3c:58:c2:aa:bb:cc")


def test_pretty_hostname():
    assert pretty_hostname("iPhone-de-Juan.local") == "iPhone de Juan"
    assert pretty_hostname("android-a1b2c3d4e5f6.lan") == "Móvil Android"
    assert pretty_hostname("192-168-1-20") is None
    assert pretty_hostname(None) is None


def test_describe_device():
    kw = {"gateway": "192.168.1.1", "my_ips": {"192.168.1.34"}}
    assert describe_device("192.168.1.1", "e4:ab:89:12:34:56", None, None, **kw).kind == "router"
    assert describe_device("192.168.1.34", "3c:58:c2:aa:bb:cc", None, None, **kw).kind == "me"
    tv = describe_device("192.168.1.21", "8c:79:f5:01:02:03", "Samsung Electronics", "Samsung-TV", **kw)
    assert (tv.name, tv.kind) == ("Samsung TV", "tv")
    phone = describe_device("192.168.1.20", "f2:6d:11:22:33:44", None, None, **kw)
    assert phone.name == "Móvil o tablet con dirección privada" and phone.private_mac
    unknown = describe_device("192.168.1.66", "00:11:22:33:44:55", None, None, **kw)
    assert unknown.name == "Dispositivo desconocido" and unknown.note
