from cartero.knowledge import match_suffix, parse_oui_file


def test_suffix_match_respects_label_boundaries():
    table = {"google.com": "G", "events.data.microsoft.com": "T", "microsoft.com": "M"}
    assert match_suffix("www.google.com", table) == "G"
    assert match_suffix("notgoogle.com", table) is None
    assert match_suffix("v10.events.data.microsoft.com.", table) == "T"  # el más específico gana
    assert match_suffix("WWW.Microsoft.com", table) == "M"


def test_domain_and_tracker_lookup(kb):
    assert kb.domain_info("audio-ak.spotifycdn.com").org == "Spotify"
    assert kb.domain_info("audio-ak.spotifycdn.com").country_name == "Suecia"
    assert kb.tracker_for("stats.g.doubleclick.net") == "Google (publicidad)"
    assert kb.tracker_for("www.google.com") is None


def test_ip_ranges(kb):
    assert kb.ip_info("142.250.184.14").org == "Google"
    assert kb.ip_info("2606:4700::6810:84e5").org == "Cloudflare"
    assert kb.ip_info("95.161.76.100") is None
    assert kb.ip_info("no-es-una-ip") is None


def test_process_names(kb):
    assert kb.process_info("chrome.exe").name == "Navegador Google Chrome"
    assert kb.process_info("svchost.exe").category == "system"
    assert kb.process_info("Discord Helper (Renderer)").name == "Discord"
    unknown = kb.process_info("updater_service.exe")
    assert not unknown.known


def test_oui_formats(tmp_path):
    ieee = tmp_path / "oui.txt"
    ieee.write_text("00-1B-63   (hex)\t\tApple, Inc.\n001B63     (base 16)\t\tApple, Inc.\n")
    assert parse_oui_file(ieee) == {"001B63": "Apple, Inc."}
    manuf = tmp_path / "manuf"
    manuf.write_text("# comentario\n00:1B:63\tApple\tApple, Inc.\n00:1B:C5:00:00:00/36\tX\tX\n")
    assert parse_oui_file(manuf) == {"001B63": "Apple, Inc."}
    nmap = tmp_path / "nmap-mac-prefixes"
    nmap.write_text("001B63 Apple Computer\n")
    assert parse_oui_file(nmap) == {"001B63": "Apple Computer"}
    csvf = tmp_path / "oui.csv"
    csvf.write_text('Registry,Assignment,Organization Name,Organization Address\nMA-L,001B63,"Apple, Inc.",x\n')
    assert parse_oui_file(csvf) == {"001B63": "Apple, Inc."}
