import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.snort_monitor import SnortMonitor, parse_fast_alert
from modules.soar import SOAREngine


LINE = ("07/21-17:01:02.123456  [**] [1:2100365:8] ET SCAN Test Signature "
        "[**] [Classification: Attempted Information Leak] [Priority: 1] "
        "{TCP} 203.0.113.50:45678 -> 192.168.1.10:22")


class Socket:
    def __init__(self): self.events = []
    def emit(self, name, data): self.events.append((name, data))


class Detector:
    def __init__(self): self.alerts = []
    def report_alert(self, *args): self.alerts.append(args)


def test_parse_snort_fast_alert():
    event = parse_fast_alert(LINE)
    assert event["sid"] == 2100365
    assert event["priority"] == 1
    assert event["src_ip"] == "203.0.113.50"
    assert event["dst_port"] == 22


def test_snort_event_enters_detector_without_direct_block():
    socket, detector = Socket(), Detector()
    monitor = SnortMonitor(socket, {"SNORT_ENABLED": "True"}, detector)
    event = monitor.ingest_line(LINE)
    assert event and monitor.stats["alerts"] == 1
    alert = detector.alerts[0]
    assert alert[0] == "SNORT_ALERT" and alert[1] == "CRITICAL"
    assert alert[-1]["evidence"] == ["snort_signature"]


def test_invalid_snort_line_is_ignored():
    monitor = SnortMonitor(Socket(), {}, Detector())
    assert monitor.ingest_line("not an alert") is None
    assert monitor.stats["invalid"] == 1


def test_block_evidence_requires_independent_sources():
    alert = {"details": {"source": "snort", "evidence": ["snort_signature"],
                         "ip_reputation": {"score": 95, "source": "abuseipdb"}}}
    assert SOAREngine._block_evidence(alert) == ["abuseipdb_90", "snort_signature"]


def test_demo_reputation_is_not_block_evidence():
    alert = {"details": {"source": "snort",
                         "ip_reputation": {"score": 99, "source": "demo"}}}
    assert SOAREngine._block_evidence(alert) == ["snort_signature"]


def test_auto_block_gate_requires_95_and_two_sources(tmp_path):
    soar = SOAREngine(Socket(), {
        "SOAR_MIN_BLOCK_CONFIDENCE": 95,
        "SOAR_REQUIRE_CORROBORATION": True,
    }, blocklist_path=str(tmp_path / "blocklist.txt"))
    base = {"confidence": .99, "details": {"evidence": ["snort_signature"]}}
    assert not soar._eligible_auto_block(base)
    base["details"]["evidence"].append("threat_intel_ioc")
    assert soar._eligible_auto_block(base)
    base["details"]["demo"] = True
    assert not soar._eligible_auto_block(base)
