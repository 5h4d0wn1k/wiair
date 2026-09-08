"""Probe / client audit tests."""

import unittest

from wiair.probe_audit.analyzer import (
    build_probe_fixture, analyze_probe_requests, privacy_risk,
)


class TestProbeFixture(unittest.TestCase):
    def test_build_single(self):
        frames = build_probe_fixture("AA:BB:CC:DD:EE:FF", ["HomeNet"])
        self.assertEqual(len(frames), 1)

    def test_build_multiple(self):
        frames = build_probe_fixture("AA:BB:CC:DD:EE:FF",
                                     ["HomeNet", "CorpWifi", "FreeWiFi"])
        self.assertEqual(len(frames), 3)

    def test_build_empty(self):
        frames = build_probe_fixture("AA:BB:CC:DD:EE:FF", [])
        self.assertEqual(len(frames), 0)


class TestProbeAnalysis(unittest.TestCase):
    def test_single_client(self):
        frames = build_probe_fixture("AA:BB:CC:DD:EE:FF", ["HomeNet", "CorpWifi"])
        result = analyze_probe_requests(frames)
        self.assertEqual(result["total_probes"], 2)
        self.assertEqual(result["unique_clients"], 1)
        self.assertIn("aa:bb:cc:dd:ee:ff", result["clients"])

    def test_hidden_ssid_discovery(self):
        frames = build_probe_fixture("AA:BB:CC:DD:EE:FF", ["HiddenNet"])
        result = analyze_probe_requests(frames)
        self.assertIn("HiddenNet", result["hidden_ssids_discovered"])

    def test_multiple_clients(self):
        frames1 = build_probe_fixture("AA:BB:CC:DD:EE:FF", ["Net1"])
        frames2 = build_probe_fixture("11:22:33:44:55:66", ["Net2"])
        result = analyze_probe_requests(frames1 + frames2)
        self.assertEqual(result["unique_clients"], 2)

    def test_probe_count(self):
        frames = build_probe_fixture("AA:BB:CC:DD:EE:FF",
                                     ["Net1", "Net2", "Net3"])
        result = analyze_probe_requests(frames)
        client = result["clients"]["aa:bb:cc:dd:ee:ff"]
        self.assertEqual(client["probe_count"], 3)


class TestPrivacyRisk(unittest.TestCase):
    def test_high_risk(self):
        frames = build_probe_fixture("AA:BB:CC:DD:EE:FF",
                                     ["Net1", "Net2", "Net3", "Net4", "Net5"])
        analysis = analyze_probe_requests(frames)
        risk = privacy_risk(analysis)
        self.assertGreater(risk["risk_score"], 0)

    def test_no_probes_low_risk(self):
        analysis = {"total_probes": 0, "unique_clients": 0,
                    "hidden_ssids_discovered": [], "clients": {}}
        risk = privacy_risk(analysis)
        self.assertEqual(risk["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
