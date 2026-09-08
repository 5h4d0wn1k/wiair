"""Evil twin tests."""

import os
import struct
import unittest

from wiair.eviltwin.twin import evil_twin_flow, generate_portal_html, write_pcap


class TestEvilTwin(unittest.TestCase):
    def test_flow_creates_pcap(self):
        result = evil_twin_flow(
            ssid="EvilTwinTest",
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
            client="11:22:33:44:55:66",
            output_path="/tmp/test_eviltwin.pcap",
        )
        self.assertEqual(result["frames_count"], 3)
        self.assertTrue(os.path.exists(result["pcap_path"]))
        self.assertEqual(result["ssid"], "EvilTwinTest")
        os.unlink(result["pcap_path"])

    def test_pcap_format(self):
        path = "/tmp/test_eviltwin_format.pcap"
        frames = [b'\x00' * 28, b'\x01' * 32]
        write_pcap(frames, path)
        with open(path, "rb") as f:
            hdr = f.read(24)
            magic = struct.unpack("<I", hdr[:4])[0]
            self.assertEqual(magic, 0xa1b2c3d4)
        os.unlink(path)

    def test_portal_html(self):
        path = "/tmp/test_portal.html"
        result = generate_portal_html("TestSSID", path)
        self.assertTrue(os.path.exists(result))
        with open(result) as f:
            html = f.read()
        self.assertIn("TestSSID", html)
        self.assertIn("<form", html)
        os.unlink(result)

    def test_flow_metadata(self):
        result = evil_twin_flow(
            ssid="Meta",
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
            client="11:22:33:44:55:66",
            output_path="/tmp/test_meta.pcap",
        )
        self.assertIn("flow", result)
        self.assertEqual(result["flow"], ["beacon", "probe_response", "auth"])
        os.unlink(result["pcap_path"])


if __name__ == "__main__":
    unittest.main()
