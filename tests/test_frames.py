"""Frame library tests — byte-exact roundtrips + FCS verification."""

import struct
import unittest

from wiair.frames.ieee80211 import (
    FrameControl, Dot11Frame, build_beacon, parse_beacon,
    build_probe_req, parse_probe_req, build_probe_resp, parse_probe_resp,
    build_auth, parse_auth, build_deauth, parse_deauth,
    build_association_req, parse_association_req,
    build_association_resp, parse_association_resp,
    crc32_80211, verify_fcs, encode_ssid, encode_supported_rates,
    encode_country, encode_rsn, _parse_ies, mac_bytes, mac_to_bytes,
    FRAME_TYPE_MGMT, SUBTYPE_BEACON, SUBTYPE_DEAUTH, REASON_CODES,
)


class TestCRC32(unittest.TestCase):
    def test_known_vector(self):
        data = b'\x00' * 100
        crc = crc32_80211(data)
        self.assertIsInstance(crc, int)
        self.assertGreater(crc, 0)

    def test_fcs_roundtrip(self):
        raw = b'\x00\x08\x00\x00\xff\xff\xff\xff\xff\xff' + b'\x00' * 14
        fcs = crc32_80211(raw)
        frame_with_fcs = raw + struct.pack("<I", fcs)
        self.assertTrue(verify_fcs(frame_with_fcs))

    def test_fcs_corrupt(self):
        raw = b'\x00\x08\x00\x00\xff\xff\xff\xff\xff\xff' + b'\x00' * 14
        fcs = crc32_80211(raw)
        frame_with_fcs = raw + struct.pack("<I", fcs ^ 0xFF)
        self.assertFalse(verify_fcs(frame_with_fcs))

    def test_fcs_too_short(self):
        self.assertFalse(verify_fcs(b'\x00\x01'))


class TestFrameControl(unittest.TestCase):
    def test_beacon_fc(self):
        fc = FrameControl(frame_type=0, frame_subtype=8)
        raw = fc.to_bytes()
        parsed = FrameControl.from_bytes(raw)
        self.assertEqual(parsed.frame_type, 0)
        self.assertEqual(parsed.frame_subtype, 8)
        self.assertFalse(parsed.protected)

    def test_deauth_fc(self):
        fc = FrameControl(frame_type=0, frame_subtype=12)
        raw = fc.to_bytes()
        parsed = FrameControl.from_bytes(raw)
        self.assertEqual(parsed.frame_subtype, 12)

    def test_fc_bits(self):
        fc = FrameControl(to_ds=True, from_ds=True, retry=True, order=True)
        raw = fc.to_bytes()
        parsed = FrameControl.from_bytes(raw)
        self.assertTrue(parsed.to_ds)
        self.assertTrue(parsed.from_ds)
        self.assertTrue(parsed.retry)
        self.assertTrue(parsed.order)


class TestBeacon(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        ssid = "TestNet"
        bssid = "00:11:22:33:44:55"
        src = "AA:BB:CC:DD:EE:FF"
        beacon = build_beacon(ssid=ssid, bssid=bssid, src=src, seq_num=42)
        raw = beacon.to_bytes()
        parsed = parse_beacon(raw)
        self.assertEqual(parsed["ssid"], ssid)
        self.assertEqual(parsed["bssid"], bssid)
        self.assertEqual(parsed["src"].lower(), src.lower())
        self.assertEqual(parsed["sequence"], 42)
        self.assertTrue(verify_fcs(raw))

    def test_ssid_encoding(self):
        ie = encode_ssid("Hello")
        self.assertEqual(ie[0], 0)  # IE ID
        self.assertEqual(ie[1], 5)  # length
        self.assertEqual(ie[2:7], b"Hello")

    def test_empty_ssid(self):
        ie = encode_ssid("")
        self.assertEqual(ie[0], 0)
        self.assertEqual(ie[1], 0)

    def test_unicode_ssid(self):
        ie = encode_ssid("WiFi🔒")
        self.assertEqual(ie[0], 0)
        self.assertGreater(ie[1], 0)

    def test_country_ie(self):
        ie = encode_country("US")
        self.assertEqual(ie[0], 7)  # IE ID
        self.assertEqual(ie[2:4], b"US")

    def test_rsn_ie(self):
        ie = encode_rsn(psk=True)
        self.assertEqual(ie[0], 48)  # RSN IE ID
        self.assertGreater(len(ie), 10)

    def test_rsn_transition_dual_akm(self):
        ie = encode_rsn(akms=[0x02, 0x08])  # PSK + SAE = WPA2/WPA3 transition
        self.assertEqual(ie[0], 48)
        body = ie[2:]
        # version(2) + group(4) + pairwise_count(2) + pairwise(4) + akm_count(2)
        akm_count = struct.unpack("<H", body[12:14])[0]
        self.assertEqual(akm_count, 2)
        akms = body[14:22]
        self.assertEqual(akms[3], 0x02)  # PSK
        self.assertEqual(akms[7], 0x08)  # SAE

    def test_beacon_with_all_ies(self):
        beacon = build_beacon("Test", "00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF",
                              rates=[1.0, 2.0], country="DE", rsn=True)
        raw = beacon.to_bytes()
        parsed = parse_beacon(raw)
        self.assertEqual(parsed["ssid"], "Test")
        self.assertIn(48, parsed["ies"])  # RSN IE present

    def test_beacon_no_rsn(self):
        beacon = build_beacon("Open", "00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF",
                              rsn=False)
        raw = beacon.to_bytes()
        parsed = parse_beacon(raw)
        self.assertNotIn(48, parsed["ies"])


class TestProbeReq(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        probe = build_probe_req(ssid="ProbeTest", src="AA:BB:CC:DD:EE:FF", seq_num=7)
        raw = probe.to_bytes()
        parsed = parse_probe_req(raw)
        self.assertEqual(parsed["ssid"], "ProbeTest")
        self.assertEqual(parsed["src"].lower(), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed["sequence"], 7)

    def test_hidden_ssid(self):
        probe = build_probe_req(ssid="", src="AA:BB:CC:DD:EE:FF")
        raw = probe.to_bytes()
        parsed = parse_probe_req(raw)
        self.assertEqual(parsed["ssid"], "")

    def test_long_ssid(self):
        long_ssid = "A" * 32
        probe = build_probe_req(ssid=long_ssid, src="AA:BB:CC:DD:EE:FF")
        raw = probe.to_bytes()
        parsed = parse_probe_req(raw)
        self.assertEqual(parsed["ssid"], long_ssid)


class TestProbeResp(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        resp = build_probe_resp(ssid="RespTest", bssid="00:11:22:33:44:55",
                                src="AA:BB:CC:DD:EE:FF",
                                dst="11:22:33:44:55:66", seq_num=5)
        raw = resp.to_bytes()
        parsed = parse_probe_resp(raw)
        self.assertEqual(parsed["ssid"], "RespTest")
        self.assertEqual(parsed["bssid"], "00:11:22:33:44:55")
        self.assertEqual(parsed["dst"], "11:22:33:44:55:66")
        self.assertEqual(parsed["sequence"], 5)


class TestAuth(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        auth = build_auth(bssid="00:11:22:33:44:55",
                          src="AA:BB:CC:DD:EE:FF",
                          dst="11:22:33:44:55:66",
                          seq_num=3)
        raw = auth.to_bytes()
        parsed = parse_auth(raw)
        self.assertEqual(parsed["type"], "auth")
        self.assertEqual(parsed["auth_algo"], 0)
        self.assertEqual(parsed["auth_seq"], 1)
        self.assertEqual(parsed["status"], 0)

    def test_sae_auth(self):
        auth = build_auth(bssid="00:11:22:33:44:55",
                          src="AA:BB:CC:DD:EE:FF",
                          dst="11:22:33:44:55:66",
                          auth_algo=1, auth_seq=1, status=0)
        raw = auth.to_bytes()
        parsed = parse_auth(raw)
        self.assertEqual(parsed["auth_algo"], 1)
        self.assertEqual(parsed["auth_seq"], 1)


class TestDeauth(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        for reason in range(1, 14):
            deauth = build_deauth(bssid="00:11:22:33:44:55",
                                  src="AA:BB:CC:DD:EE:FF",
                                  dst="11:22:33:44:55:66",
                                  reason=reason, seq_num=reason)
            raw = deauth.to_bytes()
            parsed = parse_deauth(raw)
            self.assertEqual(parsed["reason"], reason)
            self.assertEqual(parsed["sequence"], reason)
            self.assertIn(reason, REASON_CODES)

    def test_deauth_len(self):
        deauth = build_deauth(bssid="00:11:22:33:44:55",
                              src="AA:BB:CC:DD:EE:FF",
                              dst="ff:ff:ff:ff:ff:ff")
        raw = deauth.to_bytes()
        self.assertEqual(len(raw), 30)  # 24 header + 2 reason + 4 FCS


class TestAssociation(unittest.TestCase):
    def test_assoc_req_roundtrip(self):
        req = build_association_req(ssid="AssoTest", bssid="00:11:22:33:44:55",
                                    src="AA:BB:CC:DD:EE:FF")
        raw = req.to_bytes()
        parsed = parse_association_req(raw)
        self.assertEqual(parsed["ssid"], "AssoTest")
        self.assertEqual(parsed["bssid"], "00:11:22:33:44:55")

    def test_assoc_resp_roundtrip(self):
        resp = build_association_resp(bssid="00:11:22:33:44:55",
                                      src="AA:BB:CC:DD:EE:FF",
                                      dst="11:22:33:44:55:66")
        raw = resp.to_bytes()
        parsed = parse_association_resp(raw)
        self.assertEqual(parsed["status"], 0)
        self.assertEqual(parsed["aid"], 1)


class TestMACHelpers(unittest.TestCase):
    def test_mac_bytes(self):
        self.assertEqual(mac_bytes(b'\x00\x11\x22\x33\x44\x55'), "00:11:22:33:44:55")

    def test_mac_to_bytes(self):
        self.assertEqual(mac_to_bytes("00:11:22:33:44:55"), b'\x00\x11\x22\x33\x44\x55')


class TestSequenceNumbering(unittest.TestCase):
    def test_seq_num(self):
        f = Dot11Frame(fc=FrameControl(frame_type=0, frame_subtype=8))
        f.seq_num = 0x123
        self.assertEqual(f.seq_num, 0x123)
        f.seq_num = 0xFFF
        self.assertEqual(f.seq_num, 0xFFF)

    def test_frag_num(self):
        f = Dot11Frame(fc=FrameControl(frame_type=0, frame_subtype=8))
        f.seq_ctrl = 0x05  # frag 5
        self.assertEqual(f.frag_num, 5)


if __name__ == "__main__":
    unittest.main()
