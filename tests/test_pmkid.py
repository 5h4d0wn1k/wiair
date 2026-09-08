"""PMKID / EAPOL pipeline tests."""

import os
import struct
import unittest

from wiair.pmkid.pipeline import (
    build_4way_pcap, parse_eapol_from_pcap, pipeline_summary,
    pmkid_to_hashcat, pmkid_to_hcx, extract_pmkid_from_key_data,
    build_eapol_m1, build_eapol_m2, build_eapol_m3, build_eapol_m4,
    write_eapol_pcap, ETHERTYPE_EAPOL,
)


class TestEAPOLBuild(unittest.TestCase):
    def test_m1_length(self):
        anonce = bytes(32)
        m1 = build_eapol_m1("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", anonce)
        # Ethernet header (14) + EAPOL body
        self.assertGreater(len(m1), 14)

    def test_m1_has_ethertype(self):
        anonce = bytes(32)
        m1 = build_eapol_m1("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", anonce)
        ethertype = struct.unpack(">H", m1[12:14])[0]
        self.assertEqual(ethertype, ETHERTYPE_EAPOL)


class TestPMKIDExtract(unittest.TestCase):
    def test_extract_from_key_data(self):
        pmkid = bytes(range(0x10, 0x20))
        # Build key data: key_index(1) + RSN KDE header(3) + KDE type(2) + PMKID(16)
        key_data = bytearray()
        key_data.append(0x00)  # key index
        key_data.extend(struct.pack(">BB", 1, 4))  # PMKID KDE ID + type
        key_data.extend(struct.pack(">BB", 0x01, 0x00))  # KDE ID
        key_data.extend(pmkid)
        extracted = extract_pmkid_from_key_data(bytes(key_data))
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted, pmkid)

    def test_no_pmkid_in_key_data(self):
        key_data = b'\x00\x01\x02\x03'
        extracted = extract_pmkid_from_key_data(key_data)
        self.assertIsNone(extracted)


class TestPCAPRoundtrip(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        ap_mac = "00:11:22:33:44:55"
        client_mac = "AA:BB:CC:DD:EE:FF"
        essid = "TestNet"
        pmkid = bytes(range(0x10, 0x20))
        path = build_4way_pcap(ap_mac, client_mac, essid, pmkid,
                               "/tmp/test_eapol_4way.pcap")
        self.assertTrue(os.path.exists(path))

        results = parse_eapol_from_pcap(path)
        self.assertEqual(len(results), 4)

        # M1 should have PMKID
        m1 = results[0]
        self.assertIn("pmkid", m1)
        self.assertEqual(m1["pmkid"], pmkid.hex())
        os.unlink(path)


class TestHashcatFormat(unittest.TestCase):
    def test_pmkid_hashcat(self):
        pmkid = bytes(range(0x10, 0x20))
        line = pmkid_to_hashcat(pmkid, "00:11:22:33:44:55",
                                "AA:BB:CC:DD:EE:FF", "TestNet")
        self.assertIn("WPA*02*", line)
        self.assertIn("001122334455", line)
        self.assertIn("AABBCCDDEEFF", line)
        self.assertIn("TestNet", line)

    def test_pmkid_hcx(self):
        pmkid = bytes(range(0x10, 0x20))
        line = pmkid_to_hcx(pmkid, "00:11:22:33:44:55",
                            "AA:BB:CC:DD:EE:FF", "TestNet")
        self.assertIn("PMKID*", line)
        self.assertIn("TestNet", line)


class TestPipeline(unittest.TestCase):
    def test_full_pipeline(self):
        ap_mac = "00:11:22:33:44:55"
        client_mac = "AA:BB:CC:DD:EE:FF"
        essid = "PipelineTest"
        pmkid = bytes(range(0x10, 0x20))
        result = pipeline_summary(ap_mac, client_mac, essid, pmkid)
        self.assertTrue(result["ready_for_crack"])
        self.assertEqual(result["pmkid_extracted"], pmkid.hex())
        self.assertIn("hashcat_line", result)
        self.assertIn("hcx_line", result)
        # Cleanup
        if os.path.exists(result["pcap_path"]):
            os.unlink(result["pcap_path"])


if __name__ == "__main__":
    unittest.main()
