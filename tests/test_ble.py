"""BLE tests — CRC-24, PDU construction, de-anonymization, ATT parse."""

import unittest

from wiair.ble.ble import (
    crc24_ble, build_adv_ind, build_scan_req, BLEAdvPDU,
    de_anonymize_random_addr, parse_att_pdu,
    PDU_ADV_IND, PDU_SCAN_REQ,
)


class TestBLECRC24(unittest.TestCase):
    def test_known_vector(self):
        data = b'\x00' * 20
        crc = crc24_ble(data)
        self.assertIsInstance(crc, int)
        self.assertGreaterEqual(crc, 0)
        self.assertLessEqual(crc, 0xFFFFFF)

    def test_deterministic(self):
        data = b'\xAA\xBB\xCC\xDD\xEE'
        self.assertEqual(crc24_ble(data), crc24_ble(data))

    def test_different_data_different_crc(self):
        self.assertNotEqual(crc24_ble(b'\x00'), crc24_ble(b'\x01'))


class TestBLEAdvPDU(unittest.TestCase):
    def test_adv_ind_build(self):
        addr = b'\xAA\xBB\xCC\xDD\xEE\xFF'
        pdu = build_adv_ind(addr)
        raw = pdu.to_bytes()
        self.assertEqual(len(raw), 10)  # 1 type + 6 addr + 3 CRC
        self.assertEqual(raw[0] & 0x0F, PDU_ADV_IND)

    def test_adv_ind_with_data(self):
        addr = b'\xAA\xBB\xCC\xDD\xEE\xFF'
        adv_data = b'\x02\x01\x06'  # flags
        pdu = build_adv_ind(addr, adv_data)
        raw = pdu.to_bytes()
        self.assertGreater(len(raw), 10)

    def test_scan_req_build(self):
        scanner = b'\x11\x22\x33\x44\x55\x66'
        advertiser = b'\xAA\xBB\xCC\xDD\xEE\xFF'
        pdu = build_scan_req(scanner, advertiser)
        raw = pdu.to_bytes()
        self.assertEqual(len(raw), 16)  # 1 + 6 scanner + 6 advertiser + 3 CRC

    def test_adv_ind_roundtrip(self):
        addr = b'\xAA\xBB\xCC\xDD\xEE\xFF'
        pdu = build_adv_ind(addr)
        raw = pdu.to_bytes()
        parsed = BLEAdvPDU.from_bytes(raw)
        self.assertEqual(parsed.pdu_type, PDU_ADV_IND)
        self.assertEqual(parsed.adv_addr, addr)


class TestDeAnonymize(unittest.TestCase):
    def test_random_addr(self):
        # Random BLE address: bits [7:6] of the LAST byte = 11
        addr = bytes([0x23, 0x45, 0x67, 0x89, 0xAB, 0xC3])  # 0xC3 = 11000011
        result = de_anonymize_random_addr(addr)
        self.assertEqual(result["address_type"], "random")
        self.assertTrue(result["is_resolvable"])

    def test_public_addr(self):
        addr = b'\xAA\x23\x45\x67\x89\xAB'
        result = de_anonymize_random_addr(addr)
        self.assertIn(result["address_type"], ["public", "random"])
        self.assertIn("techniques", result)

    def test_adv_data_leak(self):
        result = de_anonymize_random_addr(b'\xC1\x23\x45\x67\x89\xAB',
                                           adv_data=b'\x02\x01\x06')
        self.assertTrue(result["adv_data_leak"])


class TestATTParse(unittest.TestCase):
    def test_error_opcode(self):
        data = bytes([0x01, 0x0A, 0x00, 0x01, 0x0A])
        result = parse_att_pdu(data)
        self.assertEqual(result["opcode"], 0x01)
        self.assertIn("error_code", result)

    def test_exchange_mtu(self):
        data = bytes([0x02, 0x17, 0x00])
        result = parse_att_pdu(data)
        self.assertEqual(result["opcode"], 0x02)
        self.assertEqual(result["client_mtu"], 23)

    def test_find_info_req(self):
        data = bytes([0x04, 0x01, 0x00, 0x10, 0x00])
        result = parse_att_pdu(data)
        self.assertEqual(result["attack_vector"], "service_enumeration")

    def test_read_req(self):
        data = bytes([0x0A, 0x01, 0x00])
        result = parse_att_pdu(data)
        self.assertEqual(result["opcode"], 0x0A)

    def test_empty(self):
        result = parse_att_pdu(b'')
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
