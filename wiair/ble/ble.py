"""BLE side — ADV_IND/SCAN_REQ PDU bytes (CRC-24), MAC de-anonymization study.

CRC-24 for BLE, ADV_IND/SCAN_REQ PDU construction,
BLE MAC de-anonymization on fixtures, GATT ATT PDU parse.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# BLE CRC-24 (polynomial 0x00065B — reflected 0xEDB88320 with 24-bit mask)
# ---------------------------------------------------------------------------

_BLE_CRC_TABLE: list[int] = []

def _build_ble_crc_table() -> list[int]:
    tbl = []
    poly = 0x00065B
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        tbl.append(crc & 0xFFFFFF)
    return tbl

_BLE_CRC_TABLE = _build_ble_crc_table()


def crc24_ble(data: bytes) -> int:
    """Compute BLE CRC-24 over data. Returns 24-bit value."""
    crc = 0x555555  # BLE CRC init value
    for b in data:
        crc = _BLE_CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFF


# ---------------------------------------------------------------------------
# BLE PDU types
# ---------------------------------------------------------------------------

PDU_ADV_IND = 0x00
PDU_ADV_DIRECT_IND = 0x01
PDU_ADV_NONCONN_IND = 0x02
PDU_SCAN_REQ = 0x03
PDU_SCAN_RSP = 0x04
PDU_CONNECT_IND = 0x05
PDU_ADV_SCAN_IND = 0x06
PDU_SCAN_RSP_TYPE = PDU_SCAN_RSP


@dataclass
class BLEAdvPDU:
    pdu_type: int
    tx_add: bool = False  # 0=public, 1=random
    rx_add: bool = False
    adv_addr: bytes = field(default_factory=lambda: b'\x00\x00\x00\x00\x00\x00')
    adv_data: bytes = b''
    crc: int = 0

    def to_bytes(self, include_crc: bool = True) -> bytes:
        """Build raw BLE PDU with optional CRC."""
        # PDU header: preamble(1) + access address(4) = skipped here
        # We build the PDU body (after access address)
        pdu_body = bytearray()
        pdu_body.append(self.pdu_type | (0x01 << 6) if self.tx_add else self.pdu_type)
        pdu_body.extend(self.adv_addr)
        if self.adv_data:
            pdu_body.extend(self.adv_data)
        if include_crc:
            self.crc = crc24_ble(bytes(pdu_body))
            pdu_body.extend(struct.pack("<I", self.crc)[:3])
        return bytes(pdu_body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BLEAdvPDU":
        if len(data) < 7:
            raise ValueError("PDU too short")
        pdu_type = data[0] & 0x0F
        tx_add = bool(data[0] & (1 << 6))
        rx_add = bool(data[0] & (1 << 7))
        adv_addr = data[1:7]
        adv_data = data[7:-3] if len(data) > 10 else b''
        return cls(pdu_type=pdu_type, tx_add=tx_add, rx_add=rx_add,
                   adv_addr=adv_addr, adv_data=adv_data)


def build_adv_ind(addr: bytes, adv_data: bytes = b'',
                  tx_add: bool = False) -> BLEAdvPDU:
    """Build ADV_IND PDU."""
    return BLEAdvPDU(
        pdu_type=PDU_ADV_IND,
        tx_add=tx_add,
        adv_addr=addr[:6].ljust(6, b'\x00'),
        adv_data=adv_data,
    )


def build_scan_req(scanner_addr: bytes, advertiser_addr: bytes,
                   tx_add: bool = False, rx_add: bool = False) -> BLEAdvPDU:
    """Build SCAN_REQ PDU."""
    pdu = BLEAdvPDU(
        pdu_type=PDU_SCAN_REQ,
        tx_add=tx_add,
        rx_add=rx_add,
        adv_addr=scanner_addr[:6].ljust(6, b'\x00'),
    )
    pdu.adv_data = advertiser_addr[:6].ljust(6, b'\x00')
    return pdu


# ---------------------------------------------------------------------------
# BLE MAC de-anonymization study
# ---------------------------------------------------------------------------

def de_anonymize_random_addr(random_addr: bytes,
                             adv_data: bytes = b'') -> dict:
    """Study stable/random BLE address de-anonymization.

    Techniques:
    1. Resolve hash: if hash bits visible, reverse with known identity
    2. Cross-reference: link random addr to identity via advertisement data
    3. Temporal: track addr rotation to build stable identity
    """
    addr_type = "random" if (random_addr[6-1] >> 6) == 0b11 else "public"

    return {
        "address_hex": random_addr.hex(),
        "address_type": addr_type,
        "is_resolvable": (addr_type == "random" and len(random_addr) == 6),
        "identity_notes": (
            "Random address cannot be resolved without IRK. "
            "Cross-reference advertisement data or temporal patterns for identity."
        ),
        "adv_data_leak": len(adv_data) > 0,
        "techniques": [
            "IRK resolution with known identity key",
            "Advertisement data fingerprinting",
            "Temporal address rotation pattern analysis",
            "Service UUID correlation",
        ],
    }


# ---------------------------------------------------------------------------
# GATT ATT PDU parse
# ---------------------------------------------------------------------------

ATT_OP_ERROR = 0x01
ATT_OP_EXCHANGE_MTU = 0x02
ATT_OP_FIND_INFO_REQ = 0x04
ATT_OP_FIND_INFO_RSP = 0x05
ATT_OP_READ_BY_TYPE_REQ = 0x08
ATT_OP_READ_BY_TYPE_RSP = 0x09
ATT_OP_READ_REQ = 0x0A
ATT_OP_READ_RSP = 0x0B
ATT_OP_WRITE_REQ = 0x12
ATT_OP_WRITE_RSP = 0x13
ATT_OP_HANDLE_NFY = 0x1B
ATT_OP_HANDLE_IND = 0x1D


def parse_att_pdu(data: bytes) -> dict:
    """Parse a single ATT PDU for service discovery attack simulation."""
    if not data:
        return {"error": "empty"}

    opcode = data[0]
    result = {"opcode": opcode, "opcode_hex": f"0x{opcode:02x}"}

    if opcode == ATT_OP_ERROR:
        if len(data) >= 5:
            result["request_opcode"] = data[1]
            result["handle"] = struct.unpack("<H", data[2:4])[0]
            result["error_code"] = data[4]
            result["description"] = _att_error_desc(data[4])
    elif opcode == ATT_OP_EXCHANGE_MTU:
        if len(data) >= 3:
            result["client_mtu"] = struct.unpack("<H", data[1:3])[0]
    elif opcode == ATT_OP_FIND_INFO_REQ:
        if len(data) >= 5:
            result["handle_start"] = struct.unpack("<H", data[1:3])[0]
            result["handle_end"] = struct.unpack("<H", data[3:5])[0]
            result["attack_vector"] = "service_enumeration"
    elif opcode == ATT_OP_FIND_INFO_RSP:
        if len(data) >= 2:
            result["format"] = data[1]  # 1=16-bit, 2=128-bit
            result["attributes"] = _parse_find_info_rsp(data[2:])
    elif opcode == ATT_OP_READ_BY_TYPE_REQ:
        if len(data) >= 7:
            result["handle_start"] = struct.unpack("<H", data[1:3])[0]
            result["handle_end"] = struct.unpack("<H", data[3:5])[0]
            result["uuid"] = data[5:7].hex()
            result["attack_vector"] = "characteristic_enumeration"
    elif opcode == ATT_OP_READ_RSP:
        result["value_hex"] = data[1:].hex() if len(data) > 1 else ""
        result["attack_vector"] = "attribute_value_extraction"
    elif opcode == ATT_OP_WRITE_REQ:
        if len(data) >= 3:
            result["handle"] = struct.unpack("<H", data[1:3])[0]
            result["value_hex"] = data[3:].hex()
            result["attack_vector"] = "attribute_manipulation"
    elif opcode in (ATT_OP_HANDLE_NFY, ATT_OP_HANDLE_IND):
        if len(data) >= 3:
            result["handle"] = struct.unpack("<H", data[1:3])[0]
            result["value_hex"] = data[3:].hex()

    return result


def _att_error_desc(code: int) -> str:
    errors = {
        0x01: "Invalid Handle",
        0x02: "Read Not Permitted",
        0x03: "Write Not Permitted",
        0x05: "Authentication Required",
        0x06: "Request Not Supported",
        0x07: "Invalid Offset",
        0x0A: "Attribute Not Found",
        0x0D: "Invalid Attribute Value Length",
    }
    return errors.get(code, f"Unknown ({code:#04x})")


def _parse_find_info_rsp(data: bytes) -> list[dict]:
    attrs = []
    i = 0
    while i + 4 <= len(data):
        handle = struct.unpack("<H", data[i:i+2])[0]
        uuid = data[i+2:i+4]
        attrs.append({"handle": handle, "uuid_hex": uuid.hex()})
        i += 4
    return attrs
