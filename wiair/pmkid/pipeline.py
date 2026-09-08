"""PMKID / EAPOL 4-way handshake pipeline.

Parse synthetic .pcap with EAPOL 4-way fixture (M1..M4),
extract PMKID from M1, produce hashcat 22000-format + hcxpcapngtool-style output.
"""

import struct
import os
from typing import Optional


# ---------------------------------------------------------------------------
# EAPOL / Key Data constants
# ---------------------------------------------------------------------------

ETHERTYPE_EAPOL = 0x888E
EAPOL_VERSION = 3

# Key descriptor type
KEYDescriptorType_EAPOL = 2

# Key Information flags
KEYINFOKeyType        = 0x0007  # bits 0-2: type (0=group, 1=pairwise, 2=pmkSA)
KEYINFOKeyMIC         = 0x0080  # bit 7: MIC present
KEYINFOSecure         = 0x0100  # bit 8: Secure
KEYINFOError          = 0x0200  # bit 9: Error
KEYINFORequest        = 0x0400  # bit 10: Request
KEYINFOEncKeyData     = 0x1000  # bit 12: Encrypted Key Data


def _build_key_info(key_type: int = 1, mic: bool = False, secure: bool = False,
                    error: bool = False, request: bool = False,
                    enc_key_data: bool = False) -> int:
    val = key_type & 0x07
    if mic:
        val |= KEYINFOKeyMIC
    if secure:
        val |= KEYINFOSecure
    if error:
        val |= KEYINFOError
    if request:
        val |= KEYINFORequest
    if enc_key_data:
        val |= KEYINFOEncKeyData
    return val


# ---------------------------------------------------------------------------
# PMKID handling
# ---------------------------------------------------------------------------

PMKID_KDE_TYPE = 0x04  # RSN Key Data
PMKID_KDE_ID = 1       # PMKID KDE identifier


def extract_pmkid_from_key_data(key_data: bytes) -> Optional[bytes]:
    """Extract PMKID (16 bytes) from EAPOL key data field.

    Uses RSN KDE format:
      Element ID (1) + Length (1) + Type (1) + PMKID KDE ID (1) + PMKID (16)
    where Element ID = 0xdd (vendor) for WPA, or we search for a 16-byte
    block preceded by KDE marker 0x01, 0x00 (PMKID KDE).
    """
    # Strategy 1: look for RSN PMKID KDE (type 0x01, ID 0x00)
    # Format: [eid=0xdd][len][0x00 0x0f 0xac][type=1][0x01 0x00][pmkid=16]
    i = 0
    while i + 4 < len(key_data):
        # Check for KDE type 1 (PMKID) at offset
        if i + 22 <= len(key_data):
            if key_data[i] == 0xdd and key_data[i+2:i+5] == b'\x00\x0f\xac':
                ktype = key_data[i+5]
                if ktype == 1 and key_data[i+6:i+8] == b'\x01\x00':
                    pmkid = key_data[i+8:i+24]
                    if len(pmkid) == 16:
                        return pmkid
        # Strategy 2: raw PMKID marker (for synthetic fixtures)
        if key_data[i:i+2] == b'\x01\x00' and i + 18 <= len(key_data):
            candidate = key_data[i+2:i+18]
            if len(candidate) == 16:
                return candidate
        i += 1
    return None


def pmkid_to_hashcat(pmkid: bytes, mac_ap: str, mac_client: str,
                     essid: str) -> str:
    """Format PMKID as hashcat mode 22000 hash line."""
    return (
        f"WPA*02*{pmkid.hex()}"
        f"*{mac_ap.replace(':', '')}"
        f"*{mac_client.replace(':', '')}"
        f"**"
        f"*{essid}"
    )


def pmkid_to_hcx(pmkid: bytes, mac_ap: str, mac_client: str,
                  essid: str) -> str:
    """Format PMKID in hcxpcapngtool-style output."""
    return (
        f"PMKID*{pmkid.hex()}"
        f"*{mac_ap.replace(':', '')}"
        f"*{mac_client.replace(':', '')}"
        f"*{essid}"
    )


# ---------------------------------------------------------------------------
# EAPOL 4-way fixture builder
# ---------------------------------------------------------------------------

def build_eapol_m1(ap_mac: str, client_mac: str, anonce: bytes,
                   key_data: bytes = b'') -> bytes:
    """Build EAPOL Message 1 of 4-way handshake (simplified)."""
    eapol_hdr = struct.pack(">BBH",
                            EAPOL_VERSION,
                            3,  # EAPOL-Key
                            0)  # body length placeholder
    key_info = _build_key_info(key_type=1, error=False, request=False)
    key_data_len = len(key_data)
    key_payload = struct.pack(">H", key_info)
    key_payload += struct.pack(">I", 0)  # replay counter
    key_payload += anonce  # 32 bytes
    key_payload += b'\x00' * 16  # key MIC placeholder
    key_payload += struct.pack(">H", key_data_len)  # key data length
    key_payload += key_data

    body = eapol_hdr + key_payload
    # fix body length: bytes 2-3 of body = EAPOL body length
    body = body[:2] + struct.pack(">H", len(key_payload)) + body[4:]

    # Ethernet frame (no FCS for pcap)
    eth = bytes.fromhex(ap_mac.replace(':', ''))
    eth += bytes.fromhex(client_mac.replace(':', ''))
    eth += struct.pack(">H", ETHERTYPE_EAPOL)
    return eth + body


def build_eapol_m2(client_mac: str, ap_mac: str, snonce: bytes) -> bytes:
    """Build EAPOL Message 2."""
    eapol_hdr = struct.pack(">BBH", EAPOL_VERSION, 3, 0)
    key_info = _build_key_info(key_type=1, mic=True, request=False)
    key_payload = struct.pack(">H", key_info)
    key_payload += struct.pack(">I", 1)  # replay counter
    key_payload += snonce  # 32 bytes
    key_payload += b'\x00' * 16  # MIC
    key_payload += struct.pack(">H", 0)
    body = eapol_hdr + key_payload
    body = body[:1] + struct.pack(">BB", body[1], body[2]) + struct.pack(">H", len(key_payload))

    eth = bytes.fromhex(client_mac.replace(':', ''))
    eth += bytes.fromhex(ap_mac.replace(':', ''))
    eth += struct.pack(">H", ETHERTYPE_EAPOL)
    return eth + body


def build_eapol_m3(ap_mac: str, client_mac: str, anonce: bytes) -> bytes:
    """Build EAPOL Message 3."""
    eapol_hdr = struct.pack(">BBH", EAPOL_VERSION, 3, 0)
    key_info = _build_key_info(key_type=1, mic=True, secure=True)
    key_payload = struct.pack(">H", key_info)
    key_payload += struct.pack(">I", 2)  # replay counter
    key_payload += anonce
    key_payload += b'\x00' * 16  # MIC
    key_payload += struct.pack(">H", 0)
    body = eapol_hdr + key_payload
    body = body[:1] + struct.pack(">BB", body[1], body[2]) + struct.pack(">H", len(key_payload))

    eth = bytes.fromhex(ap_mac.replace(':', ''))
    eth += bytes.fromhex(client_mac.replace(':', ''))
    eth += struct.pack(">H", ETHERTYPE_EAPOL)
    return eth + body


def build_eapol_m4(client_mac: str, ap_mac: str) -> bytes:
    """Build EAPOL Message 4 (empty key data)."""
    eapol_hdr = struct.pack(">BBH", EAPOL_VERSION, 3, 0)
    key_info = _build_key_info(key_type=1, secure=True)
    key_payload = struct.pack(">H", key_info)
    key_payload += struct.pack(">I", 2)  # replay counter
    key_payload += b'\x00' * 32  # SNonce placeholder
    key_payload += b'\x00' * 16  # MIC
    key_payload += struct.pack(">H", 0)
    body = eapol_hdr + key_payload
    body = body[:1] + struct.pack(">BB", body[1], body[2]) + struct.pack(">H", len(key_payload))

    eth = bytes.fromhex(client_mac.replace(':', ''))
    eth += bytes.fromhex(ap_mac.replace(':', ''))
    eth += struct.pack(">H", ETHERTYPE_EAPOL)
    return eth + body


def build_4way_pcap(ap_mac: str, client_mac: str, essid: str,
                    pmkid: bytes,
                    output_path: str = "fixtures/eapol_4way.pcap") -> str:
    """Build a synthetic 4-way handshake pcap with PMKID in M1."""
    anonce = bytes(range(0x10, 0x30))
    snonce = bytes(range(0x30, 0x50))

    # PMKID KDE in M1 key data — use RSN KDE format
    # [eid=0xdd][len][0x00 0x0f 0xac][type=1][0x01 0x00][pmkid=16]
    pmkid_kde = bytearray()
    pmkid_kde.append(0xdd)  # element ID (vendor)
    inner = bytes([0x00, 0x0F, 0xAC]) + bytes([0x01]) + b'\x01\x00' + pmkid
    pmkid_kde.append(len(inner))
    pmkid_kde.extend(inner)

    m1 = build_eapol_m1(ap_mac, client_mac, anonce, pmkid_kde)
    m2 = build_eapol_m2(client_mac, ap_mac, snonce)
    m3 = build_eapol_m3(ap_mac, client_mac, anonce)
    m4 = build_eapol_m4(client_mac, ap_mac)

    frames = [m1, m2, m3, m4]
    write_eapol_pcap(frames, output_path)
    return output_path


def write_eapol_pcap(frames: list[bytes], path: str) -> str:
    """Write EAPOL frames to a pcap (linktype 1 = Ethernet II)."""
    LINKTYPE_ETHERNET = 1
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII",
                            0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for raw in frames:
            f.write(struct.pack("<IIII", 0, 0, len(raw), len(raw)))
            f.write(raw)
    return path


def parse_eapol_from_pcap(path: str) -> list[dict]:
    """Parse EAPOL frames from a pcap file."""
    results = []
    with open(path, "rb") as f:
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            return results
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            results.append(_parse_single_eapol(data))
    return results


def _parse_single_eapol(data: bytes) -> dict:
    """Parse a single EAPOL Ethernet frame."""
    if len(data) < 14:
        return {"error": "too_short"}
    dst_mac = data[0:6].hex()
    src_mac = data[6:12].hex()
    ethertype = struct.unpack(">H", data[12:14])[0]
    if ethertype != ETHERTYPE_EAPOL:
        return {"error": f"not_eapol_{ethertype:#x}"}

    eapol_data = data[14:]
    if len(eapol_data) < 4:
        return {"error": "eapol_too_short"}

    version = eapol_data[0]
    eapol_type = eapol_data[1]
    body_len = struct.unpack(">H", eapol_data[2:4])[0]

    result = {
        "src_mac": ":".join(src_mac[i:i+2] for i in range(0, 12, 2)),
        "dst_mac": ":".join(dst_mac[i:i+2] for i in range(0, 12, 2)),
        "version": version,
        "eapol_type": eapol_type,
        "body_len": body_len,
    }

    if eapol_type == 3 and len(eapol_data) >= 60:  # EAPOL-Key minimum: hdr(4) + key_info(2) + replay(4) + nonce(32) + mic(16) + kd_len(2)
        key_info = struct.unpack(">H", eapol_data[4:6])[0]
        replay_counter = struct.unpack(">I", eapol_data[6:10])[0]
        nonce = eapol_data[10:42]
        mic = eapol_data[42:58]
        kd_len = struct.unpack(">H", eapol_data[58:60])[0]
        key_data = eapol_data[60:60+kd_len]

        result["key_info"] = key_info
        result["replay_counter"] = replay_counter
        result["nonce_hex"] = nonce.hex()
        result["mic_hex"] = mic.hex()
        result["key_data_hex"] = key_data.hex()
        result["key_data_len"] = kd_len

        pmkid = extract_pmkid_from_key_data(key_data)
        if pmkid:
            result["pmkid"] = pmkid.hex()
            result["pmkid_raw"] = pmkid

    return result


def pipeline_summary(ap_mac: str, client_mac: str, essid: str,
                     pmkid: bytes) -> dict:
    """Full pipeline: build → parse → extract → format."""
    pcap_path = build_4way_pcap(ap_mac, client_mac, essid, pmkid)
    parsed = parse_eapol_from_pcap(pcap_path)
    m1_pmkid = None
    for p in parsed:
        if "pmkid_raw" in p:
            m1_pmkid = p["pmkid_raw"]
            break
    return {
        "pcap_path": pcap_path,
        "frames_parsed": len(parsed),
        "pmkid_extracted": m1_pmkid.hex() if m1_pmkid else None,
        "hashcat_line": pmkid_to_hashcat(m1_pmkid or pmkid, ap_mac, client_mac, essid),
        "hcx_line": pmkid_to_hcx(m1_pmkid or pmkid, ap_mac, client_mac, essid),
        "ready_for_crack": m1_pmkid is not None,
    }
