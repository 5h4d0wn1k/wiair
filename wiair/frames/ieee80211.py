"""IEEE 802.11 frame builders and parsers — byte-exact, stdlib only.

Handles management frames: beacon, probe req/resp, auth, deauth, association req/resp.
Frame control bits, sequence numbering, Duration, DA/SA/BSSID, Information Elements.
FCS via CRC-32 (802.11 polynomial) is appended and verifiable.
"""

import struct
import binascii
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# CRC-32 with 802.11 polynomial (0xEDB88320 reflected)
# ---------------------------------------------------------------------------

_CRC_TABLE: list[int] = []

def _build_crc_table() -> list[int]:
    tbl = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        tbl.append(crc)
    return tbl

_CRC_TABLE = _build_crc_table()


def crc32_80211(data: bytes) -> int:
    """Compute 802.11 CRC-32 over *data*. Returns unsigned 32-bit value."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def verify_fcs(frame_with_fcs: bytes) -> bool:
    """Verify FCS of a raw frame that includes the trailing 4-byte FCS."""
    if len(frame_with_fcs) < 4:
        return False
    body = frame_with_fcs[:-4]
    expected = struct.unpack("<I", frame_with_fcs[-4:])[0]
    return crc32_80211(body) == expected

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Frame types / subtypes (management)
FRAME_TYPE_MGMT = 0
SUBTYPE_BEACON = 0x08
SUBTYPE_PROBE_REQ = 0x04
SUBTYPE_PROBE_RESP = 0x05
SUBTYPE_AUTH = 0x0B
SUBTYPE_DEAUTH = 0x0C
SUBTYPE_ASSOC_REQ = 0x00
SUBTYPE_ASSOC_RESP = 0x01

# Reason codes (802.11-2020 Table 9-46)
REASON_CODES: dict[int, str] = {
    0x01: "Unspecified",
    0x02: "Previous authentication no longer valid",
    0x03: "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS",
    0x04: "Inactivity",
    0x05: "AP unable to handle all associated STAs",
    0x06: "Class 2 frame received from nonauthenticated STA",
    0x07: "Class 3 frame received from nonassociated STA",
    0x08: "Disassociated because sending STA is leaving (or has left) BSS",
    0x09: "STA requesting (re)association is not authenticated",
    0x0A: "Information element unacceptable",
    0x0B: "Microcode failure",
    0x0C: "Failed to setup QoS",
    0x0D: "Request declined",
}

# Status codes
STATUS_SUCCESS = 0
STATUS_FAILURE = 1

# IE IDs
IE_SSID = 0
IE_SUPPORTED_RATES = 1
IE_COUNTRY = 7
IE_RSN = 48
IE_EXTENDED_SUPPORTED_RATES = 50

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FrameControl:
    protocol_version: int = 2
    frame_type: int = 0
    frame_subtype: int = 0
    to_ds: bool = False
    from_ds: bool = False
    more_frag: bool = False
    retry: bool = False
    power_mgmt: bool = False
    more_data: bool = False
    protected: bool = False
    order: bool = False

    def to_bytes(self) -> bytes:
        fc = 0
        fc |= (self.protocol_version & 0x3)
        fc |= (self.frame_type & 0x3) << 2
        fc |= (self.frame_subtype & 0xF) << 4
        if self.to_ds:
            fc |= 1 << 8
        if self.from_ds:
            fc |= 1 << 9
        if self.more_frag:
            fc |= 1 << 10
        if self.retry:
            fc |= 1 << 11
        if self.power_mgmt:
            fc |= 1 << 12
        if self.more_data:
            fc |= 1 << 13
        if self.protected:
            fc |= 1 << 14
        if self.order:
            fc |= 1 << 15
        return struct.pack("<H", fc)

    @classmethod
    def from_bytes(cls, data: bytes) -> "FrameControl":
        fc = struct.unpack("<H", data[:2])[0]
        return cls(
            protocol_version=fc & 0x3,
            frame_type=(fc >> 2) & 0x3,
            frame_subtype=(fc >> 4) & 0xF,
            to_ds=bool(fc & (1 << 8)),
            from_ds=bool(fc & (1 << 9)),
            more_frag=bool(fc & (1 << 10)),
            retry=bool(fc & (1 << 11)),
            power_mgmt=bool(fc & (1 << 12)),
            more_data=bool(fc & (1 << 13)),
            protected=bool(fc & (1 << 14)),
            order=bool(fc & (1 << 15)),
        )


@dataclass
class Dot11Frame:
    fc: FrameControl
    duration: int = 0
    addr1: bytes = field(default_factory=lambda: b'\xff\xff\xff\xff\xff\xff')
    addr2: bytes = field(default_factory=lambda: b'\x00\x11\x22\x33\x44\x55')
    addr3: bytes = field(default_factory=lambda: b'\x00\x11\x22\x33\x44\x55')
    seq_ctrl: int = 0
    body: bytes = b''
    fcs: Optional[int] = None

    @property
    def seq_num(self) -> int:
        return (self.seq_ctrl >> 4) & 0xFFF

    @seq_num.setter
    def seq_num(self, val: int) -> None:
        frag = self.seq_ctrl & 0x0F
        self.seq_ctrl = ((val & 0xFFF) << 4) | frag

    @property
    def frag_num(self) -> int:
        return self.seq_ctrl & 0x0F

    def header_bytes(self) -> bytes:
        """Header without FCS."""
        hdr = bytearray()
        hdr.extend(self.fc.to_bytes())
        hdr.extend(struct.pack("<H", self.duration))
        hdr.extend(self.addr1)
        hdr.extend(self.addr2)
        hdr.extend(self.addr3)
        hdr.extend(struct.pack("<H", self.seq_ctrl))
        return bytes(hdr)

    def to_bytes(self, include_fcs: bool = True) -> bytes:
        """Full frame bytes with optional FCS."""
        raw = self.header_bytes() + self.body
        if include_fcs:
            fcs_val = crc32_80211(raw)
            return raw + struct.pack("<I", fcs_val)
        return raw

    @classmethod
    def from_bytes(cls, data: bytes) -> "Dot11Frame":
        """Parse a raw frame (with or without FCS)."""
        if len(data) < 24:
            raise ValueError(f"Frame too short: {len(data)} bytes")
        fc = FrameControl.from_bytes(data[0:2])
        duration = struct.unpack("<H", data[2:4])[0]
        addr1 = data[4:10]
        addr2 = data[10:16]
        addr3 = data[16:22]
        seq_ctrl = struct.unpack("<H", data[22:24])[0]
        body = data[24:]
        return cls(fc=fc, duration=duration, addr1=addr1, addr2=addr2,
                   addr3=addr3, seq_ctrl=seq_ctrl, body=body)


# ---------------------------------------------------------------------------
# IE helpers
# ---------------------------------------------------------------------------

def encode_ssid(ssid: str) -> bytes:
    """Encode SSID as IE tag."""
    ssid_bytes = ssid.encode("utf-8")
    return struct.pack("BB", IE_SSID, len(ssid_bytes)) + ssid_bytes


def encode_supported_rates(rates: list[float]) -> bytes:
    """Encode Supported Rates IE. rates in Mbit/s."""
    rate_bytes = bytearray()
    for r in rates:
        val = int(r * 2)
        rate_bytes.append(val)
    return struct.pack("BB", IE_SUPPORTED_RATES, len(rate_bytes)) + bytes(rate_bytes)


def encode_country(country_code: str = "XX") -> bytes:
    """Encode Country IE."""
    cc = country_code[:2].encode("ascii")
    data = cc + b'\x04'  # first channel
    return struct.pack("BB", IE_COUNTRY, len(data)) + data


def encode_rsn(psk: bool = True, akms: Optional[list[int]] = None) -> bytes:
    """Encode RSN IE (WPA2/WPA3/transition).

    akms is an optional list of AKM suite type octets to embed; when given it
    overrides `psk`. Example transition-mode (WPA2+WPA3): akms=[0x02, 0x08].
    """
    version = struct.pack("<H", 1)
    group_cipher = bytes([0x00, 0x0F, 0xAC, 0x04])  # CCMP-128
    pairwise_count = struct.pack("<H", 1)
    pairwise_cipher = bytes([0x00, 0x0F, 0xAC, 0x04])  # CCMP-128
    if akms is None:
        akms = [0x02] if psk else [0x01]  # PSK or 802.1X
    akm_count = struct.pack("<H", len(akms))
    akm_suites = b"".join(bytes([0x00, 0x0F, 0xAC, t]) for t in akms)
    rsn_data = (version + group_cipher + pairwise_count + pairwise_cipher
                + akm_count + akm_suites)
    return struct.pack("BB", IE_RSN, len(rsn_data)) + rsn_data


def _parse_ies(data: bytes) -> dict[int, bytes]:
    """Parse Information Elements from body bytes."""
    ies = {}
    i = 0
    while i + 1 < len(data):
        eid = data[i]
        elen = data[i + 1]
        if i + 2 + elen > len(data):
            break
        ies[eid] = data[i + 2: i + 2 + elen]
        i += 2 + elen
    return ies


def _find_ssid(ies: dict[int, bytes]) -> str:
    if IE_SSID in ies:
        return ies[IE_SSID].decode("utf-8", errors="replace")
    return ""


# ---------------------------------------------------------------------------
# MAC helpers
# ---------------------------------------------------------------------------

def mac_bytes(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)

def mac_to_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))

# ---------------------------------------------------------------------------
# Beacon
# ---------------------------------------------------------------------------

def build_beacon(ssid: str, bssid: str, src: str, seq_num: int = 0,
                 rates: Optional[list[float]] = None,
                 country: str = "XX",
                 rsn: bool = True,
                 timestamp: int = 0,
                 beacon_interval: int = 100,
                 capability: int = 0x0001) -> Dot11Frame:
    """Build a beacon management frame."""
    if rates is None:
        rates = [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0]
    fc = FrameControl(frame_type=FRAME_TYPE_MGMT, frame_subtype=SUBTYPE_BEACON)
    body = bytearray()
    body.extend(struct.pack("<Q", timestamp))
    body.extend(struct.pack("<H", beacon_interval))
    body.extend(struct.pack("<H", capability))
    body.extend(encode_ssid(ssid))
    body.extend(encode_supported_rates(rates))
    body.extend(encode_country(country))
    if rsn:
        body.extend(encode_rsn(psk=True))
    frame = Dot11Frame(
        fc=fc,
        addr1=mac_to_bytes("ff:ff:ff:ff:ff:ff"),
        addr2=mac_to_bytes(src),
        addr3=mac_to_bytes(bssid),
    )
    frame.body = bytes(body)
    frame.seq_num = seq_num
    return frame


def parse_beacon(data: bytes) -> dict:
    """Parse beacon frame. Returns dict with parsed fields."""
    frame = Dot11Frame.from_bytes(data)
    ies = _parse_ies(frame.body[12:])  # skip timestamp(8) + interval(2) + cap(2)
    return {
        "type": "beacon",
        "bssid": mac_bytes(frame.addr3),
        "src": mac_bytes(frame.addr2),
        "ssid": _find_ssid(ies),
        "sequence": frame.seq_num,
        "ies": {k: v.hex() for k, v in ies.items()},
        "raw_hex": frame.to_bytes().hex(),
    }


# ---------------------------------------------------------------------------
# Probe Request
# ---------------------------------------------------------------------------

def build_probe_req(ssid: str, src: str, seq_num: int = 0,
                    rates: Optional[list[float]] = None) -> Dot11Frame:
    if rates is None:
        rates = [1.0, 2.0, 5.5, 11.0, 6.0, 12.0, 24.0]
    fc = FrameControl(frame_type=FRAME_TYPE_MGMT, frame_subtype=SUBTYPE_PROBE_REQ)
    body = bytearray()
    body.extend(encode_ssid(ssid))
    body.extend(encode_supported_rates(rates))
    frame = Dot11Frame(
        fc=fc,
        addr1=mac_to_bytes("ff:ff:ff:ff:ff:ff"),
        addr2=mac_to_bytes(src),
        addr3=mac_to_bytes(src),
    )
    frame.body = bytes(body)
    frame.seq_num = seq_num
    return frame


def parse_probe_req(data: bytes) -> dict:
    frame = Dot11Frame.from_bytes(data)
    ies = _parse_ies(frame.body)
    return {
        "type": "probe_request",
        "src": mac_bytes(frame.addr2),
        "ssid": _find_ssid(ies),
        "sequence": frame.seq_num,
        "ies": {k: v.hex() for k, v in ies.items()},
        "raw_hex": frame.to_bytes().hex(),
    }


# ---------------------------------------------------------------------------
# Probe Response
# ---------------------------------------------------------------------------

def build_probe_resp(ssid: str, bssid: str, src: str, dst: str,
                     seq_num: int = 0,
                     rates: Optional[list[float]] = None,
                     country: str = "XX",
                     rsn: bool = True) -> Dot11Frame:
    if rates is None:
        rates = [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0]
    fc = FrameControl(frame_type=FRAME_TYPE_MGMT, frame_subtype=SUBTYPE_PROBE_RESP)
    body = bytearray()
    body.extend(struct.pack("<Q", 0))  # timestamp
    body.extend(struct.pack("<H", 100))  # beacon interval
    body.extend(struct.pack("<H", 0x0001))  # capability
    body.extend(encode_ssid(ssid))
    body.extend(encode_supported_rates(rates))
    body.extend(encode_country(country))
    if rsn:
        body.extend(encode_rsn(psk=True))
    frame = Dot11Frame(
        fc=fc,
        addr1=mac_to_bytes(dst),
        addr2=mac_to_bytes(src),
        addr3=mac_to_bytes(bssid),
    )
    frame.body = bytes(body)
    frame.seq_num = seq_num
    return frame


def parse_probe_resp(data: bytes) -> dict:
    frame = Dot11Frame.from_bytes(data)
    ies = _parse_ies(frame.body[12:])
    return {
        "type": "probe_response",
        "bssid": mac_bytes(frame.addr3),
        "src": mac_bytes(frame.addr2),
        "dst": mac_bytes(frame.addr1),
        "ssid": _find_ssid(ies),
        "sequence": frame.seq_num,
        "ies": {k: v.hex() for k, v in ies.items()},
        "raw_hex": frame.to_bytes().hex(),
    }


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def build_auth(bssid: str, src: str, dst: str, seq_num: int = 0,
               auth_algo: int = 0, auth_seq: int = 1,
               status: int = STATUS_SUCCESS) -> Dot11Frame:
    fc = FrameControl(frame_type=FRAME_TYPE_MGMT, frame_subtype=SUBTYPE_AUTH)
    body = struct.pack("<HHH", auth_algo, auth_seq, status)
    frame = Dot11Frame(
        fc=fc,
        addr1=mac_to_bytes(dst),
        addr2=mac_to_bytes(src),
        addr3=mac_to_bytes(bssid),
    )
    frame.body = body
    frame.seq_num = seq_num
    return frame


def parse_auth(data: bytes) -> dict:
    frame = Dot11Frame.from_bytes(data)
    if len(frame.body) >= 6:
        auth_algo, auth_seq, status = struct.unpack("<HHH", frame.body[:6])
    else:
        auth_algo, auth_seq, status = 0, 0, 0
    return {
        "type": "auth",
        "bssid": mac_bytes(frame.addr3),
        "src": mac_bytes(frame.addr2),
        "dst": mac_bytes(frame.addr1),
        "auth_algo": auth_algo,
        "auth_seq": auth_seq,
        "status": status,
        "sequence": frame.seq_num,
        "raw_hex": frame.to_bytes().hex(),
    }


# ---------------------------------------------------------------------------
# Deauthentication
# ---------------------------------------------------------------------------

def build_deauth(bssid: str, src: str, dst: str, reason: int = 0x01,
                 seq_num: int = 0) -> Dot11Frame:
    fc = FrameControl(frame_type=FRAME_TYPE_MGMT, frame_subtype=SUBTYPE_DEAUTH)
    body = struct.pack("<H", reason)
    frame = Dot11Frame(
        fc=fc,
        addr1=mac_to_bytes(dst),
        addr2=mac_to_bytes(src),
        addr3=mac_to_bytes(bssid),
    )
    frame.body = body
    frame.seq_num = seq_num
    return frame


def parse_deauth(data: bytes) -> dict:
    frame = Dot11Frame.from_bytes(data)
    reason = struct.unpack("<H", frame.body[:2])[0] if len(frame.body) >= 2 else 0
    return {
        "type": "deauth",
        "bssid": mac_bytes(frame.addr3),
        "src": mac_bytes(frame.addr2),
        "dst": mac_bytes(frame.addr1),
        "reason": reason,
        "reason_text": REASON_CODES.get(reason, "Unknown"),
        "sequence": frame.seq_num,
        "raw_hex": frame.to_bytes().hex(),
    }


# ---------------------------------------------------------------------------
# Association Request
# ---------------------------------------------------------------------------

def build_association_req(ssid: str, bssid: str, src: str,
                          seq_num: int = 0,
                          rates: Optional[list[float]] = None,
                          rsn: bool = True) -> Dot11Frame:
    if rates is None:
        rates = [1.0, 2.0, 5.5, 11.0, 6.0, 12.0, 24.0]
    fc = FrameControl(frame_type=FRAME_TYPE_MGMT, frame_subtype=SUBTYPE_ASSOC_REQ)
    body = bytearray()
    body.extend(struct.pack("<H", 0x0001))  # capability
    body.extend(struct.pack("<H", 10))  # listen interval
    body.extend(encode_ssid(ssid))
    body.extend(encode_supported_rates(rates))
    if rsn:
        body.extend(encode_rsn(psk=True))
    frame = Dot11Frame(
        fc=fc,
        addr1=mac_to_bytes(bssid),
        addr2=mac_to_bytes(src),
        addr3=mac_to_bytes(bssid),
    )
    frame.body = bytes(body)
    frame.seq_num = seq_num
    return frame


def parse_association_req(data: bytes) -> dict:
    frame = Dot11Frame.from_bytes(data)
    ies = _parse_ies(frame.body[4:])  # skip capability(2) + listen interval(2)
    return {
        "type": "association_request",
        "bssid": mac_bytes(frame.addr3),
        "src": mac_bytes(frame.addr2),
        "ssid": _find_ssid(ies),
        "sequence": frame.seq_num,
        "raw_hex": frame.to_bytes().hex(),
    }


# ---------------------------------------------------------------------------
# Association Response
# ---------------------------------------------------------------------------

def build_association_resp(bssid: str, src: str, dst: str,
                           seq_num: int = 0,
                           status: int = STATUS_SUCCESS,
                           aid: int = 1,
                           rates: Optional[list[float]] = None) -> Dot11Frame:
    if rates is None:
        rates = [1.0, 2.0, 5.5, 11.0, 6.0, 12.0, 24.0, 36.0, 48.0, 54.0]
    fc = FrameControl(frame_type=FRAME_TYPE_MGMT, frame_subtype=SUBTYPE_ASSOC_RESP)
    body = bytearray()
    body.extend(struct.pack("<H", status))
    body.extend(struct.pack("<H", aid & 0x3FFF))
    body.extend(struct.pack("<H", 0x0001))  # capability
    body.extend(encode_supported_rates(rates))
    frame = Dot11Frame(
        fc=fc,
        addr1=mac_to_bytes(dst),
        addr2=mac_to_bytes(src),
        addr3=mac_to_bytes(bssid),
    )
    frame.body = bytes(body)
    frame.seq_num = seq_num
    return frame


def parse_association_resp(data: bytes) -> dict:
    frame = Dot11Frame.from_bytes(data)
    if len(frame.body) >= 6:
        status, aid, cap = struct.unpack("<HHH", frame.body[:6])
    else:
        status, aid, cap = 0, 0, 0
    return {
        "type": "association_response",
        "bssid": mac_bytes(frame.addr3),
        "src": mac_bytes(frame.addr2),
        "dst": mac_bytes(frame.addr1),
        "status": status,
        "aid": aid,
        "sequence": frame.seq_num,
        "raw_hex": frame.to_bytes().hex(),
    }
