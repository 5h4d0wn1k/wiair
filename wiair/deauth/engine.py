"""Deauth engine — craft deauth frames, storm simulator, rate-limited.

Live emission requires --air --lab-ssid <allowlist>.
"""

import struct
import time
from dataclasses import dataclass
from typing import Callable, Optional

from wiair.frames.ieee80211 import (
    build_deauth,
    parse_deauth,
    Dot11Frame,
    REASON_CODES,
)
from wiair.safety import require_air


@dataclass
class DeauthStormConfig:
    bssid: str
    src: str
    dst: str = "ff:ff:ff:ff:ff:ff"
    reason_start: int = 0x01
    reason_end: int = 0x0D
    count_per_reason: int = 3
    delay: float = 0.01  # seconds between frames
    max_rate: int = 100  # max frames per second


def craft_deauth_frames(config: DeauthStormConfig) -> list[bytes]:
    """Build deauth frames for every reason code in range, with repeats."""
    frames = []
    seq = 0
    for reason in range(config.reason_start, config.reason_end + 1):
        for _ in range(config.count_per_reason):
            f = build_deauth(
                bssid=config.bssid,
                src=config.src,
                dst=config.dst,
                reason=reason,
                seq_num=seq & 0xFFF,
            )
            frames.append(f.to_bytes())
            seq += 1
    return frames


def deauth_frame_info(raw: bytes) -> dict:
    """Parse and annotate a raw deauth frame."""
    parsed = parse_deauth(raw)
    parsed["total_bytes"] = len(raw)
    parsed["fcs_present"] = len(raw) >= 28  # 24 hdr + 2 reason + 4 fcs
    return parsed


def simulate_storm(config: DeauthStormConfig,
                   on_frame: Optional[Callable[[bytes, dict], None]] = None,
                   emit: bool = False) -> list[dict]:
    """Simulate a deauth storm offline. Returns list of frame metadata.

    If emit=True and --air + allowlist satisfied, would send (stubbed).
    """
    if emit:
        # SAFETY GATE: require air + allowlist. Always refuses in tests/demo.
        require_air(config.bssid)
        # There is no live radio driver yet; emission is a documented stub.
        raise SystemExit("REFUSED: live deauth emission is not implemented "
                         "in this offline build. --air --lab-ssid only "
                         "authorizes the (future) hardware path.")

    frames = craft_deauth_frames(config)
    min_interval = 1.0 / config.max_rate
    results = []
    for raw in frames:
        info = deauth_frame_info(raw)
        if on_frame:
            on_frame(raw, info)
        results.append(info)
        if config.delay > 0:
            time.sleep(min(config.delay, min_interval))
    return results


def reason_table() -> dict[int, str]:
    """Return the full reason code table."""
    return dict(REASON_CODES)


def storm_summary(results: list[dict]) -> dict:
    """Summarize storm simulation results."""
    reasons_seen = {}
    for r in results:
        rc = r["reason"]
        reasons_seen[rc] = reasons_seen.get(rc, 0) + 1
    return {
        "total_frames": len(results),
        "unique_reasons": len(reasons_seen),
        "reasons": reasons_seen,
        "bytes_total": sum(r["total_bytes"] for r in results),
    }
