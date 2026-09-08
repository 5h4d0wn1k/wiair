"""WIDS-evasion — honest study tool.

Given a detected-frame fixture, compute evasion options (seq randomization,
MAC cycling) and their detectability score under a simple heuristic detector.
DEFENSIVE evaluation, clearly labeled.
"""

from dataclasses import dataclass
from typing import Optional

from wiair.frames.ieee80211 import Dot11Frame, FrameControl


# ---------------------------------------------------------------------------
# Heuristic WIDS detector model (simplified)
# ---------------------------------------------------------------------------

@dataclass
class EvasionParams:
    seq_randomize: bool = False
    mac_cycling: bool = False
    interval_jitter: bool = False
    fragment: bool = False


def detectability_score(params: EvasionParams,
                        num_frames: int = 100,
                        time_window: float = 1.0) -> dict:
    """Compute detectability under heuristic WIDS.

    Heuristic model:
    - Same MAC + sequential seq → high detectability (0.95)
    - MAC cycling → reduces pattern but adds vendor OUI anomaly
    - Seq randomization → breaks sequence correlation
    - Interval jitter → breaks periodicity
    - Fragmentation → changes frame signature
    """
    base_score = 0.95  # default: very detectable

    reduction = 0.0
    notes = []

    if params.seq_randomize:
        # Breaking sequential pattern reduces ~40% of detection signal
        reduction += 0.40
        notes.append("seq_randomize: breaks sequential pattern (-40%)")

    if params.mac_cycling:
        # MAC cycling removes fixed-source correlation but adds OUI anomaly
        reduction += 0.25
        penalty = 0.10  # OUI anomaly detection
        notes.append(f"mac_cycling: removes source correlation (-25%) but OUI anomaly (+{penalty})")
        reduction -= penalty

    if params.interval_jitter:
        # Breaks periodic transmission pattern
        reduction += 0.15
        notes.append("interval_jitter: breaks periodicity (-15%)")

    if params.fragment:
        # Fragmentation changes frame size distribution
        reduction += 0.10
        notes.append("fragment: changes size distribution (-10%)")

    detectability = max(0.05, base_score - reduction)

    # High frame count increases detectability regardless of evasion
    if num_frames > 50:
        detectability = min(1.0, detectability + 0.10)
        notes.append(f"high_frame_count({num_frames}): +10% detectability")

    return {
        "detectability": round(detectability, 3),
        "risk_level": (
            "HIGH" if detectability > 0.7 else
            "MEDIUM" if detectability > 0.4 else
            "LOW"
        ),
        "notes": notes,
        "defense_evaluation": True,  # Clearly labeled
        "label": "WIDS-EVASION DEFENSIVE STUDY — NOT FOR OFFENSIVE USE",
    }


def evaluate_evasion(frame_data: bytes,
                     seq_randomize: bool = False,
                     mac_cycling: bool = False,
                     interval_jitter: bool = False,
                     fragment: bool = False,
                     num_frames: int = 100) -> dict:
    """Full evasion analysis on a given frame.

    Returns detection score and recommendations from a DEFENSIVE perspective.
    """
    frame = Dot11Frame.from_bytes(frame_data)
    params = EvasionParams(
        seq_randomize=seq_randomize,
        mac_cycling=mac_cycling,
        interval_jitter=interval_jitter,
        fragment=fragment,
    )
    score = detectability_score(params, num_frames)

    return {
        "original_frame": {
            "type": frame.fc.frame_type,
            "subtype": frame.fc.frame_subtype,
            "src": frame.addr2.hex(),
            "seq_num": frame.seq_num,
        },
        "evasion_params": {
            "seq_randomize": params.seq_randomize,
            "mac_cycling": params.mac_cycling,
            "interval_jitter": params.interval_jitter,
            "fragment": params.fragment,
        },
        "detection_analysis": score,
        "recommendation": _defense_recommendation(score),
    }


def _defense_recommendation(score: dict) -> str:
    """Recommendation from defender's perspective."""
    risk = score["risk_level"]
    if risk == "HIGH":
        return ("Defender perspective: attack frames are highly detectable. "
                "WIDS will likely trigger. Recommend alerting on sequential "
                "deauth sequences and fixed-source management floods.")
    if risk == "MEDIUM":
        return ("Defender perspective: evasion techniques partially reduce "
                "detectability. WIDS should monitor for OUI anomalies and "
                "probe-response storms in addition to sequence analysis.")
    return ("Defender perspective: evasion is somewhat effective against "
            "simple heuristics. Deploy ML-based anomaly detection and "
            "cross-correlate with RF spectrum analysis.")
