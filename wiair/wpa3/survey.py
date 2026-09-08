"""WPA3 (SAE) handshake detection and security posture analysis.

Parse auth frames, flag WPA2/WPA3/OWE transition mode,
score security posture per AP from fixtures.
"""

from wiair.frames.ieee80211 import (
    build_auth,
    parse_auth,
    mac_to_bytes,
    mac_bytes,
)


# SAE authentication algorithms
SAE_COMMIT = 1
SAE_CONFIRM = 2
OPEN_SYSTEM = 0
SAE_THRESHOLD = 3  # SAE auth seq > 2 implies SAE


def detect_sae_auth(frame_data: bytes) -> dict:
    """Analyze an auth frame to detect SAE (WPA3) handshake."""
    parsed = parse_auth(frame_data)
    auth_algo = parsed["auth_algo"]
    auth_seq = parsed["auth_seq"]

    is_sae_commit = (auth_algo == SAE_COMMIT and auth_seq == 1)
    is_sae_confirm = (auth_algo == SAE_COMMIT and auth_seq == 2)
    is_sae = auth_algo >= SAE_COMMIT

    return {
        "auth_algo": auth_algo,
        "auth_seq": auth_seq,
        "status": parsed["status"],
        "is_sae": is_sae,
        "sae_phase": "commit" if is_sae_commit else ("confirm" if is_sae_confirm else None),
        "src": parsed["src"],
        "bssid": parsed["bssid"],
    }


def detect_transition_mode(beacon_info: dict) -> dict:
    """Detect WPA2/WPA3 transition mode from beacon/probe response info.

    Heuristics:
    - RSN IE with AKM 0x000FAC:0x08 = SAE (WPA3)
    - RSN IE with AKM 0x000FAC:0x02 = PSK (WPA2)
    - Both present → transition mode
    - OWE: AKM 0x000FAC:0x12
    """
    ies = beacon_info.get("ies", {})
    rsn_hex = ies.get("48", "")

    result = {
        "wpa3_sae": False,
        "wpa2_psk": False,
        "owe": False,
        "transition_mode": False,
        "security": "unknown",
    }

    if not rsn_hex:
        result["security"] = "open_or_wep"
        return result

    rsn_bytes = bytes.fromhex(rsn_hex)

    # Parse AKM suites (simplified — after pairwise cipher suite list)
    # RSN format: version(2) + group(4) + pairwise_count(2) + pairwise(n*4) + akm_count(2) + akm(n*4)
    if len(rsn_bytes) < 10:
        return result

    offset = 2  # version
    offset += 4  # group cipher
    pairwise_count = int.from_bytes(rsn_bytes[offset:offset+2], 'little')
    offset += 2 + pairwise_count * 4

    if offset + 2 > len(rsn_bytes):
        return result

    akm_count = int.from_bytes(rsn_bytes[offset:offset+2], 'little')
    offset += 2

    for i in range(akm_count):
        if offset + 4 > len(rsn_bytes):
            break
        suite = rsn_bytes[offset:offset+4]
        if suite[:3] == b'\x00\x0f\xac':
            akm_type = suite[3]
            if akm_type == 0x02:
                result["wpa2_psk"] = True
            elif akm_type == 0x08:
                result["wpa3_sae"] = True
            elif akm_type == 0x0C:
                result["wpa3_sae"] = True  # SAE-PSK
            elif akm_type == 0x12:
                result["owe"] = True
        offset += 4

    if result["wpa3_sae"] and result["wpa2_psk"]:
        result["transition_mode"] = True
        result["security"] = "wpa2/wpa3_transition"
    elif result["wpa3_sae"]:
        result["security"] = "wpa3_sae"
    elif result["wpa2_psk"]:
        result["security"] = "wpa2_psk"
    elif result["owe"]:
        result["security"] = "owe"
    else:
        result["security"] = "unknown_rsn"

    return result


def security_posture_score(transition_info: dict,
                           has_mfp: bool = False) -> dict:
    """Score AP security posture 0-100.

    Scoring:
    - WPA3 SAE only: 95
    - WPA2/WPA3 transition: 75
    - WPA2 PSK: 60
    - OWE: 70
    - Open: 0
    - MFP bonus: +10
    """
    scores = {
        "wpa3_sae": 95,
        "wpa2/wpa3_transition": 75,
        "wpa2_psk": 60,
        "owe": 70,
        "open_or_wep": 0,
        "unknown": 10,
    }
    sec = transition_info.get("security", "unknown")
    base = scores.get(sec, 10)
    if has_mfp:
        base = min(100, base + 10)
    return {
        "security": sec,
        "score": base,
        "has_mfp": has_mfp,
        "recommendation": _recommendation(sec, base),
    }


def _recommendation(security: str, score: int) -> str:
    if score >= 90:
        return "Strong: WPA3 SAE. Acceptable for sensitive networks."
    if score >= 70:
        return "Good: Transition mode. Ensure WPA3-only for high security."
    if score >= 50:
        return "Moderate: WPA2 PSK. Consider upgrading to WPA3."
    return "Weak: Open or legacy encryption. Not recommended."


def survey_ap(auth_frames: list[bytes],
              beacon_info: dict,
              has_mfp: bool = False) -> dict:
    """Full WPA3 survey of an AP from captured frames + beacon info."""
    sae_frames = []
    for frame_data in auth_frames:
        sae_info = detect_sae_auth(frame_data)
        if sae_info["is_sae"]:
            sae_frames.append(sae_info)

    transition = detect_transition_mode(beacon_info)
    posture = security_posture_score(transition, has_mfp)

    return {
        "sae_frames": sae_frames,
        "transition": transition,
        "posture": posture,
        "sae_detected": len(sae_frames) > 0,
        "beacon_ssid": beacon_info.get("ssid", ""),
    }
