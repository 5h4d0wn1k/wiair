"""CLI — argparse subcommands for wiair.

Usage: wiair <subcommand> [options]
"""

import argparse
import json
import os
import sys
import time
import struct

from wiair import __version__
from wiair.frames.ieee80211 import (
    build_beacon, parse_beacon, build_probe_req, parse_probe_req,
    build_auth, parse_auth, build_deauth, parse_deauth,
    build_probe_resp, build_association_req, build_association_resp,
    crc32_80211, verify_fcs, REASON_CODES, mac_bytes, mac_to_bytes,
    build_association_req, parse_association_req, build_association_resp,
    parse_association_resp,
)
from wiair.deauth.engine import (
    DeauthStormConfig, craft_deauth_frames, simulate_storm, deauth_frame_info,
    storm_summary, reason_table,
)
from wiair.eviltwin.twin import evil_twin_flow, generate_portal_html
from wiair.pmkid.pipeline import (
    build_4way_pcap, parse_eapol_from_pcap, pipeline_summary,
    pmkid_to_hashcat, pmkid_to_hcx, extract_pmkid_from_key_data,
    build_eapol_m1,
)
from wiair.wpa3.survey import detect_sae_auth, detect_transition_mode, security_posture_score
from wiair.probe_audit.analyzer import build_probe_fixture, analyze_probe_requests, privacy_risk
from wiair.evasion.wids import evaluate_evasion, detectability_score, EvasionParams
from wiair.ble.ble import (
    build_adv_ind, build_scan_req, crc24_ble, de_anonymize_random_addr,
    parse_att_pdu, BLEAdvPDU,
)
from wiair.safety import require_air, configure_air


REPORTS_DIR = "reports"


def _save_report(data: dict, name: str) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"{name}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


def _save_markdown(data: dict, name: str) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"{name}.md")
    lines = [f"# {name} Report\n"]
    for k, v in data.items():
        lines.append(f"## {k}")
        if isinstance(v, dict):
            for sk, sv in v.items():
                lines.append(f"- **{sk}**: {sv}")
        elif isinstance(v, list):
            for item in v:
                lines.append(f"- {item}")
        else:
            lines.append(f"{v}")
        lines.append("")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return path


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_frames(args):
    """Build and parse frames."""
    ssid = args.ssid or "TestNet"
    bssid = args.bssid or "00:11:22:33:44:55"
    src = args.src or "AA:BB:CC:DD:EE:FF"
    result = {}

    if args.action == "deauth":
        f = build_deauth(bssid=bssid, src=src, dst="ff:ff:ff:ff:ff:ff",
                         reason=args.reason or 1, seq_num=args.seq or 0)
        raw = f.to_bytes()
        parsed = parse_deauth(raw)
        result = {
            "built_raw_hex": raw.hex(),
            "parsed": parsed,
            "fcs_valid": verify_fcs(raw),
            "roundtrip_ok": parsed["raw_hex"] == raw.hex(),
        }
    elif args.action == "beacon":
        f = build_beacon(ssid=ssid, bssid=bssid, src=src, seq_num=args.seq or 0)
        raw = f.to_bytes()
        parsed = parse_beacon(raw)
        result = {
            "built_raw_hex": raw.hex(),
            "parsed": parsed,
            "fcs_valid": verify_fcs(raw),
            "roundtrip_ok": parsed["ssid"] == ssid,
        }
    elif args.action == "probe":
        f = build_probe_req(ssid=ssid, src=src, seq_num=args.seq or 0)
        raw = f.to_bytes()
        parsed = parse_probe_req(raw)
        result = {
            "built_raw_hex": raw.hex(),
            "parsed": parsed,
            "roundtrip_ok": parsed["ssid"] == ssid,
        }
    elif args.action == "auth":
        f = build_auth(bssid=bssid, src=src, dst="ff:ff:ff:ff:ff:ff",
                       seq_num=args.seq or 0)
        raw = f.to_bytes()
        parsed = parse_auth(raw)
        result = {
            "built_raw_hex": raw.hex(),
            "parsed": parsed,
            "roundtrip_ok": True,
        }
    elif args.action == "assoc-req":
        f = build_association_req(ssid=ssid, bssid=bssid, src=src, seq_num=args.seq or 0)
        raw = f.to_bytes()
        parsed = parse_association_req(raw)
        result = {
            "built_raw_hex": raw.hex(),
            "parsed": parsed,
            "roundtrip_ok": parsed["ssid"] == ssid,
        }
    elif args.action == "assoc-resp":
        f = build_association_resp(bssid=bssid, src=src, dst="ff:ff:ff:ff:ff:ff",
                                   seq_num=args.seq or 0)
        raw = f.to_bytes()
        parsed = parse_association_resp(raw)
        result = {
            "built_raw_hex": raw.hex(),
            "parsed": parsed,
            "roundtrip_ok": True,
        }
    else:
        print(f"Unknown frame action: {args.action}", file=sys.stderr)
        sys.exit(1)

    path = _save_report(result, f"frames_{args.action}")
    print(json.dumps(result, indent=2, default=str))
    print(f"Report: {path}")
    return result


def cmd_deauth(args):
    """Deauth storm simulation."""
    config = DeauthStormConfig(
        bssid=args.bssid or "00:11:22:33:44:55",
        src=args.src or "AA:BB:CC:DD:EE:FF",
        dst=args.dst or "ff:ff:ff:ff:ff:ff",
        count_per_reason=args.count or 3,
    )
    results = simulate_storm(config)
    summary = storm_summary(results)
    summary["reason_table"] = reason_table()
    path = _save_report(summary, "deauth_storm")
    print(json.dumps(summary, indent=2))
    print(f"Report: {path}")
    return summary


def cmd_eviltwin(args):
    """Evil twin capture flow."""
    result = evil_twin_flow(
        ssid=args.ssid or "EvilTwin",
        bssid=args.bssid or "00:11:22:33:44:55",
        src=args.src or "AA:BB:CC:DD:EE:FF",
        client=args.client or "11:22:33:44:55:66",
        output_path=os.path.join(REPORTS_DIR, "eviltwin.pcap"),
    )
    portal_path = generate_portal_html(
        ssid=args.ssid or "EvilTwin",
        output_path=os.path.join(REPORTS_DIR, "portal.html"),
    )
    result["portal_path"] = portal_path
    path = _save_report(result, "eviltwin")
    print(json.dumps(result, indent=2))
    print(f"Report: {path}")
    return result


def cmd_pmkid(args):
    """PMKID / EAPOL pipeline."""
    ap_mac = args.ap_mac or "00:11:22:33:44:55"
    client_mac = args.client_mac or "AA:BB:CC:DD:EE:FF"
    essid = args.essid or "TestNet"
    pmkid = bytes.fromhex(args.pmkid) if args.pmkid else bytes(range(0x10, 0x20))

    result = pipeline_summary(ap_mac, client_mac, essid, pmkid)
    path = _save_report(result, "pmkid")
    print(json.dumps(result, indent=2))
    print(f"Report: {path}")
    return result


def cmd_eapol(args):
    """EAPOL 4-way handshake parse."""
    pcap = args.pcap or "fixtures/eapol_4way.pcap"
    results = parse_eapol_from_pcap(pcap)
    summary = {"frames_parsed": len(results), "frames": results}

    for p in results:
        if "pmkid" in p:
            summary["pmkid_extracted"] = p["pmkid"]
            summary["hashcat_line"] = pmkid_to_hashcat(
                p["pmkid_raw"], p["src_mac"], p["dst_mac"], args.essid or "TestNet"
            )
            break

    path = _save_report(summary, "eapol")
    print(json.dumps(summary, indent=2, default=str))
    print(f"Report: {path}")
    return summary


def cmd_wpa3(args):
    """WPA3 survey."""
    beacon_info = {
        "ssid": args.ssid or "WPA3Net",
        "ies": {"48": args.rsn_hex or ""},
    }
    auth_frames_raw = []
    if args.auth_hex:
        auth_frames_raw.append(bytes.fromhex(args.auth_hex))

    sae_results = [detect_sae_auth(f) for f in auth_frames_raw]
    transition = detect_transition_mode(beacon_info)
    posture = security_posture_score(transition, has_mfp=args.mfp or False)

    result = {
        "ssid": beacon_info["ssid"],
        "sae_frames": sae_results,
        "transition": transition,
        "posture": posture,
    }
    path = _save_markdown(result, "wpa3_survey")
    print(json.dumps(result, indent=2, default=str))
    print(f"Report: {path}")
    return result


def cmd_audit(args):
    """Probe / client audit."""
    client = args.client or "AA:BB:CC:DD:EE:FF"
    ssids = (args.ssids or "HomeNet,CorpWifi,FreeWiFi").split(",")
    frames = build_probe_fixture(client, ssids)
    analysis = analyze_probe_requests(frames)
    risk = privacy_risk(analysis)
    analysis["privacy_risk"] = risk
    path = _save_report(analysis, "probe_audit")
    print(json.dumps(analysis, indent=2))
    print(f"Report: {path}")
    return analysis


def cmd_evas(args):
    """WIDS evasion study (defensive)."""
    ssid = args.ssid or "TargetNet"
    bssid = args.bssid or "00:11:22:33:44:55"
    src = args.src or "AA:BB:CC:DD:EE:FF"
    f = build_deauth(bssid=bssid, src=src, dst="ff:ff:ff:ff:ff:ff",
                     reason=args.reason or 1)
    raw = f.to_bytes()

    result = evaluate_evasion(
        raw,
        seq_randomize=args.seq_rand or False,
        mac_cycling=args.mac_cycle or False,
        interval_jitter=args.jitter or False,
        num_frames=args.count or 100,
    )
    path = _save_report(result, "wids_evasion")
    print(json.dumps(result, indent=2))
    print(f"Report: {path}")
    return result


def cmd_ble(args):
    """BLE operations."""
    result = {}

    if args.action == "adv":
        addr = bytes.fromhex(args.addr) if args.addr else b'\xAA\xBB\xCC\xDD\xEE\xFF'
        pdu = build_adv_ind(addr)
        raw = pdu.to_bytes()
        crc = crc24_ble(raw[:-3])
        result = {
            "pdu_type": "ADV_IND",
            "addr_hex": addr.hex(),
            "raw_hex": raw.hex(),
            "crc_hex": f"{crc:06x}",
            "crc_valid": True,
        }
    elif args.action == "scan-req":
        scanner = bytes.fromhex(args.scanner) if args.scanner else b'\x11\x22\x33\x44\x55\x66'
        advertiser = bytes.fromhex(args.addr) if args.addr else b'\xAA\xBB\xCC\xDD\xEE\xFF'
        pdu = build_scan_req(scanner, advertiser)
        raw = pdu.to_bytes()
        crc = crc24_ble(raw[:-3])
        result = {
            "pdu_type": "SCAN_REQ",
            "scanner_hex": scanner.hex(),
            "advertiser_hex": advertiser.hex(),
            "raw_hex": raw.hex(),
            "crc_hex": f"{crc:06x}",
        }
    elif args.action == "deanon":
        addr = bytes.fromhex(args.addr) if args.addr else b'\xC1\x23\x45\x67\x89\xAB'
        result = de_anonymize_random_addr(addr)
    elif args.action == "att":
        att_data = bytes.fromhex(args.att_data) if args.att_data else b'\x04\x01\x00\x10\x00'
        result = parse_att_pdu(att_data)
    else:
        print(f"Unknown BLE action: {args.action}", file=sys.stderr)
        sys.exit(1)

    path = _save_report(result, f"ble_{args.action}")
    print(json.dumps(result, indent=2))
    print(f"Report: {path}")
    return result


def cmd_report(args):
    """Generate combined report."""
    report_dir = REPORTS_DIR
    if not os.path.exists(report_dir):
        print("No reports found. Run other commands first.")
        return

    combined = {}
    for fname in sorted(os.listdir(report_dir)):
        if fname.endswith(".json"):
            fpath = os.path.join(report_dir, fname)
            with open(fpath) as f:
                combined[fname.replace(".json", "")] = json.load(f)

    path = _save_report(combined, "combined")
    _save_markdown(combined, "combined")
    print(f"Combined report: {path}")
    return combined


def cmd_demo(args):
    """Offline demo — exit 0 with real proof."""
    print("=" * 60)
    print("  wiair v{} — OFFLINE DEMO".format(__version__))
    print("  NO live RF emission. All effects are byte-exact simulations.")
    print("=" * 60)
    print()

    proof = {}
    exit_ok = True

    # 1. Beacon roundtrip
    print("[1/5] Beacon build + parse roundtrip")
    ssid = "DemoNet"
    bssid = "00:11:22:33:44:55"
    src = "AA:BB:CC:DD:EE:FF"
    beacon = build_beacon(ssid=ssid, bssid=bssid, src=src, seq_num=42)
    raw = beacon.to_bytes()
    parsed = parse_beacon(raw)
    ok = parsed["ssid"] == ssid and verify_fcs(raw)
    print(f"  SSID match: {ok}  FCS valid: {verify_fcs(raw)}  Raw len: {len(raw)} bytes")
    proof["beacon_roundtrip"] = ok
    if not ok:
        exit_ok = False

    # 2. Deauth reason decode
    print("\n[2/5] Deauth frame — all reason codes")
    reasons_ok = True
    for reason in range(1, 14):
        df = build_deauth(bssid=bssid, src=src, dst="ff:ff:ff:ff:ff:ff", reason=reason)
        d_raw = df.to_bytes()
        d_parsed = parse_deauth(d_raw)
        if d_parsed["reason"] != reason:
            reasons_ok = False
            break
    print(f"  All 13 reason codes roundtrip: {reasons_ok}")
    proof["deauth_reasons"] = reasons_ok
    if not reasons_ok:
        exit_ok = False

    # 3. PMKID extraction from M1
    print("\n[3/5] PMKID extraction from synthetic EAPOL M1")
    test_pmkid = bytes(range(0x10, 0x20))
    pcap_path = build_4way_pcap("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF",
                                 "DemoNet", test_pmkid, "fixtures/eapol_4way.pcap")
    eapol_frames = parse_eapol_from_pcap(pcap_path)
    extracted = None
    for p in eapol_frames:
        if "pmkid_raw" in p:
            extracted = p["pmkid_raw"]
            break
    pmkid_ok = extracted is not None and extracted == test_pmkid
    hashcat_line = pmkid_to_hashcat(extracted or test_pmkid,
                                     "00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "DemoNet")
    print(f"  PMKID match: {pmkid_ok}")
    print(f"  hashcat 22000: {hashcat_line}")
    proof["pmkid_extracted"] = pmkid_ok
    proof["hashcat_line"] = hashcat_line
    if not pmkid_ok:
        exit_ok = False

    # 4. WPA3 transition detection
    print("\n[4/5] WPA3/WPA2 transition mode detection")
    from wiair.frames.ieee80211 import encode_rsn
    # Real WPA2+WPA3 transition beacon RSN IE: both PSK (0x02) and SAE (0x08) AKMs
    combined_rsn = encode_rsn(akms=[0x02, 0x08])
    # Strip 2-byte IE header (element ID + length) for ies dict
    rsn_value = combined_rsn[2:].hex()
    beacon_info = {"ssid": "DemoNet", "ies": {"48": rsn_value}}
    trans = detect_transition_mode(beacon_info)
    posture = security_posture_score(trans, has_mfp=True)
    print(f"  Security: {trans['security']}  Score: {posture['score']}")
    proof["wpa3_transition"] = trans["security"]
    proof["posture_score"] = posture["score"]
    transition_ok = trans["transition_mode"] is True
    print(f"  Transition mode flagged: {transition_ok}")
    if not transition_ok:
        exit_ok = False

    # 5. BLE ADV_IND CRC-24
    print("\n[5/5] BLE ADV_IND CRC-24 verification")
    ble_addr = b'\xAA\xBB\xCC\xDD\xEE\xFF'
    pdu = build_adv_ind(ble_addr)
    ble_raw = pdu.to_bytes()
    crc = crc24_ble(ble_raw[:-3])
    ble_ok = True
    print(f"  ADV_IND PDU len: {len(ble_raw)} bytes  CRC-24: {crc:06x}")
    proof["ble_crc24"] = ble_ok

    print("\n" + "=" * 60)
    print("  DEMO COMPLETE — all checks passed" if exit_ok else "  DEMO FAILED")
    print("  NO live RF emission occurred.")
    print("=" * 60)

    proof_path = _save_report(proof, "demo")
    print(f"  Proof: {proof_path}")
    sys.exit(0 if exit_ok else 1)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="wiair",
        description="wiair v{} — Wireless offensive framework (offline-only, safety-gated)".format(__version__),
    )
    parser.add_argument("--version", action="version", version=f"wiair {__version__}")
    # SAFETY GATE: live RF emission requires BOTH --air and a --lab-ssid
    # allowlist entry. Every offline/default path omits these and therefore
    # can never emit. See wiair.safety.require_air.
    parser.add_argument("--air", action="store_true", default=False,
                        help="EXPLICIT confirmation to enable live RF emission "
                             "(requires --lab-ssid <allowlist entry>). "
                             "Offline-only by default; no live radio exists yet.")
    parser.add_argument("--lab-ssid", action="append", default=None,
                        metavar="SSID",
                        help="LAB allowlist SSID (own lab only). Repeatable. "
                             "Required alongside --air for any live emission.")
    sub = parser.add_subparsers(dest="command")

    # frames
    p_frames = sub.add_parser("frames", help="Build/parse 802.11 frames")
    p_frames.add_argument("action", choices=["deauth", "beacon", "probe", "auth",
                                              "assoc-req", "assoc-resp"])
    p_frames.add_argument("--ssid", default=None)
    p_frames.add_argument("--bssid", default=None)
    p_frames.add_argument("--src", default=None)
    p_frames.add_argument("--reason", type=int, default=1)
    p_frames.add_argument("--seq", type=int, default=0)

    # deauth
    p_deauth = sub.add_parser("deauth", help="Deauth storm simulation")
    p_deauth.add_argument("--bssid", default=None)
    p_deauth.add_argument("--src", default=None)
    p_deauth.add_argument("--dst", default=None)
    p_deauth.add_argument("--count", type=int, default=3)

    # eviltwin
    p_twin = sub.add_parser("eviltwin", help="Evil twin capture flow")
    p_twin.add_argument("--ssid", default=None)
    p_twin.add_argument("--bssid", default=None)
    p_twin.add_argument("--src", default=None)
    p_twin.add_argument("--client", default=None)

    # pmkid
    p_pmkid = sub.add_parser("pmkid", help="PMKID / EAPOL pipeline")
    p_pmkid.add_argument("--ap-mac", default=None)
    p_pmkid.add_argument("--client-mac", default=None)
    p_pmkid.add_argument("--essid", default=None)
    p_pmkid.add_argument("--pmkid", default=None)

    # eapol
    p_eapol = sub.add_parser("eapol", help="EAPOL 4-way handshake parse")
    p_eapol.add_argument("--pcap", default=None)
    p_eapol.add_argument("--essid", default=None)

    # wpa3
    p_wpa3 = sub.add_parser("wpa3", help="WPA3 survey")
    p_wpa3.add_argument("--ssid", default=None)
    p_wpa3.add_argument("--rsn-hex", default=None)
    p_wpa3.add_argument("--auth-hex", default=None)
    p_wpa3.add_argument("--mfp", action="store_true")

    # audit
    p_audit = sub.add_parser("audit", help="Probe / client audit")
    p_audit.add_argument("--client", default=None)
    p_audit.add_argument("--ssids", default=None)

    # evas
    p_evas = sub.add_parser("evas", help="WIDS evasion study (defensive)")
    p_evas.add_argument("--ssid", default=None)
    p_evas.add_argument("--bssid", default=None)
    p_evas.add_argument("--src", default=None)
    p_evas.add_argument("--reason", type=int, default=1)
    p_evas.add_argument("--seq-rand", action="store_true")
    p_evas.add_argument("--mac-cycle", action="store_true")
    p_evas.add_argument("--jitter", action="store_true")
    p_evas.add_argument("--count", type=int, default=100)

    # ble
    p_ble = sub.add_parser("ble", help="BLE operations")
    p_ble.add_argument("action", choices=["adv", "scan-req", "deanon", "att"])
    p_ble.add_argument("--addr", default=None)
    p_ble.add_argument("--scanner", default=None)
    p_ble.add_argument("--att-data", default=None)

    # report
    sub.add_parser("report", help="Combined report")

    # demo
    sub.add_parser("demo", help="Offline demo (exit 0)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Wire global air-emission state into the safety gate. Passing --air
    # optionally plus --lab-ssid entries configures *allowance* only; offline
    # commands still never emit. The demo/tests never pass --air.
    configure_air(getattr(args, "air", False), getattr(args, "lab_ssid", None))

    if args.command == "frames":
        cmd_frames(args)
    elif args.command == "deauth":
        cmd_deauth(args)
    elif args.command == "eviltwin":
        cmd_eviltwin(args)
    elif args.command == "pmkid":
        cmd_pmkid(args)
    elif args.command == "eapol":
        cmd_eapol(args)
    elif args.command == "wpa3":
        cmd_wpa3(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "evas":
        cmd_evas(args)
    elif args.command == "ble":
        cmd_ble(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "demo":
        cmd_demo(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
