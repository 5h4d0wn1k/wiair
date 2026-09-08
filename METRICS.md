# Metrics

Measured on: Python 3.13.5, Linux x86_64 — `python -m unittest discover -s tests`
and `python -m wiair demo` (offline, no live RF).

## Test Suite

| Metric | Value |
|--------|-------|
| Total tests | 100 |
| Tests passing | 100 |
| Test runtime (unittest) | 0.99s (1.64s incl. discovery startup) |
| Modules tested | 9 (frames, deauth, eviltwin, pmkid, wpa3, probe_audit, evasion, ble, safety) |
| Demo exit code | 0 (all proofs passed) |
| Demo wall time | 0.34s |

## Frame Library

| Operation | Value |
|-----------|-------|
| Beacon build+parse roundtrip (demonet) | 88 bytes, FCS verified true |
| Deauth frame (24 hdr + 2 reason + 4 FCS) | 30 bytes |
| Probe request | 47 bytes |
| Auth (open system) | 34 bytes |
| Association request | 71 bytes |
| Association response | 46 bytes |
| Reason codes supported | 13 (0x01–0x0D), all roundtrip-decode |
| SSID encoding | UTF-8, up to 32 bytes |
| CRC-32 802.11 | 0xEDB88320 reflected, byte-exact verify |

## Deauth Engine

| Operation | Value |
|-----------|-------|
| Simulated storm frames | 13 causes × N repeats, rate-limited (≤ 100 f/s) |
| Live `emit=True` | Always refused by `require_air()` (no --air in demo/tests) |

## PMKID Pipeline

| Operation | Value |
|-----------|-------|
| EAPOL 4-way fixture | 4 frames (M1..M4), synthetic |
| PMKID extraction | Byte-exact from M1 RSN KDE (verified `1011…1f`) |
| Hashcat 22000 format | `WPA*02*<pmkid>*<ap>*<client>***<essid>` |
| hcxpcapngtool format | `PMKID*<pmkid>*<ap>*<client>*<essid>` |
| Crack stub | Reports `ready_for_crack: true` (hashcat optional, skipped if absent) |

## WPA3 Survey

| Operation | Value |
|-----------|-------|
| SAE detection | Auth algo = 1, seq 1 = commit, 2 = confirm |
| Transition mode | Dual-AKM RSN (PSK 0x02 + SAE 0x08) → flagged `wpa2/wpa3_transition` |
| Posture scoring | 0–100, MFP bonus +10; demo transition = 85 |

## BLE

| Operation | Value |
|-----------|-------|
| CRC-24 polynomial | 0x00065B (BLE standard), init 0x555555 |
| ADV_IND PDU | 10 bytes (type + addr6 + CRC3), CRC verified |
| SCAN_REQ PDU | 16 bytes |
| ATT opcodes parsed | 12 (error, mtu, find-info req/rsp, read-by-type, read rsp, write, notify, indicate, …) |

## WIDS Evasion (defensive study)

| Operation | Value |
|-----------|-------|
| Base detectability (no evasion) | 0.95 → HIGH |
| Seq randomization | -40% |
| MAC cycling | -25% (with +10% OUI penalty) |
| Label | `WIDS-EVASION DEFENSIVE STUDY — NOT FOR OFFENSIVE USE` |

## Probe / Client Audit

| Operation | Value |
|-----------|-------|
| Probe fixture build | 1 probe per SSID, per client |
| Hidden-SSID discovery | Any probed SSID listed as discovered |
| Privacy risk | 0–100 from leaked SSID count + hidden exposure |

## CLI

| Subcommand | Exit | Output |
|------------|------|--------|
| `frames beacon/deauth/probe/auth/assoc-req/assoc-resp` | 0 | JSON + roundtrip proof |
| `deauth` | 0 | Storm summary + reason table |
| `eviltwin` | 0 | POC pcap (beacon→probe→auth) + portal HTML |
| `pmkid` | 0 | hashcat + hcx format lines |
| `eapol` | 0 | Parsed handshake frames + PMKID + hashcat |
| `wpa3` | 0 | Posture markdown |
| `audit` | 0 | Client probe analysis |
| `evas` | 0 | Defensive evasion report |
| `ble` | 0 | PDU bytes + CRC verification + ATT parse |
| `report` | 0 | Combined JSON + markdown |
| `demo` | 0 | All 5 proofs printed, JSON saved |

## Safety Gates (measured)

| Gate | Result |
|------|--------|
| `require_air()` with no `--air` | REFUSED (`SystemExit`) |
| `--lab-ssid` alone (no `--air`) | REFUSED |
| `--air` with non-allowlisted SSID | REFUSED |
| `--air` + allowlisted lab-* SSID | Gate passes (stub; no live radio exists) |

## Identity

Placeholder MAC: 00:11:22:33:44:55
Placeholder SSIDs: lab-home, lab-wpa3, lab-ble
Identity: 5h4d0wn1k (pseudonym)