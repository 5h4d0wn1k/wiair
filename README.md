# wiair

Wireless offensive framework — byte-exact 802.11/BLE frame craft+parse, offline-only safety-gated

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

---

## Quickstart

```bash
python3 -m pip install -e .
python3 -m wiair --help
python3 -m wiair demo    # offline, exit 0
python3 -m unittest discover -s tests
```

## Modules

| Module | Description |
|--------|-------------|
| `frames` | 802.11 beacon/probe/auth/deauth/association builders + parsers with CRC-32 FCS |
| `deauth` | Deauth storm simulator with reason-code table, rate-limited |
| `eviltwin` | Cloned-SSID beacon + probe-response builder, POC pcap, portal HTML stub |
| `pmkid` | EAPOL 4-way handshake builder/parser, PMKID extraction, hashcat 22000 format |
| `wpa3` | SAE (WPA3) handshake detection, WPA2/WPA3/OWE transition scoring |
| `probe_audit` | Probe-request capture fixtures, hidden-SSID discovery, client privacy analysis |
| `evasion` | WIDS-evasion defensive study with heuristic detectability scoring |
| `ble` | ADV_IND/SCAN_REQ PDU construction (CRC-24), MAC de-anonymization study, ATT parse |
| `safety` | Regulatory gates: `require_air()` refuses emission without `--air --lab-ssid` |

## Live Lab Test Plan

> **All testing must be performed on your own airspace and your own devices only.**

| Test | Device | SSID | Expected | Proof |
|------|--------|------|----------|-------|
| Beacon injection | Own AP | lab-home | Beacon visible in Wireshark | pcap dump |
| Deauth storm | Own client | lab-home | Client disconnected | reassociation log |
| Evil twin | Own device | lab-home | Captive portal served | HTTP 200 + HTML |
| PMKID capture | Own AP | lab-home | Hashcat line valid | `hashcat --test` |
| BLE scan | Own BLE device | N/A | ADV_IND decoded | pcap parse |
| WPA3 survey | Own WPA3 AP | lab-wpa3 | SAE detected | posture score ≥ 90 |

All SSIDs above are placeholders. Replace with your own lab SSIDs.

## Metrics

See [METRICS.md](METRICS.md) for measured values.

## Safety Gates

1. **`require_air()` guard**: Any code path that would emit RF is gated behind
   `require_air(ssid)` which raises `SystemExit` unless `--air --lab-ssid <allowlist>`
   is explicitly provided on the command line.
2. **Deauth emission**: The deauth storm simulator accepts an `emit` parameter that
   is `False` by default. Setting `emit=True` without `--air` raises `SystemExit`.
3. **No live radio code**: All frame construction is done in pure Python bytes.
   There is no `scapy.sendrecv`, no `socket`, no `ioctl` in any code path.
   Scapy is listed as an optional dependency for advanced analysis, never for emission.
4. **Offline-only by default**: Every subcommand operates on in-memory bytes or
   fixture pcap files. No network or RF interaction is possible in default mode.
