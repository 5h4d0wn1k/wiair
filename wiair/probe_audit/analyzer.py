"""Probe / client audit — passive client analyzer.

Build probe-request capture fixtures, expose hidden-SSID discovery,
client probe leaks.
"""

from dataclasses import dataclass, field
from typing import Optional

from wiair.frames.ieee80211 import (
    build_probe_req,
    parse_probe_req,
    mac_bytes,
)


@dataclass
class ProbeRecord:
    src_mac: str
    ssid: str
    sequence: int
    raw_hex: str = ""


@dataclass
class ClientProfile:
    mac: str
    probed_ssids: list[str] = field(default_factory=list)
    probe_count: int = 0
    hidden_ssids: list[str] = field(default_factory=list)
    is_hidden_exposed: bool = False


def build_probe_fixture(client_mac: str, ssids: list[str],
                        seq_start: int = 1) -> list[bytes]:
    """Build probe request frames for each SSID."""
    frames = []
    for i, ssid in enumerate(ssids):
        f = build_probe_req(ssid=ssid, src=client_mac, seq_num=seq_start + i)
        frames.append(f.to_bytes())
    return frames


def analyze_probe_requests(probe_frames: list[bytes]) -> dict:
    """Analyze a list of raw probe request frames.

    Returns profiles of clients and their leaked SSIDs.
    """
    clients: dict[str, ClientProfile] = {}
    hidden_ssids_found: set[str] = set()

    for raw in probe_frames:
        info = parse_probe_req(raw)
        mac = info["src"]
        ssid = info["ssid"]

        if mac not in clients:
            clients[mac] = ClientProfile(mac=mac)
        cp = clients[mac]
        cp.probe_count += 1

        if ssid and ssid not in cp.probed_ssids:
            cp.probed_ssids.append(ssid)
        elif not ssid:
            cp.is_hidden_exposed = True

    # Hidden SSID discovery: if a client probes for a hidden network
    for cp in clients.values():
        for ssid in cp.probed_ssids:
            # Any SSID in probe is a "discovered" hidden network
            if ssid not in hidden_ssids_found:
                cp.hidden_ssids.append(ssid)
                hidden_ssids_found.add(ssid)

    return {
        "total_probes": len(probe_frames),
        "unique_clients": len(clients),
        "hidden_ssids_discovered": list(hidden_ssids_found),
        "clients": {
            mac: {
                "mac": cp.mac,
                "probed_ssids": cp.probed_ssids,
                "probe_count": cp.probe_count,
                "is_hidden_exposed": cp.is_hidden_exposed,
            }
            for mac, cp in clients.items()
        },
    }


def privacy_risk(analysis: dict) -> dict:
    """Evaluate privacy risk from client probe behavior."""
    total_clients = analysis["unique_clients"]
    exposed = sum(1 for c in analysis["clients"].values() if c["is_hidden_exposed"])
    ssid_leakers = sum(1 for c in analysis["clients"].values() if len(c["probed_ssids"]) > 0)

    risk_score = 0
    if total_clients > 0:
        risk_score = int((exposed + ssid_leakers) / total_clients * 100)

    return {
        "risk_score": min(100, risk_score),
        "clients_total": total_clients,
        "clients_leaking_ssids": ssid_leakers,
        "clients_with_hidden_exposure": exposed,
        "recommendation": (
            "Disable auto-connect/probe to avoid leaking preferred network lists."
            if risk_score > 50 else
            "Client probe behavior is within normal range."
        ),
    }
