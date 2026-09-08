"""Safety gates — regulatory, allowlist, air-emission guards.

Live RF emission is hardware-gated. `require_air(ssid)` refuses (raises
SystemExit) unless *both* of the following are true:

1. The user passed `--air` on the command line (explicit confirmation), AND
2. `ssid` is a member of the configured LAB allowlist (populated from
   `--lab-ssid <entry>`, defaulting to the placeholder lab-* entries below).

There is NO live radio code in this tree; no code path that emits RF exists.
This gate exists so that any *future* hardware-backed emission path cannot be
triggered accidentally from tests or the demo (which never pass `--air`).
"""

# Placeholder lab SSIDs — replace with your own owned lab identifiers.
# Never point this framework at third-party networks.
DEFAULT_ALLOWED_LAB_SSIDS: frozenset[str] = frozenset({
    "lab-home",
    "lab-wpa3",
    "lab-ble",
    "lab-iot",
    "lab-office",
})

# Global CLI state — set by `main()` from `--air` / `--lab-ssid`.
AIR_ENABLED: bool = False
ALLOWED_LAB_SSIDS: set[str] = set(DEFAULT_ALLOWED_LAB_SSIDS)


def register_lab_ssid(ssid: str) -> None:
    """Add an SSID to the LAB allowlist."""
    ALLOWED_LAB_SSIDS.add(ssid)


def configure_air(air_enabled: bool, lab_ssids: list[str] | None = None) -> None:
    """Set the CLI air-emission state from --air / --lab-ssid.

    lab_ssids is the list of `--lab-ssid` values given (may be empty).
    The allowlist always contains the placeholder defaults; passing
    `--lab-ssid` entries adds to them, but the caller must still
    pass `--air` for the gate to pass.
    """
    global AIR_ENABLED
    AIR_ENABLED = bool(air_enabled)
    if lab_ssids:
        ALLOWED_LAB_SSIDS.update(lab_ssids)


def require_air(ssid: str) -> None:
    """Refuse live RF emission unless --air AND allowlist entry both given.

    Raises SystemExit with a clear regulatory notice otherwise. Lifecycle:
    - tests / demo never pass --air, so this ALWAYS refuses there.
    - a future hardware path may only proceed after explicit --air + allowlist.
    """
    if not AIR_ENABLED:
        raise SystemExit(
            "REFUSED: live RF emission requires --air --lab-ssid <allowed>. "
            "No --air confirmation given. This is an offline-only framework "
            "by default. See README (IMPORTANT: Read before use.)."
        )
    if ssid not in ALLOWED_LAB_SSIDS:
        raise SystemExit(
            f"REFUSED: '{ssid}' is not in the LAB allowlist. live RF emission "
            "requires --lab-ssid <allowed-entry>. Test only your OWN airspace "
            "and devices. See README (IMPORTANT: Read before use.)."
        )
    # NOTE: even when the gate passes, no live radio driver exists yet.
    # Emission remains a documented future-hardware stub.
