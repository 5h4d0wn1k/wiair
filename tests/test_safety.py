"""Safety gate tests — ensures air emission is refused without --air + allowlist."""

import unittest

from wiair.safety import (
    require_air, ALLOWED_LAB_SSIDS, register_lab_ssid,
    AIR_ENABLED, configure_air, DEFAULT_ALLOWED_LAB_SSIDS,
)


class TestSafetyGate(unittest.TestCase):
    def setUp(self):
        configure_air(False, None)  # reset to offline everywhere

    def tearDown(self):
        configure_air(False, None)  # never leave air enabled

    def test_require_air_refuses(self):
        """require_air must always refuse without air flag."""
        with self.assertRaises(SystemExit):
            require_air("TestSSID")

    def test_register_ssid(self):
        """Registering an SSID adds it to the allowlist."""
        register_lab_ssid("lab-home")
        self.assertIn("lab-home", ALLOWED_LAB_SSIDS)

    def test_require_air_refuses_even_registered(self):
        """require_air refuses without --air even if SSID is allowlisted."""
        register_lab_ssid("lab-test")
        with self.assertRaises(SystemExit):
            require_air("lab-test")

    def test_gate_requires_both_air_and_allowlist(self):
        """--air alone (no matching allowlist) must still refuse."""
        configure_air(True, None)  # --air present, but ssid not allowlisted
        with self.assertRaises(SystemExit):
            require_air("not-in-lab")

    def test_gate_passes_with_air_and_allowlisted_ssid(self):
        """Explicit --air + allowlisted SSID satisfies the gate (stub)."""
        configure_air(True, ["lab-home"])
        require_air("lab-home")  # must not raise

    def test_gate_refuses_partial(self):
        """--lab-ssid without --air must refuse."""
        configure_air(False, ["lab-home"])
        with self.assertRaises(SystemExit):
            require_air("lab-home")

    def test_defaults_are_placeholders(self):
        self.assertIn("lab-home", DEFAULT_ALLOWED_LAB_SSIDS)
        self.assertNotIn("00:11:22:33:44:55", DEFAULT_ALLOWED_LAB_SSIDS)


if __name__ == "__main__":
    unittest.main()
