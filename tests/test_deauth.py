"""Deauth engine tests."""

import unittest

from wiair.deauth.engine import (
    DeauthStormConfig, craft_deauth_frames, simulate_storm,
    deauth_frame_info, storm_summary, reason_table,
)
from wiair.frames.ieee80211 import parse_deauth


class TestDeauthCraft(unittest.TestCase):
    def test_single_reason(self):
        config = DeauthStormConfig(
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
            reason_start=1,
            reason_end=1,
            count_per_reason=1,
        )
        frames = craft_deauth_frames(config)
        self.assertEqual(len(frames), 1)
        parsed = parse_deauth(frames[0])
        self.assertEqual(parsed["reason"], 1)

    def test_all_reasons(self):
        config = DeauthStormConfig(
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
            reason_start=1,
            reason_end=13,
            count_per_reason=1,
        )
        frames = craft_deauth_frames(config)
        self.assertEqual(len(frames), 13)
        for i, raw in enumerate(frames):
            parsed = parse_deauth(raw)
            self.assertEqual(parsed["reason"], i + 1)

    def test_repeats(self):
        config = DeauthStormConfig(
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
            reason_start=1,
            reason_end=3,
            count_per_reason=5,
        )
        frames = craft_deauth_frames(config)
        self.assertEqual(len(frames), 15)


class TestDeauthStorm(unittest.TestCase):
    def test_simulate_offline(self):
        config = DeauthStormConfig(
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
            reason_start=1,
            reason_end=3,
            count_per_reason=2,
        )
        results = simulate_storm(config)
        self.assertEqual(len(results), 6)
        for r in results:
            self.assertIn("reason", r)
            self.assertIn("total_bytes", r)

    def test_storm_summary(self):
        config = DeauthStormConfig(
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
            reason_start=1,
            reason_end=13,
            count_per_reason=3,
        )
        results = simulate_storm(config)
        summary = storm_summary(results)
        self.assertEqual(summary["total_frames"], 39)
        self.assertEqual(summary["unique_reasons"], 13)

    def test_frame_info(self):
        config = DeauthStormConfig(
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
            reason_start=1,
            reason_end=1,
            count_per_reason=1,
        )
        frames = craft_deauth_frames(config)
        info = deauth_frame_info(frames[0])
        self.assertIn("reason", info)
        self.assertIn("fcs_present", info)

    def test_reason_table(self):
        table = reason_table()
        self.assertEqual(len(table), 13)
        self.assertIn(0x01, table)
        self.assertIn(0x0D, table)


class TestDeauthSafety(unittest.TestCase):
    def test_emit_refused(self):
        """Emission without --air must fail."""
        config = DeauthStormConfig(
            bssid="00:11:22:33:44:55",
            src="AA:BB:CC:DD:EE:FF",
        )
        with self.assertRaises(SystemExit):
            simulate_storm(config, emit=True)


if __name__ == "__main__":
    unittest.main()
