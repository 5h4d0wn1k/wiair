"""WIDS evasion study tests."""

import unittest

from wiair.frames.ieee80211 import build_deauth
from wiair.evasion.wids import evaluate_evasion, detectability_score, EvasionParams


class TestEvasionDetectability(unittest.TestCase):
    def test_no_evasion_high(self):
        params = EvasionParams()
        score = detectability_score(params)
        self.assertGreater(score["detectability"], 0.8)
        self.assertEqual(score["risk_level"], "HIGH")

    def test_seq_randomize(self):
        params_no = EvasionParams()
        params_yes = EvasionParams(seq_randomize=True)
        score_no = detectability_score(params_no)
        score_yes = detectability_score(params_yes)
        self.assertLess(score_yes["detectability"], score_no["detectability"])

    def test_mac_cycling(self):
        params = EvasionParams(mac_cycling=True)
        score = detectability_score(params)
        self.assertLess(score["detectability"], 0.95)

    def test_all_evasion(self):
        params = EvasionParams(
            seq_randomize=True,
            mac_cycling=True,
            interval_jitter=True,
            fragment=True,
        )
        score = detectability_score(params, num_frames=50)
        self.assertLess(score["detectability"], 0.5)


class TestEvaluateEvasion(unittest.TestCase):
    def test_full_evaluation(self):
        deauth = build_deauth(bssid="00:11:22:33:44:55",
                              src="AA:BB:CC:DD:EE:FF",
                              dst="ff:ff:ff:ff:ff:ff",
                              reason=1)
        raw = deauth.to_bytes()
        result = evaluate_evasion(raw, seq_randomize=True, num_frames=50)
        self.assertIn("original_frame", result)
        self.assertIn("detection_analysis", result)
        self.assertIn("recommendation", result)
        self.assertTrue(result["detection_analysis"]["defense_evaluation"])

    def test_defense_label(self):
        deauth = build_deauth(bssid="00:11:22:33:44:55",
                              src="AA:BB:CC:DD:EE:FF",
                              dst="ff:ff:ff:ff:ff:ff",
                              reason=1)
        result = evaluate_evasion(deauth.to_bytes())
        self.assertIn("DEFENSIVE STUDY", result["detection_analysis"]["label"])


if __name__ == "__main__":
    unittest.main()
