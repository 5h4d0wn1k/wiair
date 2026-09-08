"""WPA3 survey tests."""

import unittest

from wiair.frames.ieee80211 import build_auth, encode_rsn
from wiair.wpa3.survey import (
    detect_sae_auth, detect_transition_mode, security_posture_score, survey_ap,
)


class TestSAEDetection(unittest.TestCase):
    def test_open_auth(self):
        auth = build_auth(bssid="00:11:22:33:44:55",
                          src="AA:BB:CC:DD:EE:FF",
                          dst="11:22:33:44:55:66")
        raw = auth.to_bytes()
        result = detect_sae_auth(raw)
        self.assertFalse(result["is_sae"])

    def test_sae_commit(self):
        auth = build_auth(bssid="00:11:22:33:44:55",
                          src="AA:BB:CC:DD:EE:FF",
                          dst="11:22:33:44:55:66",
                          auth_algo=1, auth_seq=1)
        raw = auth.to_bytes()
        result = detect_sae_auth(raw)
        self.assertTrue(result["is_sae"])
        self.assertEqual(result["sae_phase"], "commit")

    def test_sae_confirm(self):
        auth = build_auth(bssid="00:11:22:33:44:55",
                          src="AA:BB:CC:DD:EE:FF",
                          dst="11:22:33:44:55:66",
                          auth_algo=1, auth_seq=2)
        raw = auth.to_bytes()
        result = detect_sae_auth(raw)
        self.assertTrue(result["is_sae"])
        self.assertEqual(result["sae_phase"], "confirm")


class TestTransitionMode(unittest.TestCase):
    def test_wpa2_only(self):
        rsn = encode_rsn(psk=True)
        info = {"ssid": "Test", "ies": {"48": rsn[2:].hex()}}
        result = detect_transition_mode(info)
        self.assertTrue(result["wpa2_psk"])
        self.assertFalse(result["wpa3_sae"])
        self.assertEqual(result["security"], "wpa2_psk")

    def test_transition(self):
        rsn_psk = encode_rsn(psk=True)
        info = {"ssid": "Test", "ies": {"48": rsn_psk[2:].hex()}}
        result = detect_transition_mode(info)
        self.assertIn(result["security"], ["wpa2_psk", "wpa2/wpa3_transition"])

    def test_open(self):
        info = {"ssid": "Open", "ies": {}}
        result = detect_transition_mode(info)
        self.assertEqual(result["security"], "open_or_wep")


class TestPostureScore(unittest.TestCase):
    def test_wpa3_score(self):
        transition = {"security": "wpa3_sae"}
        posture = security_posture_score(transition)
        self.assertEqual(posture["score"], 95)

    def test_wpa2_score(self):
        transition = {"security": "wpa2_psk"}
        posture = security_posture_score(transition)
        self.assertEqual(posture["score"], 60)

    def test_mfp_bonus(self):
        transition = {"security": "wpa2_psk"}
        posture = security_posture_score(transition, has_mfp=True)
        self.assertEqual(posture["score"], 70)

    def test_recommendation(self):
        transition = {"security": "wpa3_sae"}
        posture = security_posture_score(transition)
        self.assertIn("Strong", posture["recommendation"])


class TestSurveyAP(unittest.TestCase):
    def test_survey_with_sae(self):
        sae_commit = build_auth(bssid="00:11:22:33:44:55",
                                src="AA:BB:CC:DD:EE:FF",
                                dst="11:22:33:44:55:66",
                                auth_algo=1, auth_seq=1)
        rsn = encode_rsn(psk=True)
        beacon_info = {"ssid": "TestAP", "ies": {"48": rsn[2:].hex()}}
        result = survey_ap([sae_commit.to_bytes()], beacon_info)
        self.assertTrue(result["sae_detected"])
        self.assertEqual(len(result["sae_frames"]), 1)
        self.assertEqual(result["beacon_ssid"], "TestAP")


if __name__ == "__main__":
    unittest.main()
