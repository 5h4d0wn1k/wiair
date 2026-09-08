"""Demo exit-0 verification test."""

import subprocess
import sys
import unittest


class TestDemo(unittest.TestCase):
    def test_demo_exit_0(self):
        """CLI --demo must exit 0 with proof output."""
        result = subprocess.run(
            [sys.executable, "-m", "wiair", "demo"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, f"demo failed:\n{result.stderr}")
        self.assertIn("DEMO COMPLETE", result.stdout)
        self.assertIn("NO live RF emission", result.stdout)


if __name__ == "__main__":
    unittest.main()
