"""Exercise the public downloadable kit without recording any human answers."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

class PilotTest(unittest.TestCase):
    def test_independent_packets(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with zipfile.ZipFile(HERE / "pilot-16.zip") as kit:
                kit.extractall(root)
            subprocess.run([sys.executable, "-B", "organize.py"], cwd=root, check=True,
                           stdout=subprocess.DEVNULL)
            batch = root / "SPE_PILOT_16"
            self.assertTrue((batch / "COORDINATION/coordinator.json").is_file())
            allocations = []
            for role in ("A", "B"):
                with zipfile.ZipFile(batch / f"REVISOR_{role}.zip") as packet:
                    self.assertFalse(any("coordinator" in name or "labels" in name for name in packet.namelist()))
                    packet.extractall(root / role)
                con = sqlite3.connect(root / role / f"{role}.sqlite")
                try:
                    cards = con.execute("SELECT ticket, card FROM items ORDER BY pos").fetchall()
                    self.assertEqual(con.execute("SELECT COUNT(*) FROM answers").fetchone(), (0,))
                finally:
                    con.close()
                self.assertEqual(len(cards), 16)
                items = [json.loads(raw) for _, raw in cards]
                self.assertEqual(sum(item["language"] == "es" for item in items), 8)
                self.assertEqual(len({item["event"] for item in items}), 6)
                allocations.append(cards)
            a, b = allocations
            self.assertTrue({r[0] for r in a}.isdisjoint(r[0] for r in b))
            self.assertEqual(sorted(c for _, c in a), sorted(c for _, c in b))
            self.assertNotEqual([c for _, c in a], [c for _, c in b])

if __name__ == "__main__":
    unittest.main()
