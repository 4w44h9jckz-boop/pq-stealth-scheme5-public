"""Standard test-runner entry point for the standalone tooling self-tests."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ToolSelfTests(unittest.TestCase):
    """Run each executable self-test and preserve its diagnostics on failure."""

    def run_script(self, name: str) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / name)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"{result.stdout}\n{result.stderr}".strip(),
        )

    def test_derive_sizes(self) -> None:
        self.run_script("test-derive-sizes.py")

    def test_gen_vectors(self) -> None:
        self.run_script("test-gen-vectors.py")

    def test_check_measured(self) -> None:
        self.run_script("test-check-measured.py")

    def test_check_shared(self) -> None:
        """The shared files match the manifest, and a one-byte change is reported."""
        self.run_script("check_shared.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("tools", "crates/core", "crates/ec", "crates/kem", "contracts",
                         "vectors/tier1", "harness"):
                shutil.copytree(ROOT / name, root / name,
                                ignore=shutil.ignore_patterns("__pycache__", "target"))
            victim = root / "crates/ec/src/lib.rs"
            victim.write_bytes(victim.read_bytes().replace(b"0x02", b"0x12", 1))
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/check_shared.py"), "--root", str(root)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)
            self.assertIn("differs: crates/ec/src/lib.rs", result.stdout)


if __name__ == "__main__":
    unittest.main()
