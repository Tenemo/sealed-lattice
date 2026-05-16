#!/usr/bin/env python3
"""Build upstream LaZer and emit sealed-lattice public vectors."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def run_command(command: list[str], cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def require_nonempty_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"Required oracle input is missing or empty: {path}")


def run_oracle(repo_root: Path, lazer_root: Path, out_path: Path) -> None:
    require_nonempty_file(lazer_root / "python" / "demo" / "demo_params.h")

    run_command(["make", "-B", "lazer.h"], cwd=lazer_root)
    require_nonempty_file(lazer_root / "lazer.h")

    run_command(["make", "liblazer.so"], cwd=lazer_root)
    run_command(["make"], cwd=lazer_root / "python")
    run_command(
        ["python3", "../params_cffi_build.py", "demo_params.h", "../.."],
        cwd=lazer_root / "python" / "demo",
    )
    run_command(
        [
            "python3",
            str(repo_root / "tools" / "lazer-oracle" / "vector-emitter" / "emit_linear_vectors.py"),
            "--repo-root",
            str(repo_root),
            "--lazer-root",
            str(lazer_root),
            "--out",
            str(out_path),
        ],
        cwd=lazer_root / "python" / "demo",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--lazer-root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    run_oracle(
        repo_root=Path(args.repo_root),
        lazer_root=Path(args.lazer_root),
        out_path=Path(args.out),
    )


if __name__ == "__main__":
    main()
