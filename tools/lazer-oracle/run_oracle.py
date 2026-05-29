#!/usr/bin/env python3
"""Build upstream LaZer and emit a selected sealed-lattice vector profile."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


PROFILE_CONFIGS = {
    "demo-linear": {
        "emitter": "emit_linear_vectors.py",
        "header": "demo_params.h",
        "parameter_header": "demo_params.h",
    },
    "receiver-key-linear": {
        "emitter": "emit_receiver_key_linear_vectors.py",
        "header": "receiver_key_params.h",
        "parameter_header": "receiver_key_params.h",
    },
    "ballot-field-linear": {
        "emitter": "emit_ballot_field_linear_vectors.py",
        "header": "ballot_field_params.h",
        "parameter_header": "ballot_field_params.h",
        "requires_input": True,
    },
}


def run_command(command: list[str], working_directory: Path) -> None:
    subprocess.run(command, cwd=working_directory, check=True)


def require_nonempty_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"Required oracle input is missing or empty: {path}")


def run_oracle(
    *,
    repo_root: Path,
    lazer_root: Path,
    oracle_input_path: Path | None,
    out_path: Path,
    profile: str,
) -> None:
    profile_config = PROFILE_CONFIGS[profile]
    demo_directory = lazer_root / "python" / "demo"
    require_nonempty_file(demo_directory / profile_config["header"])
    if profile_config.get("requires_input", False):
        if oracle_input_path is None:
            raise RuntimeError(f"{profile} requires --input.")
        require_nonempty_file(oracle_input_path)

    run_command(["make", "-B", "lazer.h"], working_directory=lazer_root)
    require_nonempty_file(lazer_root / "lazer.h")

    run_command(["make", "liblazer.so"], working_directory=lazer_root)
    run_command(["make"], working_directory=lazer_root / "python")
    run_command(
        [
            "python3",
            "../params_cffi_build.py",
            profile_config["parameter_header"],
            "../..",
        ],
        working_directory=demo_directory,
    )
    emitter_command = [
        "python3",
        str(
            repo_root
            / "tools"
            / "lazer-oracle"
            / "vector-emitter"
            / profile_config["emitter"]
        ),
        "--repo-root",
        str(repo_root),
        "--lazer-root",
        str(lazer_root),
        "--out",
        str(out_path),
    ]
    if oracle_input_path is not None:
        emitter_command.extend(["--input", str(oracle_input_path)])
    run_command(emitter_command, working_directory=demo_directory)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=sorted(PROFILE_CONFIGS), required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--lazer-root", required=True)
    parser.add_argument("--input")
    parser.add_argument("--out", required=True)
    parsed_arguments = parser.parse_args()

    run_oracle(
        repo_root=Path(parsed_arguments.repo_root),
        lazer_root=Path(parsed_arguments.lazer_root),
        oracle_input_path=(
            None
            if parsed_arguments.input is None
            else Path(parsed_arguments.input)
        ),
        out_path=Path(parsed_arguments.out),
        profile=parsed_arguments.profile,
    )


if __name__ == "__main__":
    main()
