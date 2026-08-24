"""Run the pinned lattice-estimator attacks for the selected suite input.

The TypeScript evidence runner owns source derivation, process orchestration,
and output validation. This file is only the Sage-dependent calculation that
must execute inside the pinned container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any


ATTACK_IDENTIFIERS = (
    "primalUsvp",
    "primalBdd",
    "dual",
    "dualHybrid",
)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_payload_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def source_tree_sha256(source_root: Path) -> str:
    digest = hashlib.sha256()
    paths = sorted(
        (
            path
            for path in source_root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(source_root).parts
        ),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    for path in paths:
        digest.update(path.relative_to(source_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def require_text(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"{description} must be nonempty text")
    return value


def require_positive_integer(value: Any, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RuntimeError(f"{description} must be a positive integer")
    return value


def require_nonnegative_integer(value: Any, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeError(f"{description} must be a nonnegative integer")
    return value


def require_runtime(input_payload: dict[str, Any]) -> None:
    estimator = input_payload.get("estimator")
    if not isinstance(estimator, dict):
        raise RuntimeError("estimator provenance is missing")
    expected_revision = require_text(estimator.get("revision"), "estimator revision")
    expected_source_tree = require_text(
        estimator.get("sourceTreeSha256"),
        "estimator source-tree digest",
    )
    expected_container = require_text(
        estimator.get("containerImageReference"),
        "estimator container image",
    )
    expected_sage_version = require_text(
        estimator.get("sageVersion"),
        "Sage version",
    )
    if os.environ.get("SEALED_LATTICE_ESTIMATOR_REVISION") != expected_revision:
        raise RuntimeError("the estimator revision environment binding is wrong")
    if (
        os.environ.get("SEALED_LATTICE_ESTIMATOR_CONTAINER_IMAGE")
        != expected_container
    ):
        raise RuntimeError("the estimator container environment binding is wrong")
    source_root_value = os.environ.get("SEALED_LATTICE_ESTIMATOR_SOURCE_ROOT")
    if source_root_value is None:
        raise RuntimeError("SEALED_LATTICE_ESTIMATOR_SOURCE_ROOT is required")
    if source_tree_sha256(Path(source_root_value)) != expected_source_tree:
        raise RuntimeError("the mounted estimator source tree is not the pinned tree")

    from sage.version import version as sage_version  # type: ignore[import-not-found]

    if sage_version != expected_sage_version:
        raise RuntimeError(
            f"expected Sage {expected_sage_version}, found {sage_version}"
        )


def conservative_decimal_lower_bound(value: float, decimal_places: int = 12) -> float:
    scale = 10**decimal_places
    return math.floor(value * scale) / scale


def run_estimates(input_payload: dict[str, Any]) -> list[dict[str, Any]]:
    require_runtime(input_payload)

    from estimator import LWE, ND  # type: ignore[import-not-found]
    from estimator.reduction import MATZOV  # type: ignore[import-not-found]
    from sage.all import log  # type: ignore[import-not-found]

    topology = input_payload.get("topology")
    if not isinstance(topology, dict):
        raise RuntimeError("topology is missing")
    polynomial_degree = require_positive_integer(
        topology.get("polynomialDegree"),
        "polynomial degree",
    )
    diagnostic_cases = input_payload.get("diagnosticCases")
    if not isinstance(diagnostic_cases, list) or not diagnostic_cases:
        raise RuntimeError("diagnostic cases must be a nonempty list")

    attack_functions = {
        "primalUsvp": LWE.primal_usvp,
        "primalBdd": LWE.primal_bdd,
        "dual": LWE.dual,
        "dualHybrid": LWE.dual_hybrid,
    }
    reduction_cost_models = {
        "classical": MATZOV(nn="classical"),
        "quantum": MATZOV(nn="list_decoding-naive_quantum"),
    }
    secret_distribution = ND.Ternary
    error_distribution = ND.CenteredBinomial(2)

    estimates: list[dict[str, Any]] = []
    for case in diagnostic_cases:
        if not isinstance(case, dict):
            raise RuntimeError("each diagnostic case must be an object")
        identifier = require_text(case.get("identifier"), "case identifier")
        modulus_text = require_text(case.get("modulus"), "case modulus")
        scalar_sample_count = require_positive_integer(
            case.get("scalarSampleCount"),
            "scalar sample count",
        )
        parameters = LWE.Parameters(
            n=polynomial_degree,
            q=int(modulus_text),
            Xs=secret_distribution,
            Xe=error_distribution,
            m=scalar_sample_count,
            tag=identifier,
        )
        model_results: dict[str, Any] = {}
        for model_identifier, reduction_cost_model in reduction_cost_models.items():
            attack_results: dict[str, Any] = {}
            unrounded_minimum = math.inf
            for attack_identifier in ATTACK_IDENTIFIERS:
                result = attack_functions[attack_identifier](
                    parameters,
                    red_cost_model=reduction_cost_model,
                )
                security_bits = float(log(result["rop"], 2))
                if not math.isfinite(security_bits) or security_bits <= 0:
                    raise RuntimeError(
                        f"{identifier} {model_identifier} {attack_identifier} returned an invalid cost"
                    )
                unrounded_minimum = min(unrounded_minimum, security_bits)
                attack_result: dict[str, Any] = {
                    "securityBitsLowerBound": conservative_decimal_lower_bound(
                        security_bits
                    ),
                    "blockSize": int(result["beta"]),
                }
                if "d" in result:
                    attack_result["latticeDimension"] = int(result["d"])
                if "m" in result:
                    attack_result["usedScalarSamples"] = int(result["m"])
                attack_results[attack_identifier] = attack_result
            model_results[model_identifier] = {
                "attacks": attack_results,
                "minimumSecurityBitsLowerBound": conservative_decimal_lower_bound(
                    unrounded_minimum
                ),
            }
        estimates.append(
            {
                "identifier": identifier,
                "catalogLevel": require_nonnegative_integer(
                    case.get("catalogLevel"),
                    "catalog level",
                ),
                "basis": require_text(case.get("basis"), "case basis"),
                "modulusLog2LowerBound": conservative_decimal_lower_bound(
                    float(log(int(modulus_text), 2))
                ),
                "ringRelationCount": require_positive_integer(
                    case.get("ringRelationCount"),
                    "ring relation count",
                ),
                "scalarSampleCount": scalar_sample_count,
                "models": model_results,
            }
        )
    return estimates


def build_record(input_payload: dict[str, Any]) -> dict[str, Any]:
    estimates = run_estimates(input_payload)
    minimum_classical_security_bits = min(
        estimate["models"]["classical"]["minimumSecurityBitsLowerBound"]
        for estimate in estimates
    )
    minimum_quantum_security_bits = min(
        estimate["models"]["quantum"]["minimumSecurityBitsLowerBound"]
        for estimate in estimates
    )
    record: dict[str, Any] = {
        "recordKind": "selected-lattice-security-estimator-evidence",
        "recordVersion": 1,
        "inputPayloadSha256": canonical_payload_sha256(input_payload),
        "input": input_payload,
        "estimates": estimates,
        "summary": {
            "minimumClassicalSecurityBitsLowerBound": minimum_classical_security_bits,
            "minimumQuantumSecurityBitsLowerBound": minimum_quantum_security_bits,
            "materialSuccessThreshold": "at least one half",
            "scope": (
                "Known-attack scalar-LWE diagnostics under the explicitly named "
                "proxy model; reductions and joint structured or circular security "
                "remain separate assumptions."
            ),
        },
    }
    record["outputPayloadSha256"] = canonical_payload_sha256(record)
    return record


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    input_payload = json.loads(arguments.input.read_text(encoding="utf-8"))
    if not isinstance(input_payload, dict):
        raise RuntimeError("the estimator input root must be an object")
    print(json.dumps(build_record(input_payload), indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
