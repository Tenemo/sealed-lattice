#!/usr/bin/env python3
"""Emit public-only encoded-score field-row LaZer proof vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import shutil
from pathlib import Path
from typing import Any

from emit_linear_vectors import (
    build_trace,
    bytes_hex,
    coefficients_to_matrix,
    coefficients_to_vector,
    import_lazer_python,
    mutate_matrix,
    mutate_proof_byte,
    mutate_vector,
    require_upstream_rejection,
    run_command,
    sha256_file,
    verify_with_upstream,
)


VECTOR_PROFILE_ID = "encoded-score-field-linear-compatibility-v1"
REQUIRED_CASE_NAMES = [
    "valid-encoded-score-field-linear-proof",
    "mutated-encoded-score-field-statement-matrix",
    "mutated-encoded-score-field-target-vector",
    "mutated-encoded-score-field-proof-byte",
    "wrong-encoded-score-field-public-randomness",
    "truncated-encoded-score-field-proof",
    "extended-encoded-score-field-proof",
    "noncanonical-encoded-score-field-coefficient-encoding",
]

SOURCE_RING_DEGREE = 64
PROOF_RING_DEGREE = 64
SOURCE_COEFFICIENT_MODULUS = 65537
STATEMENT_ROWS = 70
STATEMENT_COLUMNS = 176
WITNESS_L2_BOUND_SQUARED = 65536


def require_nonempty_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"Required oracle input is missing or empty: {path}")


def require_nonempty_glob(directory: Path, pattern: str) -> None:
    matching_paths = list(directory.glob(pattern))
    if not matching_paths or any(path.stat().st_size == 0 for path in matching_paths):
        raise RuntimeError(
            f"Required oracle input matching {pattern} is missing or empty in {directory}"
        )


def proof_encoding_contract(proof: bytes) -> dict[str, Any]:
    return {
        "profileId": "encoded-score-field-linear-proof-encoding-v1",
        "ringDegree": PROOF_RING_DEGREE,
        "coefficientModulus": "70368744177829",
        "fullSizeCoefficientBitLength": 47,
        "compressedCoefficientBitLength": 35,
        "targetCommitmentVectorLength": 12,
        "hashMaskVectorLength": 2,
        "compressedCommitmentVectorLength": 18,
        "challengeCoefficientModulus": 17,
        "challengeCoefficientBitLength": 5,
        "hintVectorLength": 18,
        "shortResponseVectorLength": 177,
        "randomnessResponseVectorLength": 41,
        "euclideanResponseVectorLength": 4,
        "infinityResponseVectorLength": 4,
        "shortResponseLog2StandardDeviation": 18,
        "randomnessResponseLog2StandardDeviation": 12,
        "euclideanResponseLog2StandardDeviation": 14,
        "infinityResponseLog2StandardDeviation": 22,
        "source": "temp/lazer/python/demo/ballot_field_params.h:ballot_field_param",
        "expectedProofSizeBytes": len(proof),
    }


def parameter_set_contract(proof: bytes) -> dict[str, Any]:
    return {
        "profileId": VECTOR_PROFILE_ID,
        "source": "tools/lazer-oracle/ballot-field-linear-params.py",
        "relation": "A*w + t = 0",
        "ringDegree": SOURCE_RING_DEGREE,
        "proofSystemRingDegree": PROOF_RING_DEGREE,
        "coefficientModulus": SOURCE_COEFFICIENT_MODULUS,
        "statementRows": STATEMENT_ROWS,
        "statementColumns": STATEMENT_COLUMNS,
        "witnessL2BoundSquared": WITNESS_L2_BOUND_SQUARED,
        "expectedProofSizeBytes": len(proof),
    }


def build_compact_case(
    *,
    case_name: str,
    description: str,
    mutation: str,
    expected_outcome: str,
    proof_hex: str | None,
    public_randomness_hex: str | None,
    statement_matrix_patch: dict[str, int] | None,
    target_vector_patch: dict[str, int] | None,
    trace: dict[str, Any],
) -> dict[str, Any]:
    output = {
        "caseName": case_name,
        "description": description,
        "expectedOutcome": expected_outcome,
        "mutation": mutation,
        "upstreamVectorAvailable": True,
        "trace": trace,
    }
    if proof_hex is not None:
        output["proofHex"] = proof_hex
    if public_randomness_hex is not None:
        output["publicRandomnessHex"] = public_randomness_hex
    if statement_matrix_patch is not None:
        output["statementMatrixPatch"] = statement_matrix_patch
    if target_vector_patch is not None:
        output["targetVectorPatch"] = target_vector_patch

    return output


def mutate_matrix_with_patch(
    matrix_coefficients: list[list[list[int]]],
) -> tuple[list[list[list[int]]], dict[str, int]]:
    mutated = mutate_matrix(matrix_coefficients, SOURCE_COEFFICIENT_MODULUS)

    return (
        mutated,
        {
            "rowIndex": 0,
            "columnIndex": 0,
            "coefficientIndex": 0,
            "coefficient": mutated[0][0][0],
        },
    )


def mutate_target_with_patch(
    target_coefficients: list[list[int]],
) -> tuple[list[list[int]], dict[str, int]]:
    mutated = mutate_vector(target_coefficients, SOURCE_COEFFICIENT_MODULUS)

    return (
        mutated,
        {
            "rowIndex": 0,
            "coefficientIndex": 0,
            "coefficient": mutated[0][0],
        },
    )


def noncanonical_matrix_with_patch(
    matrix_coefficients: list[list[list[int]]],
) -> tuple[list[list[list[int]]], dict[str, int]]:
    mutated = copy.deepcopy(matrix_coefficients)
    mutated[0][0][0] = SOURCE_COEFFICIENT_MODULUS

    return (
        mutated,
        {
            "rowIndex": 0,
            "columnIndex": 0,
            "coefficientIndex": 0,
            "coefficient": SOURCE_COEFFICIENT_MODULUS,
        },
    )


def load_oracle_input(input_path: Path) -> dict[str, Any]:
    require_nonempty_file(input_path)
    with input_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    linear_statement = payload["linearStatement"]
    if linear_statement["statementRows"] != STATEMENT_ROWS:
        raise RuntimeError("encoded-score field statement row count changed")
    if linear_statement["statementColumns"] != STATEMENT_COLUMNS:
        raise RuntimeError("encoded-score field statement column count changed")
    if linear_statement["coefficientModulus"] != str(SOURCE_COEFFICIENT_MODULUS):
        raise RuntimeError("encoded-score field statement modulus changed")
    if linear_statement["parameterProfileId"] != VECTOR_PROFILE_ID:
        raise RuntimeError("encoded-score field statement profile changed")

    return payload


def emit_vectors(repo_root: Path, lazer_root: Path, input_path: Path, out_path: Path) -> None:
    require_nonempty_file(lazer_root / "python" / "demo" / "ballot_field_params.h")
    require_nonempty_glob(
        lazer_root / "python" / "demo",
        "_ballot_field_params_cffi*.so",
    )
    import_lazer_python(lazer_root)

    from _ballot_field_params_cffi import lib
    from lazer import lin_prover_state_t, polyring_t

    oracle_input = load_oracle_input(input_path)
    linear_statement = oracle_input["linearStatement"]
    public_randomness = bytes.fromhex(
        "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"
    )
    prover_coins = bytes.fromhex(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
    )
    parameters = lib.get_params("ballot_field_param")
    ring = polyring_t(SOURCE_RING_DEGREE, SOURCE_COEFFICIENT_MODULUS)

    matrix_coefficients = linear_statement["statementMatrixCoefficients"]
    target_coefficients = linear_statement["targetVectorCoefficients"]
    private_witness_coefficients = oracle_input["privateWitnessVectorCoefficients"]
    matrix = coefficients_to_matrix(ring, matrix_coefficients)
    target = coefficients_to_vector(ring, target_coefficients)
    private_witness = coefficients_to_vector(ring, private_witness_coefficients)

    prover = lin_prover_state_t(public_randomness, parameters)
    prover.set_statement(matrix, target)
    prover.set_witness(private_witness)
    proof = prover.prove(prover_coins)

    if not verify_with_upstream(proof, public_randomness, parameters, matrix, target):
        raise RuntimeError("upstream LaZer rejected the valid encoded-score field proof")

    parameter_set = parameter_set_contract(proof)
    proof_encoding = proof_encoding_contract(proof)
    proof_hex = bytes_hex(proof)
    public_randomness_hex = bytes_hex(public_randomness)
    wrong_public_randomness = bytearray(public_randomness)
    wrong_public_randomness[0] = 1
    truncated_proof = proof[:-1]
    extended_proof = proof + b"\0"
    mutated_matrix_coefficients, matrix_patch = mutate_matrix_with_patch(
        matrix_coefficients
    )
    mutated_target_coefficients, target_patch = mutate_target_with_patch(
        target_coefficients
    )
    noncanonical_matrix_coefficients, noncanonical_matrix_patch = (
        noncanonical_matrix_with_patch(matrix_coefficients)
    )
    mutated_proof = bytes.fromhex(mutate_proof_byte(proof))

    require_upstream_rejection(
        case_name="mutated-encoded-score-field-statement-matrix",
        proof=proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=coefficients_to_matrix(ring, mutated_matrix_coefficients),
        target=target,
    )
    require_upstream_rejection(
        case_name="mutated-encoded-score-field-target-vector",
        proof=proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=matrix,
        target=coefficients_to_vector(ring, mutated_target_coefficients),
    )
    require_upstream_rejection(
        case_name="mutated-encoded-score-field-proof-byte",
        proof=mutated_proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=matrix,
        target=target,
    )
    require_upstream_rejection(
        case_name="wrong-encoded-score-field-public-randomness",
        proof=proof,
        public_randomness=bytes(wrong_public_randomness),
        parameters=parameters,
        matrix=matrix,
        target=target,
    )
    require_upstream_rejection(
        case_name="truncated-encoded-score-field-proof",
        proof=truncated_proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=matrix,
        target=target,
    )
    extended_proof_upstream_accepted = verify_with_upstream(
        proof=extended_proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=matrix,
        target=target,
    )

    cases = [
        build_compact_case(
            case_name="valid-encoded-score-field-linear-proof",
            description="Accepting upstream LaZer linear proof for the compiler-emitted encoded-score field rows.",
            mutation="none",
            expected_outcome="accept",
            proof_hex=None,
            public_randomness_hex=None,
            statement_matrix_patch=None,
            target_vector_patch=None,
            trace=build_trace(
                parameter_set=parameter_set,
                proof_encoding=proof_encoding,
                statement_matrix_coefficients=matrix_coefficients,
                target_vector_coefficients=target_coefficients,
                proof=proof,
                public_randomness=public_randomness,
                expected_logical_rejection_layer="accept",
                upstream_verifier_accepted=True,
            ),
        ),
        build_compact_case(
            case_name="mutated-encoded-score-field-statement-matrix",
            description="Same encoded-score field proof bytes with one projected statement matrix coefficient changed.",
            mutation="statement-matrix-coefficient",
            expected_outcome="reject",
            proof_hex=None,
            public_randomness_hex=None,
            statement_matrix_patch=matrix_patch,
            target_vector_patch=None,
            trace=build_trace(
                parameter_set=parameter_set,
                proof_encoding=proof_encoding,
                statement_matrix_coefficients=mutated_matrix_coefficients,
                target_vector_coefficients=target_coefficients,
                proof=proof,
                public_randomness=public_randomness,
                expected_logical_rejection_layer="statement-binding",
                upstream_verifier_accepted=False,
            ),
        ),
        build_compact_case(
            case_name="mutated-encoded-score-field-target-vector",
            description="Same encoded-score field proof bytes with one projected target vector coefficient changed.",
            mutation="target-vector-coefficient",
            expected_outcome="reject",
            proof_hex=None,
            public_randomness_hex=None,
            statement_matrix_patch=None,
            target_vector_patch=target_patch,
            trace=build_trace(
                parameter_set=parameter_set,
                proof_encoding=proof_encoding,
                statement_matrix_coefficients=matrix_coefficients,
                target_vector_coefficients=mutated_target_coefficients,
                proof=proof,
                public_randomness=public_randomness,
                expected_logical_rejection_layer="statement-binding",
                upstream_verifier_accepted=False,
            ),
        ),
        build_compact_case(
            case_name="mutated-encoded-score-field-proof-byte",
            description="Valid encoded-score field public statement with one proof byte changed.",
            mutation="proof-byte",
            expected_outcome="reject",
            proof_hex=mutated_proof.hex(),
            public_randomness_hex=None,
            statement_matrix_patch=None,
            target_vector_patch=None,
            trace=build_trace(
                parameter_set=parameter_set,
                proof_encoding=proof_encoding,
                statement_matrix_coefficients=matrix_coefficients,
                target_vector_coefficients=target_coefficients,
                proof=mutated_proof,
                public_randomness=public_randomness,
                expected_logical_rejection_layer="proof-body",
                upstream_verifier_accepted=False,
            ),
        ),
        build_compact_case(
            case_name="wrong-encoded-score-field-public-randomness",
            description="Valid encoded-score field proof and statement with the public randomness seed changed.",
            mutation="public-randomness",
            expected_outcome="reject",
            proof_hex=None,
            public_randomness_hex=bytes(wrong_public_randomness).hex(),
            statement_matrix_patch=None,
            target_vector_patch=None,
            trace=build_trace(
                parameter_set=parameter_set,
                proof_encoding=proof_encoding,
                statement_matrix_coefficients=matrix_coefficients,
                target_vector_coefficients=target_coefficients,
                proof=proof,
                public_randomness=bytes(wrong_public_randomness),
                expected_logical_rejection_layer="public-parameter-binding",
                upstream_verifier_accepted=False,
            ),
        ),
        build_compact_case(
            case_name="truncated-encoded-score-field-proof",
            description="Valid encoded-score field proof encoding with the final byte removed.",
            mutation="proof-truncation",
            expected_outcome="reject",
            proof_hex=truncated_proof.hex(),
            public_randomness_hex=None,
            statement_matrix_patch=None,
            target_vector_patch=None,
            trace=build_trace(
                parameter_set=parameter_set,
                proof_encoding=proof_encoding,
                statement_matrix_coefficients=matrix_coefficients,
                target_vector_coefficients=target_coefficients,
                proof=truncated_proof,
                public_randomness=public_randomness,
                expected_logical_rejection_layer="proof-decoder",
                upstream_verifier_accepted=False,
            ),
        ),
        build_compact_case(
            case_name="extended-encoded-score-field-proof",
            description="Valid encoded-score field proof encoding with one trailing byte appended.",
            mutation="proof-extension",
            expected_outcome="reject",
            proof_hex=extended_proof.hex(),
            public_randomness_hex=None,
            statement_matrix_patch=None,
            target_vector_patch=None,
            trace=build_trace(
                parameter_set=parameter_set,
                proof_encoding=proof_encoding,
                statement_matrix_coefficients=matrix_coefficients,
                target_vector_coefficients=target_coefficients,
                proof=extended_proof,
                public_randomness=public_randomness,
                expected_logical_rejection_layer="proof-decoder",
                upstream_verifier_accepted=extended_proof_upstream_accepted,
            ),
        ),
        build_compact_case(
            case_name="noncanonical-encoded-score-field-coefficient-encoding",
            description="Encoded-score field statement encoding with a coefficient representative equal to the modulus.",
            mutation="coefficient-encoding",
            expected_outcome="reject",
            proof_hex=None,
            public_randomness_hex=None,
            statement_matrix_patch=noncanonical_matrix_patch,
            target_vector_patch=None,
            trace=build_trace(
                parameter_set=parameter_set,
                proof_encoding=proof_encoding,
                statement_matrix_coefficients=noncanonical_matrix_coefficients,
                target_vector_coefficients=target_coefficients,
                proof=proof,
                public_randomness=public_randomness,
                expected_logical_rejection_layer="canonical-statement-decoder",
                upstream_verifier_accepted=None,
            ),
        ),
    ]

    sage_version = (
        run_command(["sage", "--version"]).splitlines()[0]
        if shutil.which("sage")
        else "not installed in this container"
    )
    provenance = {
        "upstreamRepositoryUrl": "https://github.com/lazer-crypto/lazer",
        "upstreamCommitHash": run_command(["git", "rev-parse", "HEAD"], cwd=lazer_root),
        "dockerfileSha256": sha256_file(
            repo_root / "tools" / "lazer-oracle" / "Dockerfile"
        ),
        "oracleDriverSha256": sha256_file(
            repo_root / "tools" / "lazer-oracle" / "generate-ballot-field-linear-vectors.ts"
        ),
        "oracleInputGeneratorSha256": sha256_file(
            repo_root
            / "tools"
            / "ballot-privacy-vectors"
            / "generate-ballot-field-linear-proof-input.mts"
        ),
        "oracleRunnerSha256": sha256_file(
            repo_root / "tools" / "lazer-oracle" / "run_ballot_field_oracle.py"
        ),
        "ballotFieldParameterSourceSha256": sha256_file(
            repo_root / "tools" / "lazer-oracle" / "ballot-field-linear-params.py"
        ),
        "generatedHeaderSha256": sha256_file(
            lazer_root / "python" / "demo" / "ballot_field_params.h"
        ),
        "vectorEmitterSha256": sha256_file(Path(__file__)),
        "pythonVersion": platform.python_version(),
        "sageVersion": sage_version,
        "compilerVersion": run_command(["gcc", "--version"]).splitlines()[0],
        "buildCommand": "tsx tools/lazer-oracle/generate-ballot-field-linear-vectors.ts",
        "parameterGenerationCommand": "docker run sagemath/sagemath:latest sage lin-codegen.sage tools/lazer-oracle/ballot-field-linear-params.py",
        "profileWarning": "This vector proves only the compiler-emitted encoded-score field-row projection; share commitment, receiver payload, and receiver-key digest-expanded rows remain outside this proof vector.",
        "licenseNote": "LaZer is used only as an offline vector oracle; no upstream C library is shipped in sealed-lattice.",
    }

    output = {
        "objectType": "BallotFieldLinearProofBackendVectors",
        "objectVersion": 1,
        "profileId": VECTOR_PROFILE_ID,
        "upstreamReference": "lazer-crypto/lazer",
        "upstreamSourcePath": "temp/lazer/python/demo/ballot_field_params.h",
        "generatedFromUpstreamLaZer": True,
        "generationStatus": "generated-with-profile-warning",
        "projectionCoverage": "encoded-score-field-rows-only",
        "provenance": provenance,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "linearStatement": linear_statement,
        "proofHex": proof_hex,
        "publicRandomnessHex": public_randomness_hex,
        "targetCoefficientRepresentation": "canonicalUnsignedSourceModulus",
        "expectedProofSizeBytes": len(proof),
        "requiredCaseNames": REQUIRED_CASE_NAMES,
        "cases": cases,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(output, indent=4, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--lazer-root", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    emit_vectors(
        repo_root=Path(args.repo_root),
        lazer_root=Path(args.lazer_root),
        input_path=Path(args.input),
        out_path=Path(args.out),
    )


if __name__ == "__main__":
    main()
