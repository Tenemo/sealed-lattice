#!/usr/bin/env python3
"""Emit public-only receiver-key linear proof compatibility vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from emit_linear_vectors import (
    build_case,
    build_trace,
    bytes_hex,
    coefficients_to_matrix,
    coefficients_to_vector,
    import_lazer_python,
    matrix_to_positive_coefficients,
    mutate_matrix,
    mutate_proof_byte,
    mutate_vector,
    require_upstream_rejection,
    run_command,
    sha256_file,
    vector_to_positive_coefficients,
    verify_with_upstream,
)


VECTOR_PROFILE_ID = "receiver-key-linear-module-lwe-compatibility-v1"
REQUIRED_CASE_NAMES = [
    "valid-receiver-key-linear-proof",
    "mutated-receiver-key-statement-matrix",
    "mutated-receiver-key-target-vector",
    "mutated-receiver-key-proof-byte",
    "wrong-receiver-key-public-randomness",
    "truncated-receiver-key-proof",
    "extended-receiver-key-proof",
    "noncanonical-receiver-key-coefficient-encoding",
]

RECEIVER_KEY_RING_DEGREE = 256
RECEIVER_KEY_COEFFICIENT_MODULUS = 12289
RECEIVER_KEY_STATEMENT_ROWS = 4
RECEIVER_KEY_STATEMENT_COLUMNS = 8
RECEIVER_KEY_WITNESS_L2_BOUND_SQUARED = 8192


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
        "profileId": "receiver-key-linear-proof-encoding-v1",
        "ringDegree": 64,
        "coefficientModulus": "274877908477",
        "fullSizeCoefficientBitLength": 39,
        "compressedCoefficientBitLength": 29,
        "targetCommitmentVectorLength": 12,
        "hashMaskVectorLength": 2,
        "compressedCommitmentVectorLength": 19,
        "challengeCoefficientModulus": 17,
        "challengeCoefficientBitLength": 5,
        "hintVectorLength": 19,
        "shortResponseVectorLength": 33,
        "randomnessResponseVectorLength": 36,
        "euclideanResponseVectorLength": 4,
        "infinityResponseVectorLength": 4,
        "shortResponseLog2StandardDeviation": 17,
        "randomnessResponseLog2StandardDeviation": 12,
        "euclideanResponseLog2StandardDeviation": 12,
        "infinityResponseLog2StandardDeviation": 17,
        "source": "temp/lazer/python/demo/receiver_key_params.h:receiver_key_param",
        "expectedProofSizeBytes": len(proof),
    }


def emit_vectors(repo_root: Path, lazer_root: Path, out_path: Path) -> None:
    require_nonempty_file(lazer_root / "python" / "demo" / "receiver_key_params.h")
    require_nonempty_glob(
        lazer_root / "python" / "demo",
        "_receiver_key_params_cffi*.so",
    )
    import_lazer_python(lazer_root)

    from _receiver_key_params_cffi import lib
    from lazer import lin_prover_state_t, polymat_t, polyring_t, polyvec_t

    public_randomness = b"\0" * 32
    prover_coins = bytes.fromhex(
        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    )
    parameters = lib.get_params("receiver_key_param")
    ring = polyring_t(RECEIVER_KEY_RING_DEGREE, RECEIVER_KEY_COEFFICIENT_MODULUS)

    matrix = polymat_t(ring, RECEIVER_KEY_STATEMENT_ROWS, RECEIVER_KEY_STATEMENT_COLUMNS)
    matrix.urandom(RECEIVER_KEY_COEFFICIENT_MODULUS, public_randomness, 0)

    witness = polyvec_t(ring, RECEIVER_KEY_STATEMENT_COLUMNS)
    witness.brandom(
        2,
        public_randomness,
        0,
        l2bound=RECEIVER_KEY_WITNESS_L2_BOUND_SQUARED,
    )
    target = -(matrix * witness)

    prover = lin_prover_state_t(public_randomness, parameters)
    prover.set_statement(matrix, target)
    prover.set_witness(witness)
    proof = prover.prove(prover_coins)

    if not verify_with_upstream(proof, public_randomness, parameters, matrix, target):
        raise RuntimeError("upstream LaZer rejected the valid receiver-key proof")

    matrix_coefficients = matrix_to_positive_coefficients(
        matrix, RECEIVER_KEY_COEFFICIENT_MODULUS
    )
    target_coefficients = vector_to_positive_coefficients(
        target, RECEIVER_KEY_COEFFICIENT_MODULUS
    )
    parameter_set = {
        "profileId": VECTOR_PROFILE_ID,
        "source": "tools/lazer-oracle/receiver-key-linear-params.py",
        "relation": "A*w + t = 0",
        "ringDegree": RECEIVER_KEY_RING_DEGREE,
        "proofSystemRingDegree": 64,
        "coefficientModulus": RECEIVER_KEY_COEFFICIENT_MODULUS,
        "statementRows": RECEIVER_KEY_STATEMENT_ROWS,
        "statementColumns": RECEIVER_KEY_STATEMENT_COLUMNS,
        "witnessL2BoundSquared": RECEIVER_KEY_WITNESS_L2_BOUND_SQUARED,
        "expectedProofSizeBytes": len(proof),
    }
    proof_encoding = proof_encoding_contract(proof)
    proof_hex = bytes_hex(proof)
    public_randomness_hex = bytes_hex(public_randomness)
    wrong_public_randomness = bytearray(public_randomness)
    wrong_public_randomness[0] = 1
    truncated_proof = proof[:-1]
    extended_proof = proof + b"\0"
    mutated_matrix_coefficients = mutate_matrix(
        matrix_coefficients, RECEIVER_KEY_COEFFICIENT_MODULUS
    )
    mutated_target_coefficients = mutate_vector(
        target_coefficients, RECEIVER_KEY_COEFFICIENT_MODULUS
    )
    mutated_proof = bytes.fromhex(mutate_proof_byte(proof))

    require_upstream_rejection(
        case_name="mutated-receiver-key-statement-matrix",
        proof=proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=coefficients_to_matrix(ring, mutated_matrix_coefficients),
        target=target,
    )
    require_upstream_rejection(
        case_name="mutated-receiver-key-target-vector",
        proof=proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=matrix,
        target=coefficients_to_vector(ring, mutated_target_coefficients),
    )
    require_upstream_rejection(
        case_name="mutated-receiver-key-proof-byte",
        proof=mutated_proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=matrix,
        target=target,
    )
    require_upstream_rejection(
        case_name="wrong-receiver-key-public-randomness",
        proof=proof,
        public_randomness=bytes(wrong_public_randomness),
        parameters=parameters,
        matrix=matrix,
        target=target,
    )
    require_upstream_rejection(
        case_name="truncated-receiver-key-proof",
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

    noncanonical_matrix_coefficients = [
        [
            [
                (
                    RECEIVER_KEY_COEFFICIENT_MODULUS
                    if row_index == 0
                    and column_index == 0
                    and coefficient_index == 0
                    else coefficient
                )
                for coefficient_index, coefficient in enumerate(polynomial)
            ]
            for column_index, polynomial in enumerate(row)
        ]
        for row_index, row in enumerate(matrix_coefficients)
    ]

    cases = [
        build_case(
            case_name="valid-receiver-key-linear-proof",
            description="Accepting upstream LaZer linear proof for the receiver-key parameter relation.",
            mutation="none",
            expected_outcome="accept",
            parameter_set=parameter_set,
            proof_encoding=proof_encoding,
            public_randomness_hex=public_randomness_hex,
            statement_matrix_coefficients=matrix_coefficients,
            target_vector_coefficients=target_coefficients,
            target_coefficient_representation="centeredSignedSourceModulus",
            proof_hex=proof_hex,
            expected_proof_size_bytes=len(proof),
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
        build_case(
            case_name="mutated-receiver-key-statement-matrix",
            description="Same receiver-key proof bytes with one statement matrix coefficient changed.",
            mutation="statement-matrix-coefficient",
            expected_outcome="reject",
            parameter_set=parameter_set,
            proof_encoding=proof_encoding,
            public_randomness_hex=public_randomness_hex,
            statement_matrix_coefficients=mutated_matrix_coefficients,
            target_vector_coefficients=target_coefficients,
            target_coefficient_representation="centeredSignedSourceModulus",
            proof_hex=proof_hex,
            expected_proof_size_bytes=len(proof),
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
        build_case(
            case_name="mutated-receiver-key-target-vector",
            description="Same receiver-key proof bytes with one target vector coefficient changed.",
            mutation="target-vector-coefficient",
            expected_outcome="reject",
            parameter_set=parameter_set,
            proof_encoding=proof_encoding,
            public_randomness_hex=public_randomness_hex,
            statement_matrix_coefficients=matrix_coefficients,
            target_vector_coefficients=mutated_target_coefficients,
            target_coefficient_representation="centeredSignedSourceModulus",
            proof_hex=proof_hex,
            expected_proof_size_bytes=len(proof),
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
        build_case(
            case_name="mutated-receiver-key-proof-byte",
            description="Valid receiver-key public statement with one proof byte changed.",
            mutation="proof-byte",
            expected_outcome="reject",
            parameter_set=parameter_set,
            proof_encoding=proof_encoding,
            public_randomness_hex=public_randomness_hex,
            statement_matrix_coefficients=matrix_coefficients,
            target_vector_coefficients=target_coefficients,
            target_coefficient_representation="centeredSignedSourceModulus",
            proof_hex=mutated_proof.hex(),
            expected_proof_size_bytes=len(proof),
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
        build_case(
            case_name="wrong-receiver-key-public-randomness",
            description="Valid receiver-key proof and statement with the public randomness seed changed.",
            mutation="public-randomness",
            expected_outcome="reject",
            parameter_set=parameter_set,
            proof_encoding=proof_encoding,
            public_randomness_hex=bytes(wrong_public_randomness).hex(),
            statement_matrix_coefficients=matrix_coefficients,
            target_vector_coefficients=target_coefficients,
            target_coefficient_representation="centeredSignedSourceModulus",
            proof_hex=proof_hex,
            expected_proof_size_bytes=len(proof),
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
        build_case(
            case_name="truncated-receiver-key-proof",
            description="Valid receiver-key proof encoding with the final byte removed.",
            mutation="proof-truncation",
            expected_outcome="reject",
            parameter_set=parameter_set,
            proof_encoding=proof_encoding,
            public_randomness_hex=public_randomness_hex,
            statement_matrix_coefficients=matrix_coefficients,
            target_vector_coefficients=target_coefficients,
            target_coefficient_representation="centeredSignedSourceModulus",
            proof_hex=truncated_proof.hex(),
            expected_proof_size_bytes=len(proof),
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
        build_case(
            case_name="extended-receiver-key-proof",
            description="Valid receiver-key proof encoding with one trailing byte appended.",
            mutation="proof-extension",
            expected_outcome="reject",
            parameter_set=parameter_set,
            proof_encoding=proof_encoding,
            public_randomness_hex=public_randomness_hex,
            statement_matrix_coefficients=matrix_coefficients,
            target_vector_coefficients=target_coefficients,
            target_coefficient_representation="centeredSignedSourceModulus",
            proof_hex=extended_proof.hex(),
            expected_proof_size_bytes=len(proof),
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
        build_case(
            case_name="noncanonical-receiver-key-coefficient-encoding",
            description="Receiver-key statement encoding with a coefficient representative equal to the modulus.",
            mutation="coefficient-encoding",
            expected_outcome="reject",
            parameter_set=parameter_set,
            proof_encoding=proof_encoding,
            public_randomness_hex=public_randomness_hex,
            statement_matrix_coefficients=noncanonical_matrix_coefficients,
            target_vector_coefficients=target_coefficients,
            target_coefficient_representation="centeredSignedSourceModulus",
            proof_hex=proof_hex,
            expected_proof_size_bytes=len(proof),
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

    sage_version = run_command(["sage", "--version"]).splitlines()[0] if shutil.which("sage") else "not installed in this container"
    provenance = {
        "upstreamRepositoryUrl": "https://github.com/lazer-crypto/lazer",
        "upstreamCommitHash": run_command(["git", "rev-parse", "HEAD"], cwd=lazer_root),
        "dockerfileSha256": sha256_file(repo_root / "tools" / "lazer-oracle" / "Dockerfile"),
        "receiverKeyParameterSourceSha256": sha256_file(
            repo_root / "tools" / "lazer-oracle" / "receiver-key-linear-params.py"
        ),
        "vectorEmitterSha256": sha256_file(Path(__file__)),
        "pythonVersion": platform.python_version(),
        "sageVersion": sage_version,
        "compilerVersion": run_command(["gcc", "--version"]).splitlines()[0],
        "parameterGenerationCommand": "docker run sagemath/sagemath:latest sage lin-codegen.sage tools/lazer-oracle/receiver-key-linear-params.py",
        "profileWarning": "LaZer lin-codegen emits protocol-not-complete for this exploratory receiver-key parameter file; vectors are used for porting behavior only, not production closure.",
        "licenseNote": "LaZer is used only as an offline vector oracle; no upstream C library is shipped in sealed-lattice.",
    }

    output = {
        "objectType": "ReceiverKeyLinearProofBackendVectors",
        "objectVersion": 1,
        "profileId": VECTOR_PROFILE_ID,
        "upstreamReference": "lazer-crypto/lazer",
        "upstreamSourcePath": "temp/lazer/python/demo/receiver_key_params.h",
        "generatedFromUpstreamLaZer": True,
        "generationStatus": "generated-with-profile-warning",
        "provenance": provenance,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "requiredCaseNames": REQUIRED_CASE_NAMES,
        "cases": cases,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=4, sort_keys=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--lazer-root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    emit_vectors(Path(args.repo_root), Path(args.lazer_root), Path(args.out))


if __name__ == "__main__":
    main()
