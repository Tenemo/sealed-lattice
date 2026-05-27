#!/usr/bin/env python3
"""Emit public-only LaZer linear proof compatibility vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from lazer_bindings import (
    coefficients_to_matrix,
    coefficients_to_vector,
    import_lazer_python,
    matrix_to_positive_coefficients,
    mutate_matrix,
    mutate_proof_byte,
    mutate_vector,
    require_upstream_rejection,
    vector_to_positive_coefficients,
    verify_with_upstream,
)
from proof_trace import build_trace, bytes_hex

VECTOR_PROFILE_ID = "lazer-linear-demo-compatibility-v1"
REQUIRED_CASE_NAMES = [
    "valid-small-linear-proof",
    "mutated-statement-matrix",
    "mutated-target-vector",
    "mutated-proof-byte",
    "wrong-public-randomness",
    "truncated-proof",
    "extended-proof",
    "noncanonical-coefficient-encoding",
]


def run_command(command: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    return completed.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def build_case(
    *,
    case_name: str,
    description: str,
    mutation: str,
    expected_outcome: str,
    parameter_set: dict[str, Any],
    proof_encoding: dict[str, Any],
    public_randomness_hex: str,
    proof_hex: str,
    expected_proof_size_bytes: int,
    statement_matrix_coefficients: list[list[list[int]]],
    target_vector_coefficients: list[list[int]],
    target_coefficient_representation: str,
    trace: dict[str, Any],
) -> dict[str, Any]:
    return {
        "caseName": case_name,
        "description": description,
        "mutation": mutation,
        "expectedOutcome": expected_outcome,
        "upstreamVectorAvailable": True,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": statement_matrix_coefficients,
        "targetVectorCoefficients": target_vector_coefficients,
        "targetCoefficientRepresentation": target_coefficient_representation,
        "proofHex": proof_hex,
        "expectedProofSizeBytes": expected_proof_size_bytes,
        "trace": trace,
    }


def emit_vectors(repo_root: Path, lazer_root: Path, out_path: Path) -> None:
    import_lazer_python(lazer_root)

    from demo_params import deg, dim, mod
    from _demo_params_cffi import lib
    from lazer import polyvec_t, polymat_t, polyring_t, lin_prover_state_t

    public_randomness = b"\0" * 32
    prover_coins = bytes.fromhex(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
    )
    parameters = lib.get_params("param")
    ring = polyring_t(deg, mod)

    rows, columns = dim
    matrix = polymat_t(ring, rows, columns)
    matrix.urandom(mod, public_randomness, 0)

    witness = polyvec_t(ring, columns)
    witness.brandom(1, public_randomness, 0)
    target = -(matrix * witness)

    prover = lin_prover_state_t(public_randomness, parameters)
    prover.set_statement(matrix, target)
    prover.set_witness(witness)
    proof = prover.prove(prover_coins)

    valid_accepts = verify_with_upstream(proof, public_randomness, parameters, matrix, target)
    if not valid_accepts:
        raise RuntimeError("upstream LaZer rejected the valid generated proof")

    matrix_coefficients = matrix_to_positive_coefficients(matrix, mod)
    target_coefficients = vector_to_positive_coefficients(target, mod)
    parameter_set = {
        "profileId": VECTOR_PROFILE_ID,
        "source": "temp/lazer/python/demo/demo_params.h",
        "relation": "A*w + t = 0",
        "ringDegree": int(deg),
        "proofSystemRingDegree": 64,
        "coefficientModulus": int(mod),
        "statementRows": int(rows),
        "statementColumns": int(columns),
        "witnessL2BoundSquared": 2048,
        "expectedProofSizeBytes": len(proof),
    }
    proof_encoding = {
        "profileId": "lazer-demo-linear-proof-encoding-v1",
        "ringDegree": 64,
        "coefficientModulus": "36028797018964597",
        "fullSizeCoefficientBitLength": 56,
        "compressedCoefficientBitLength": 46,
        "targetCommitmentVectorLength": 12,
        "hashMaskVectorLength": 2,
        "compressedCommitmentVectorLength": 13,
        "challengeCoefficientModulus": 17,
        "challengeCoefficientBitLength": 5,
        "hintVectorLength": 13,
        "shortResponseVectorLength": 33,
        "randomnessResponseVectorLength": 47,
        "euclideanResponseVectorLength": 4,
        "infinityResponseVectorLength": 4,
        "shortResponseLog2StandardDeviation": 16,
        "randomnessResponseLog2StandardDeviation": 12,
        "euclideanResponseLog2StandardDeviation": 11,
        "infinityResponseLog2StandardDeviation": 16,
        "source": "temp/lazer/python/demo/demo_params.h:_param",
    }
    proof_hex = bytes_hex(proof)
    public_randomness_hex = bytes_hex(public_randomness)
    wrong_public_randomness = bytearray(public_randomness)
    wrong_public_randomness[0] = 1
    truncated_proof = proof[:-1]
    extended_proof = proof + b"\0"
    mutated_matrix_coefficients = mutate_matrix(matrix_coefficients, mod)
    mutated_target_coefficients = mutate_vector(target_coefficients, mod)
    mutated_proof = bytes.fromhex(mutate_proof_byte(proof))

    require_upstream_rejection(
        case_name="mutated-statement-matrix",
        proof=proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=coefficients_to_matrix(ring, mutated_matrix_coefficients),
        target=target,
    )
    require_upstream_rejection(
        case_name="mutated-target-vector",
        proof=proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=matrix,
        target=coefficients_to_vector(ring, mutated_target_coefficients),
    )
    require_upstream_rejection(
        case_name="mutated-proof-byte",
        proof=mutated_proof,
        public_randomness=public_randomness,
        parameters=parameters,
        matrix=matrix,
        target=target,
    )
    require_upstream_rejection(
        case_name="wrong-public-randomness",
        proof=proof,
        public_randomness=bytes(wrong_public_randomness),
        parameters=parameters,
        matrix=matrix,
        target=target,
    )
    require_upstream_rejection(
        case_name="truncated-proof",
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
                    int(mod)
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
            case_name="valid-small-linear-proof",
            description="Accepting upstream LaZer linear proof for the demo relation.",
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
            case_name="mutated-statement-matrix",
            description="Same proof bytes as the valid vector with one statement matrix coefficient changed.",
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
            case_name="mutated-target-vector",
            description="Same proof bytes as the valid vector with one target vector coefficient changed.",
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
            case_name="mutated-proof-byte",
            description="Valid public statement with one proof byte changed.",
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
            case_name="wrong-public-randomness",
            description="Valid proof and statement with the public randomness seed changed.",
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
            case_name="truncated-proof",
            description="Valid proof encoding with the final byte removed.",
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
            case_name="extended-proof",
            description="Valid proof encoding with one trailing byte appended.",
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
            case_name="noncanonical-coefficient-encoding",
            description="Statement encoding with a coefficient representative equal to the modulus.",
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

    sage_executable = shutil.which("sage")
    sage_version = (
        run_command(["sage", "--version"]).splitlines()[0]
        if sage_executable is not None
        else "not installed; committed demo_params.h used"
    )

    provenance = {
        "upstreamRepositoryUrl": "https://github.com/lazer-crypto/lazer",
        "upstreamCommitHash": run_command(["git", "rev-parse", "HEAD"], cwd=lazer_root),
        "dockerfileSha256": sha256_file(repo_root / "tools" / "lazer-oracle" / "Dockerfile"),
        "oracleDriverSha256": sha256_file(
            repo_root / "tools" / "lazer-oracle" / "generate-linear-vectors.ts"
        ),
        "oracleRunnerSha256": sha256_file(
            repo_root / "tools" / "lazer-oracle" / "run_oracle.py"
        ),
        "vectorEmitterSha256": sha256_file(Path(__file__)),
        "pythonVersion": platform.python_version(),
        "sageVersion": sage_version,
        "compilerVersion": run_command(["gcc", "--version"]).splitlines()[0],
        "buildCommand": "tsx tools/lazer-oracle/generate-linear-vectors.ts",
        "testCommand": "python3 tools/lazer-oracle/run_oracle.py followed by python3 tools/lazer-oracle/vector-emitter/emit_linear_vectors.py inside Docker",
        "parameterGenerationCommand": "cd temp/lazer/scripts && sage lin-codegen.sage ../python/demo/demo_params.py > ../python/demo/demo_params.h",
        "licenseNote": "LaZer is used only as an offline vector oracle; no upstream C library is shipped in sealed-lattice.",
    }

    output = {
        "objectType": "BallotPrivacyLinearProofBackendVectors",
        "objectVersion": 1,
        "profileId": VECTOR_PROFILE_ID,
        "upstreamReference": "lazer-crypto/lazer",
        "upstreamSourcePath": "temp/lazer/python/demo",
        "generatedFromUpstreamLaZer": True,
        "generationStatus": "generated",
        "provenance": provenance,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "targetCoefficientRepresentation": "centeredSignedSourceModulus",
        "requiredCaseNames": REQUIRED_CASE_NAMES,
        "cases": cases,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(output, separators=(",", ":"), sort_keys=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--lazer-root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    emit_vectors(Path(args.repo_root), Path(args.lazer_root), Path(args.out))


if __name__ == "__main__":
    main()
