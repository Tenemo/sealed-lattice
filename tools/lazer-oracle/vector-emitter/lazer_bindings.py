from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def import_lazer_python(lazer_root: Path) -> None:
    demo_path = lazer_root / "python" / "demo"
    python_path = lazer_root / "python"
    sys.path.insert(0, str(demo_path))
    sys.path.insert(0, str(python_path))


def polynomial_to_positive_coefficients(polynomial: Any, modulus: int) -> list[int]:
    return [int(coefficient) % modulus for coefficient in polynomial.to_list()]


def vector_to_positive_coefficients(vector: Any, modulus: int) -> list[list[int]]:
    return [
        polynomial_to_positive_coefficients(polynomial, modulus)
        for polynomial in vector.to_pol_list()
    ]


def matrix_to_positive_coefficients(matrix: Any, modulus: int) -> list[list[list[int]]]:
    return [
        [
            polynomial_to_positive_coefficients(
                matrix.get_elem(row_index, column_index), modulus
            )
            for column_index in range(matrix.cols)
        ]
        for row_index in range(matrix.rows)
    ]


def coefficients_to_matrix(ring: Any, coefficients: list[list[list[int]]]) -> Any:
    from lazer import poly_t, polymat_t

    rows = len(coefficients)
    columns = len(coefficients[0])
    matrix = polymat_t(ring, rows, columns)
    for row_index, row in enumerate(coefficients):
        for column_index, polynomial_coefficients in enumerate(row):
            matrix.set_elem(poly_t(ring, polynomial_coefficients), row_index, column_index)

    return matrix


def coefficients_to_vector(ring: Any, coefficients: list[list[int]]) -> Any:
    from lazer import poly_t, polyvec_t

    vector = polyvec_t(ring, len(coefficients))
    for entry_index, polynomial_coefficients in enumerate(coefficients):
        vector.set_elem(poly_t(ring, polynomial_coefficients), entry_index)

    return vector


def mutate_matrix(matrix_coefficients: list[list[list[int]]], modulus: int) -> list[list[list[int]]]:
    mutated = json.loads(json.dumps(matrix_coefficients))
    mutated[0][0][0] = (mutated[0][0][0] + 1) % modulus

    return mutated


def mutate_vector(vector_coefficients: list[list[int]], modulus: int) -> list[list[int]]:
    mutated = json.loads(json.dumps(vector_coefficients))
    mutated[0][0] = (mutated[0][0] + 1) % modulus

    return mutated


def mutate_proof_byte(proof: bytes) -> str:
    mutated = bytearray(proof)
    mutated[len(mutated) // 2] ^= 0x01

    return bytes(mutated).hex()


def verify_with_upstream(
    proof: bytes,
    public_randomness: bytes,
    parameters: Any,
    matrix: Any,
    target: Any,
) -> bool:
    from lazer import VerificationError, lin_verifier_state_t

    verifier = lin_verifier_state_t(public_randomness, parameters)
    verifier.set_statement(matrix, target)
    try:
        verifier.verify(proof)
    except VerificationError:
        return False
    except Exception:
        return False

    return True


def require_upstream_rejection(
    *,
    case_name: str,
    proof: bytes,
    public_randomness: bytes,
    parameters: Any,
    matrix: Any,
    target: Any,
) -> None:
    accepted = verify_with_upstream(proof, public_randomness, parameters, matrix, target)
    if accepted:
        raise RuntimeError(f"upstream LaZer accepted mutated vector case {case_name}")
