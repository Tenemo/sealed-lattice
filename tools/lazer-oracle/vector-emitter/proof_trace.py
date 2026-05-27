from __future__ import annotations

import hashlib
import json
from typing import Any

LINEAR_PROOF_PREFLIGHT_DOMAIN = "sealed.vote/internal/linear-proof-preflight-v1"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def shake128_bytes_hex(*parts: bytes) -> str:
    digest = hashlib.shake_128()
    for part in parts:
        digest.update(part)

    return digest.hexdigest(32)


def shake128_framed_bytes_hex(*parts: tuple[str, bytes]) -> str:
    digest = hashlib.shake_128()
    for label, part in parts:
        label_bytes = label.encode("utf-8")
        digest.update(len(label_bytes).to_bytes(8, "little"))
        digest.update(label_bytes)
        digest.update(len(part).to_bytes(8, "little"))
        digest.update(part)

    return digest.hexdigest(32)


def bytes_hex(value: bytes) -> str:
    return value.hex()


def canonical_json_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def canonical_json_digest(value: Any) -> str:
    canonical = canonical_json_text(value)

    return sha256_text(canonical)


def canonical_json_shake128_digest(value: Any) -> str:
    return shake128_bytes_hex(canonical_json_text(value).encode("utf-8"))


def build_sealed_lattice_preflight_transcript(
    *,
    parameter_set: dict[str, Any],
    statement_matrix_coefficients: list[list[list[int]]],
    target_vector_coefficients: list[list[int]],
    proof: bytes,
    public_randomness: bytes,
) -> dict[str, str]:
    parameter_set_canonical = canonical_json_text(parameter_set).encode("utf-8")
    statement_matrix_canonical = canonical_json_text(statement_matrix_coefficients).encode(
        "utf-8"
    )
    target_vector_canonical = canonical_json_text(target_vector_coefficients).encode("utf-8")

    return {
        "domain": LINEAR_PROOF_PREFLIGHT_DOMAIN,
        "hash": "SHAKE128-256",
        "parameterDigest": canonical_json_shake128_digest(parameter_set),
        "statementDigest": canonical_json_shake128_digest(statement_matrix_coefficients),
        "targetDigest": canonical_json_shake128_digest(target_vector_coefficients),
        "proofDigest": shake128_bytes_hex(proof),
        "publicRandomnessDigest": shake128_bytes_hex(public_randomness),
        "preflightTranscriptDigest": shake128_framed_bytes_hex(
            ("domain", LINEAR_PROOF_PREFLIGHT_DOMAIN.encode("utf-8")),
            ("parameterSet", parameter_set_canonical),
            ("statementMatrix", statement_matrix_canonical),
            ("targetVector", target_vector_canonical),
            ("publicRandomness", public_randomness),
            ("proofBytes", proof),
        ),
    }


def ceil_divide(dividend: int, divisor: int) -> int:
    return (dividend + divisor - 1) // divisor


class ProofBitReader:
    def __init__(self, proof: bytes) -> None:
        self.proof = proof
        self.bit_offset = 0

    def read_bit(self) -> int:
        if self.bit_offset >= len(self.proof) * 8:
            raise ValueError("proof encoding ended before the current field was complete")

        byte_value = self.proof[self.bit_offset // 8]
        bit_index = self.bit_offset % 8
        self.bit_offset += 1

        return (byte_value >> bit_index) & 1

    def read_unsigned_little_endian_bits(self, bit_count: int) -> int:
        value = 0
        for bit_index in range(bit_count):
            value |= self.read_bit() << bit_index

        return value

    def finish(self) -> None:
        if self.bit_offset >= len(self.proof) * 8:
            raise ValueError("proof encoding has no terminal padding bit")

        byte_index = self.bit_offset // 8
        bit_index = self.bit_offset % 8
        high_mask = (0xFF << bit_index) & 0xFF
        expected = 1 << bit_index
        if self.proof[byte_index] & high_mask != expected:
            raise ValueError("proof encoding has noncanonical terminal padding")

        self.bit_offset = (byte_index + 1) * 8
        if self.bit_offset != len(self.proof) * 8:
            raise ValueError("proof encoding contains trailing data")


def decode_uniform_polynomial_vector(
    reader: ProofBitReader,
    *,
    vector_length: int,
    ring_degree: int,
    modulus: int,
    coefficient_bit_length: int,
) -> None:
    for _ in range(vector_length * ring_degree):
        coefficient = reader.read_unsigned_little_endian_bits(coefficient_bit_length)
        if coefficient >= modulus:
            raise ValueError("uniform polynomial coefficient is not canonical")


def decode_hint_polynomial_vector(
    reader: ProofBitReader,
    *,
    vector_length: int,
    ring_degree: int,
) -> None:
    for _ in range(vector_length * ring_degree):
        first_bit = reader.read_bit()
        second_bit = reader.read_bit()
        if first_bit == 1 and second_bit == 1:
            while reader.read_bit() == 0:
                pass


def decode_gaussian_polynomial_vector(
    reader: ProofBitReader,
    *,
    vector_length: int,
    ring_degree: int,
    log2_standard_deviation: int,
) -> None:
    binary_tail_bit_length = log2_standard_deviation + 1
    for _ in range(vector_length * ring_degree):
        while reader.read_bit() == 1:
            pass
        reader.read_unsigned_little_endian_bits(binary_tail_bit_length)


def record_decoded_field(
    *,
    reader: ProofBitReader,
    field_name: str,
    decode: Any,
) -> dict[str, int | str]:
    start_bit = reader.bit_offset
    decode()
    end_bit = reader.bit_offset

    return {
        "name": field_name,
        "bitOffset": start_bit,
        "bitLength": end_bit - start_bit,
        "byteStart": start_bit // 8,
        "byteEndExclusive": ceil_divide(end_bit, 8),
    }


def decode_proof_field_trace(
    *, proof: bytes, proof_encoding: dict[str, Any]
) -> dict[str, Any]:
    reader = ProofBitReader(proof)
    ring_degree = int(proof_encoding["ringDegree"])
    coefficient_modulus = int(proof_encoding["coefficientModulus"])
    full_size_bit_length = int(proof_encoding["fullSizeCoefficientBitLength"])
    compressed_bit_length = int(proof_encoding["compressedCoefficientBitLength"])

    fields = [
        record_decoded_field(
            reader=reader,
            field_name="commitmentTargetVector",
            decode=lambda: decode_uniform_polynomial_vector(
                reader,
                vector_length=int(proof_encoding["targetCommitmentVectorLength"]),
                ring_degree=ring_degree,
                modulus=coefficient_modulus,
                coefficient_bit_length=full_size_bit_length,
            ),
        ),
        record_decoded_field(
            reader=reader,
            field_name="hashMaskVector",
            decode=lambda: decode_uniform_polynomial_vector(
                reader,
                vector_length=int(proof_encoding["hashMaskVectorLength"]),
                ring_degree=ring_degree,
                modulus=coefficient_modulus,
                coefficient_bit_length=full_size_bit_length,
            ),
        ),
        record_decoded_field(
            reader=reader,
            field_name="compressedCommitmentVector",
            decode=lambda: decode_uniform_polynomial_vector(
                reader,
                vector_length=int(proof_encoding["compressedCommitmentVectorLength"]),
                ring_degree=ring_degree,
                modulus=1 << compressed_bit_length,
                coefficient_bit_length=compressed_bit_length,
            ),
        ),
        record_decoded_field(
            reader=reader,
            field_name="challengePolynomial",
            decode=lambda: decode_uniform_polynomial_vector(
                reader,
                vector_length=1,
                ring_degree=ring_degree,
                modulus=int(proof_encoding["challengeCoefficientModulus"]),
                coefficient_bit_length=int(proof_encoding["challengeCoefficientBitLength"]),
            ),
        ),
        record_decoded_field(
            reader=reader,
            field_name="hintVector",
            decode=lambda: decode_hint_polynomial_vector(
                reader,
                vector_length=int(proof_encoding["hintVectorLength"]),
                ring_degree=ring_degree,
            ),
        ),
        record_decoded_field(
            reader=reader,
            field_name="shortResponseVector",
            decode=lambda: decode_gaussian_polynomial_vector(
                reader,
                vector_length=int(proof_encoding["shortResponseVectorLength"]),
                ring_degree=ring_degree,
                log2_standard_deviation=int(
                    proof_encoding["shortResponseLog2StandardDeviation"]
                ),
            ),
        ),
        record_decoded_field(
            reader=reader,
            field_name="randomnessResponseVector",
            decode=lambda: decode_gaussian_polynomial_vector(
                reader,
                vector_length=int(proof_encoding["randomnessResponseVectorLength"]),
                ring_degree=ring_degree,
                log2_standard_deviation=int(
                    proof_encoding["randomnessResponseLog2StandardDeviation"]
                ),
            ),
        ),
        record_decoded_field(
            reader=reader,
            field_name="euclideanResponseVector",
            decode=lambda: decode_gaussian_polynomial_vector(
                reader,
                vector_length=int(proof_encoding["euclideanResponseVectorLength"]),
                ring_degree=ring_degree,
                log2_standard_deviation=int(
                    proof_encoding["euclideanResponseLog2StandardDeviation"]
                ),
            ),
        ),
        record_decoded_field(
            reader=reader,
            field_name="infinityResponseVector",
            decode=lambda: decode_gaussian_polynomial_vector(
                reader,
                vector_length=int(proof_encoding["infinityResponseVectorLength"]),
                ring_degree=ring_degree,
                log2_standard_deviation=int(
                    proof_encoding["infinityResponseLog2StandardDeviation"]
                ),
            ),
        ),
    ]
    padding_start_bit = reader.bit_offset
    reader.finish()

    return {
        "fullProofBytes": len(proof),
        "fields": fields,
        "terminalPadding": {
            "name": "terminalPadding",
            "bitOffset": padding_start_bit,
            "bitLength": reader.bit_offset - padding_start_bit,
            "byteStart": padding_start_bit // 8,
            "byteEndExclusive": len(proof),
        },
    }

def build_trace(
    *,
    parameter_set: dict[str, Any],
    proof_encoding: dict[str, Any],
    statement_matrix_coefficients: list[list[list[int]]],
    target_vector_coefficients: list[list[int]],
    proof: bytes,
    public_randomness: bytes,
    expected_logical_rejection_layer: str,
    upstream_verifier_accepted: bool | None,
) -> dict[str, Any]:
    try:
        decoded_proof_field_lengths = decode_proof_field_trace(
            proof=proof, proof_encoding=proof_encoding
        )
    except ValueError as error:
        decoded_proof_field_lengths = {
            "fullProofBytes": len(proof),
            "decoderError": str(error),
        }

    trace = {
        "parameterDigest": canonical_json_digest(parameter_set),
        "statementDigest": canonical_json_digest(statement_matrix_coefficients),
        "targetDigest": canonical_json_digest(target_vector_coefficients),
        "proofBytesSha256": hashlib.sha256(proof).hexdigest(),
        "proofSizeBytes": len(proof),
        "publicRandomnessSha256": hashlib.sha256(public_randomness).hexdigest(),
        "sealedLatticePreflightTranscript": build_sealed_lattice_preflight_transcript(
            parameter_set=parameter_set,
            statement_matrix_coefficients=statement_matrix_coefficients,
            target_vector_coefficients=target_vector_coefficients,
            proof=proof,
            public_randomness=public_randomness,
        ),
        "decodedProofFieldLengths": decoded_proof_field_lengths,
        "expectedLogicalRejectionLayer": expected_logical_rejection_layer,
    }
    if upstream_verifier_accepted is not None:
        trace["upstreamVerifierAccepted"] = upstream_verifier_accepted

    return trace
