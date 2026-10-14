import assert from 'node:assert/strict';

import type { OracleInputMask } from '#tests/compressed-oracle/oracle-access.js';
import { littleEndian } from '#tests/exact-integer.js';

// The source-target predicate reads syntax, owner and the immutable family.
// It deliberately leaves the salt, poll and coordinate unconstrained.
// Coefficient validity belongs to the real contribution verifier, not extraction.
export const registrationSourceMask = (
    owner: Uint8Array,
    modulus: Uint8Array,
    sampleBits: bigint,
    degree: number,
) => {
    assert.equal(owner.length, 1952);
    assert.ok(modulus.length > 0 && modulus[modulus.length - 1] !== 0);
    assert.ok(sampleBits > 0n && sampleBits < 2n ** 64n);
    assert.ok(Number.isSafeInteger(degree) && degree > 0);
    const coordinateBytes = degree * (modulus.length + 1);
    assert.ok(
        Number.isSafeInteger(coordinateBytes) && coordinateBytes <= 0xffff_fffb,
    );
    const fixed: { offset: number; bytes: Uint8Array }[] = [];
    let offset = 0;
    const literal = (bytes: Uint8Array) => {
        fixed.push({ offset, bytes: bytes.slice() });
        offset += bytes.length;
    };
    const integer = (value: bigint, byteCount: number) => {
        literal(littleEndian(value, byteCount));
    };
    const header = (type: number, length: number) => {
        integer(BigInt(type), 2);
        integer(BigInt(length), 4);
    };
    integer(1n, 2);
    integer(1n, 2);
    integer(7n, 4);
    const domain = new TextEncoder().encode(
        'sealed-lattice/registered-fhe-key/v2',
    );
    header(2, 4 + domain.length);
    integer(BigInt(domain.length), 4);
    literal(domain);
    header(1, owner.length);
    literal(owner);
    header(1, 64);
    const saltOffset = offset;
    offset += 64;
    header(6, 64);
    offset += 64;
    header(1, 4 + modulus.length);
    integer(BigInt(modulus.length), 4);
    literal(modulus);
    header(5, 8);
    integer(sampleBits, 8);
    header(1, 4 + coordinateBytes);
    integer(BigInt(coordinateBytes), 4);
    offset += coordinateBytes;
    const inputBytes = offset;
    const comparedRawBits =
        8n *
        BigInt(fixed.reduce((total, range) => total + range.bytes.length, 0));
    let inputClassUpper = 1n;
    while (inputClassUpper < 8n * BigInt(inputBytes)) inputClassUpper *= 2n;
    // The maintained cell controller stores raw bits followed by a one and
    // zeros to its fixed class width. All of that suffix is constrained.
    const comparedCellBits =
        comparedRawBits + inputClassUpper + 1n - 8n * BigInt(inputBytes);
    const matches = (bytes: Uint8Array) =>
        bytes.length === inputBytes &&
        fixed.every((range) =>
            range.bytes.every(
                (value, index) => bytes[range.offset + index] === value,
            ),
        );
    return {
        fixed,
        saltOffset,
        inputBytes,
        inputClassUpper,
        comparedRawBits,
        comparedCellBits,
        matches,
    };
};

// A hidden honest source slice additionally fixes its original salt. Owner,
// family and salt can occupy non-adjacent spans of the actual tuple encoding.
export const registrationSourceSliceMask = (
    source: ReturnType<typeof registrationSourceMask>,
    salt: Uint8Array,
): OracleInputMask => {
    assert.equal(salt.length, 64);
    const positions: number[] = [];
    const values: number[] = [];
    for (const range of [
        ...source.fixed,
        { offset: source.saltOffset, bytes: salt },
    ])
        for (const [index, byte] of range.bytes.entries())
            for (let bit = 0; bit < 8; bit++) {
                positions.push(8 * (range.offset + index) + bit);
                values.push((byte >> bit) & 1);
            }
    return {
        inputLength: 8 * source.inputBytes,
        positions,
        values: Uint8Array.from(values),
    };
};

// A syntactic lower bound, even allowing an unsupported one-byte modulus
// and a one-coefficient coordinate. Every real catalogue family is longer.
export const minimumRegistrationSourceInputBytes = () =>
    registrationSourceMask(new Uint8Array(1952), Uint8Array.of(1), 1n, 1)
        .inputBytes;
