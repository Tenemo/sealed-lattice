import assert from 'node:assert/strict';

// The source-target predicate reads syntax, owner and the immutable family.
// It deliberately leaves the salt, poll, runtime and coordinate unconstrained.
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
    const integer = (width: number, value: bigint) => {
        const bytes = new Uint8Array(width);
        for (let index = 0; index < width; index++) {
            bytes[index] = Number(value & 255n);
            value >>= 8n;
        }
        assert.equal(value, 0n);
        literal(bytes);
    };
    const header = (type: number, length: number) => {
        integer(2, BigInt(type));
        integer(4, BigInt(length));
    };
    integer(2, 1n);
    integer(2, 1n);
    integer(4, 8n);
    const domain = new TextEncoder().encode(
        'sealed-lattice/registered-fhe-key/v1',
    );
    header(2, 4 + domain.length);
    integer(4, BigInt(domain.length));
    literal(domain);
    header(1, owner.length);
    literal(owner);
    header(1, 64);
    offset += 64;
    for (let hash = 0; hash < 2; hash++) {
        header(6, 64);
        offset += 64;
    }
    header(1, 4 + modulus.length);
    integer(4, BigInt(modulus.length));
    literal(modulus);
    header(4, 8);
    integer(8, sampleBits);
    header(1, 4 + coordinateBytes);
    integer(4, BigInt(coordinateBytes));
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
        inputBytes,
        inputClassUpper,
        comparedRawBits,
        comparedCellBits,
        matches,
    };
};
