import { bitLength } from '#tests/exact-integer.js';

type SignatureParameters = Readonly<{
    modulus: bigint;
    polynomialDegree: bigint;
    rowCount: bigint;
    columnCount: bigint;
    secretCoefficientBound: bigint;
    challengeWeight: bigint;
    roundingBits: bigint;
    maskingBound: bigint;
    roundingBound: bigint;
}>;

// ML-DSA-65 operands transcribed from FIPS 204 Table 1; the challenge seed
// has lambda/4 bytes and omega = 55 bounds the hint weight. Their test checks
// the key and signature sizes derived below against FIPS 204 Table 2.
export const mlDsa65ChallengeSeedBytes = 192n / 4n;
const mlDsa65HintWeight = 55n;
// The pinned implementation uses a u16 nonce in FIPS 204 ExpandMask.
export const mlDsa65MaskNonceBytes = 2n;
// FIPS 204 Algorithm 6: independent key-generation seed and public rho.
export const mlDsa65KeySeedBytes = 32n;
export const mlDsa65PublicMatrixSeedBytes = 32n;
export const mlDsa65Parameters: SignatureParameters = {
    modulus: 8380417n,
    polynomialDegree: 256n,
    rowCount: 6n,
    columnCount: 5n,
    secretCoefficientBound: 4n,
    challengeWeight: 49n,
    roundingBits: 13n,
    maskingBound: 1n << 19n,
    roundingBound: (8380417n - 1n) / 32n,
};

// FIPS 204 Algorithms 22, 24 and 26 output 32 + 32k(bitlen(q-1)-d),
// 128 + 32((k+l)bitlen(2 eta)+dk) and lambda/4 + 32l(1+bitlen(gamma1-1))
// + omega + k bytes. Beyond the seeds and the hint, a packed polynomial takes
// n/8 = 32 bytes per bit of coefficient width.
export const mlDsa65EncodedSizes = (parameters: SignatureParameters) => {
    const width = (value: bigint) => BigInt(bitLength(value));
    const polynomialBytes = (coefficientBits: bigint): bigint =>
        (parameters.polynomialDegree * coefficientBits) / 8n;
    return {
        publicKeyBytes:
            32n +
            parameters.rowCount *
                polynomialBytes(
                    width(parameters.modulus - 1n) - parameters.roundingBits,
                ),
        privateKeyBytes:
            32n +
            32n +
            64n +
            (parameters.rowCount + parameters.columnCount) *
                polynomialBytes(width(2n * parameters.secretCoefficientBound)) +
            parameters.rowCount * polynomialBytes(parameters.roundingBits),
        signatureBytes:
            mlDsa65ChallengeSeedBytes +
            parameters.columnCount *
                polynomialBytes(1n + width(parameters.maskingBound - 1n)) +
            mlDsa65HintWeight +
            parameters.rowCount,
    };
};
export const mlDsa65Sizes = mlDsa65EncodedSizes(mlDsa65Parameters);
