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
// has lambda/4 bytes. Their test derives the FIPS 204 Table 2 key and
// signature sizes from them.
export const mlDsa65ChallengeSeedBytes = 192n / 4n;
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
