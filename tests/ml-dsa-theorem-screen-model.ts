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

// FIPS 204 Table 1, ML-DSA-65. These independently maintained operands are
// checked against the deployed fips204 source by the research audit.
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

// JMW24 equation (48) and Table 2, the paper's middle proposed parameter set.
// A positive control for the inequality, not a proposed implementation change.
export const publishedDilithiumComparison: SignatureParameters = {
    modulus: 12439554041857n,
    polynomialDegree: 512n,
    rowCount: 12n,
    columnCount: 8n,
    secretCoefficientBound: 2n,
    challengeWeight: 40n,
    roundingBits: 15n,
    maskingBound: 370432n,
    roundingBound: 740864n,
};

export const screenSelfTargetReduction = (parameters: SignatureParameters) => {
    const {
        modulus,
        polynomialDegree,
        rowCount,
        columnCount,
        secretCoefficientBound,
        challengeWeight,
        roundingBits,
        maskingBound,
        roundingBound,
    } = parameters;
    if (Object.values(parameters).some((value) => value <= 0n))
        throw new RangeError('The theorem operands must be positive.');
    const responseBound =
        maskingBound - secretCoefficientBound * challengeWeight;
    if (responseBound <= 0n)
        throw new RangeError('Invalid signature response bound.');
    const roundedRelationBound =
        2n * roundingBound + 1n + (1n << (roundingBits - 1n)) * challengeWeight;
    // JMW24 equation (38), followed by Theorem 2 as instantiated in (41).
    const signatureVectorBound =
        responseBound > roundedRelationBound
            ? responseBound
            : roundedRelationBound;
    const errorCoefficient =
        2n *
        signatureVectorBound *
        polynomialDegree *
        (rowCount + columnCount + 1n);
    const strictUpperBound = modulus / 32n;
    const maximumAuxiliaryError =
        strictUpperBound === 0n
            ? 0n
            : (strictUpperBound - 1n) / errorCoefficient;
    return {
        responseBound,
        roundedRelationBound,
        signatureVectorBound,
        errorCoefficient,
        strictUpperBound,
        maximumAuxiliaryError,
        splitModulusCondition:
            modulus >= 16n && (modulus - 1n) % (2n * polynomialDegree) === 0n,
    };
};
