import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

export const wideChallengeLayout = (
    oracleCount: number,
    queryCount: number,
    largestLeafBytes: number,
) => {
    for (const count of [oracleCount, queryCount, largestLeafBytes])
        if (!Number.isSafeInteger(count) || count < 1)
            throw new RangeError('Invalid wide-challenge layout.');
    const fieldElements = 2 * oracleCount + 1;
    const requiredBytes = Math.max(
        96 * fieldElements,
        4 * queryCount,
        largestLeafBytes,
    );
    if (!Number.isSafeInteger(requiredBytes))
        throw new RangeError(
            'The challenge layout exceeds exact count arithmetic.',
        );
    let challengeBytes = 1;
    while (challengeBytes < requiredBytes) challengeBytes *= 2;
    if (!Number.isSafeInteger(challengeBytes))
        throw new RangeError(
            'The challenge layout exceeds exact count arithmetic.',
        );
    return {
        fieldElements,
        baseFieldSamples: 3 * fieldElements,
        challengeBytes,
    };
};

export const jointModuloDensityBound = (
    modulus: bigint,
    sampleBits: number,
    sampleCount: number,
) => {
    if (
        !Number.isSafeInteger(sampleBits) ||
        sampleBits < 1 ||
        sampleBits > 4096 ||
        !Number.isSafeInteger(sampleCount) ||
        sampleCount < 1 ||
        modulus < 2n
    )
        throw new RangeError('Invalid challenge sampling bound.');
    const space = 1n << BigInt(sampleBits);
    const total = BigInt(sampleCount) * modulus;
    if (total >= space)
        throw new RangeError('The joint density bound is vacuous.');
    // Each residue has probability at most (1+Q/space)/Q. Expanding the
    // product and bounding binomial coefficients by sampleCount^k gives this
    // geometric upper bound. Soundness pays density, not additive distance.
    return { numerator: space, denominator: space - total };
};

export const compileWideChallengeCompilerCensus = () => {
    const prime = compileSmallLimbProofFieldCensus().modulus;
    const agreement = compileCommonAgreementDegreeCensus();
    const queryCount = agreement.queries;
    // Conditional full word-layout profile. Its complete emitted operator
    // still must establish the algebraic-event bounds below.
    const relation = compileSetupContributionRelationCensus();
    const originalOracles =
        relation.wordColumns +
        relation.booleanColumns +
        relation.lookupEntries +
        4;
    const virtualOracles =
        relation.booleanColumns +
        relation.disjointPairs +
        relation.lookupEntries +
        2;
    const layout = wideChallengeLayout(
        originalOracles + virtualOracles,
        queryCount,
        (relation.lookupEntries + 2) * 48,
    );
    const density = jointModuloDensityBound(
        prime,
        256,
        layout.baseFieldSamples,
    );
    if (density.numerator > 2n * density.denominator)
        throw new Error('The compiler charged an insufficient density factor.');
    const adversaryQueries = 1n << 80n;
    const verificationBudget = 1n << 32n;
    const chargedQueries = 4n * (adversaryQueries + verificationBudget);
    const roleBudget = 1n << 16n;
    const tagBits = 512n;
    const saltBits = 2n * tagBits;
    const relativeBalanceBits = 160n;
    const maximumNonSaltInputBits = 1n << 40n;
    // For each output count, Chernoff gives 2*exp(-2^(kappa-2s)/3).
    // e>2 and 1/3>1/4 give this conservative binary exponent. Union over
    // every bounded non-salt input and every output, before any interaction.
    const balanceTailPower = 1n << (tagBits - 2n * relativeBalanceBits - 2n);
    const balanceFailureExponent =
        balanceTailPower - maximumNonSaltInputBits - tagBits - 2n;
    if (balanceFailureExponent < 256n)
        throw new Error('The all-input hash-balance exception is too large.');
    const committedNodeBudget = 1n << 23n;
    // Two privacy replacements per node, with a role union. Charge epsilon
    // per replacement instead of the smaller epsilon/2 total-variation bound.
    const merklePrivacyNumerator = 2n * roleBudget * committedNodeBudget;
    const merklePrivacyDenominator = 1n << relativeBalanceBits;
    let merklePrivacyBits = 0;
    while (
        merklePrivacyNumerator << BigInt(merklePrivacyBits + 1) <=
        merklePrivacyDenominator
    )
        merklePrivacyBits++;
    const programmedMessageBudget = 32n * roleBudget;
    const reprogrammingSquaredNumerator =
        9n * programmedMessageBudget ** 2n * chargedQueries;
    const reprogrammingSquaredDenominator = 1n << (tagBits + 1n);
    let reprogrammingBits = 0;
    while (
        reprogrammingSquaredNumerator << BigInt(2 * (reprogrammingBits + 1)) <=
        reprogrammingSquaredDenominator
    )
        reprogrammingBits++;
    const fieldSize = prime ** 3n;
    const queryDenominator =
        BigInt(agreement.distanceDenominator) ** BigInt(queryCount);
    const roundErrorNumerator =
        BigInt(agreement.distanceDenominator - agreement.distanceNumerator) **
            BigInt(queryCount) *
            fieldSize +
        16n * (1n << 32n) * queryDenominator;
    const roundErrorDenominator = queryDenominator * fieldSize;
    const tagSpace = 1n << tagBits;
    // Prefix-BCS extension: full verifier messages, at most four reference
    // labels per hash input, and a two-fold modulo-density charge.
    const failureNumerator =
        roleBudget *
        (24n * chargedQueries ** 2n * roundErrorNumerator * tagSpace +
            (120n * chargedQueries ** 3n + 2n * verificationBudget) *
                roundErrorDenominator);
    const failureDenominator = roundErrorDenominator * tagSpace;
    let failureBits = 0;
    while (failureNumerator << BigInt(failureBits + 1) <= failureDenominator)
        failureBits++;
    return {
        ...layout,
        queryCount,
        tagBits,
        saltBits,
        relativeBalanceBits,
        maximumNonSaltInputBits,
        committedNodeBudget,
        merklePrivacyBits,
        programmedMessageBudget,
        reprogrammingBits,
        adversaryQueries,
        verificationBudget,
        chargedQueries,
        roleBudget,
        failureNumerator,
        failureDenominator,
        failureBits,
    };
};
