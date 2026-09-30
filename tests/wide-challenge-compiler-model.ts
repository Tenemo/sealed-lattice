import { compileBallotEncryptionRelationCensus } from '#tests/ballot-encryption-relation-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileLinkedReleaseRelationCensus } from '#tests/linked-release-relation-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { deriveSetupContributionShape } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

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

// The compiler's charged caps are the same for every supported profile. The
// ledger charges them, and the proof chronology model checks that one poll of
// every profile, with a registration for every honest credential of the
// largest population, stays within them. The query cap bounds every oracle
// call of the experiment, including honest proving, verification and
// expansion, and prefix and role routing make at most four base calls of each.
// The role budget bounds the corrupt roles whose proofs can be accepted, and
// the honest-proof budget the simulated honest proofs, each of which programs
// one verifier message.
const adversaryQueries = 1n << 80n;
const roleBudget = 1n << 16n;
const honestProofBudget = 1n << 28n;
const tagBits = 512n;
export const proofCompilerCaps = {
    adversaryQueries,
    chargedQueries: 4n * adversaryQueries,
    roleBudget,
    honestProofBudget,
    tagBits,
    saltBits: 2n * tagBits,
    relativeBalanceBits: 160n,
    maximumNonSaltInputBits: 1n << 40n,
    committedNodeBudget: 1n << 23n,
    programmedMessageBudget: honestProofBudget,
} as const;

export const compileProofCompilerCapCensus = () => {
    const {
        chargedQueries,
        relativeBalanceBits,
        maximumNonSaltInputBits,
        committedNodeBudget,
        programmedMessageBudget,
    } = proofCompilerCaps;
    // For each output count, Chernoff gives 2*exp(-2^(kappa-2s)/3).
    // e>2 and 1/3>1/4 give this conservative binary exponent. Union over
    // every bounded non-salt input and every output, before any interaction.
    const balanceTailPower = 1n << (tagBits - 2n * relativeBalanceBits - 2n);
    const balanceFailureExponent =
        balanceTailPower - maximumNonSaltInputBits - tagBits - 2n;
    if (balanceFailureExponent < 256n)
        throw new Error('The all-input hash-balance exception is too large.');
    // Two privacy replacements per node of every honest proof. Charge epsilon
    // per replacement instead of the smaller epsilon/2 total-variation bound.
    const merklePrivacyNumerator = 2n * honestProofBudget * committedNodeBudget;
    const merklePrivacyDenominator = 1n << relativeBalanceBits;
    let merklePrivacyBits = 0;
    while (
        merklePrivacyNumerator << BigInt(merklePrivacyBits + 1) <=
        merklePrivacyDenominator
    )
        merklePrivacyBits++;
    const reprogrammingSquaredNumerator =
        9n * programmedMessageBudget ** 2n * chargedQueries;
    const reprogrammingSquaredDenominator = 1n << (tagBits + 1n);
    let reprogrammingBits = 0;
    while (
        reprogrammingSquaredNumerator << BigInt(2 * (reprogrammingBits + 1)) <=
        reprogrammingSquaredDenominator
    )
        reprogrammingBits++;
    return {
        ...proofCompilerCaps,
        balanceFailureExponent,
        merklePrivacyBits,
        reprogrammingBits,
    };
};

// The counts of an accepted proof role's word relation that its round error
// grows with: its committed and virtual oracles, its lookup entries and its
// affine rows.
const proofEvents = (
    name: string,
    relation: Readonly<{
        wordColumns: number;
        booleanColumns: number;
        lookupEntries: number;
        zeroProducts: number;
        affineRows: bigint;
    }>,
) => ({
    name,
    originalOracles:
        relation.wordColumns +
        relation.booleanColumns +
        relation.lookupEntries +
        4,
    virtualOracles:
        relation.booleanColumns +
        relation.zeroProducts +
        relation.lookupEntries +
        2,
    lookupEntries: relation.lookupEntries,
    affineRows: relation.affineRows,
});

// Ordinary IOP event counts for one profile's full word relation, which is
// the largest proof operator of that profile: the union over accepted proof
// roles charges every role these counts, so the registration, ballot and
// release relations must not exceed them in any count. The QROM compilation
// and whole-protocol assumptions remain separate obligations.
export const compileWideChallengeCompilerCensus = (
    profile: SupportedProfile,
) => {
    const prime = compileSmallLimbProofFieldCensus().modulus;
    const agreement = compileCommonAgreementDegreeCensus();
    const queryCount = agreement.queries;
    const relation = deriveSetupContributionShape(profile);
    const { originalOracles, virtualOracles } = proofEvents('setup', {
        ...relation,
        zeroProducts: relation.disjointPairs,
    });
    const registration = compileRegistrationKeyRelationCensus();
    const ballot = compileBallotEncryptionRelationCensus(profile);
    const release = compileLinkedReleaseRelationCensus(profile);
    for (const role of [
        proofEvents('registration', {
            ...registration,
            lookupEntries: registration.lookups,
            zeroProducts: registration.disjointPairs,
        }),
        proofEvents('ballot', {
            ...ballot,
            zeroProducts: ballot.additionalQuadraticConstraints,
        }),
        // The release secret's positive and negative columns are its one
        // zero product.
        proofEvents('release', { ...release, zeroProducts: 1 }),
    ])
        if (
            role.originalOracles > originalOracles ||
            role.virtualOracles > virtualOracles ||
            role.lookupEntries > relation.lookupEntries ||
            role.affineRows > relation.affineRows
        )
            throw new Error(
                'The ' + role.name + ' proof exceeds the charged proof events.',
            );
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
    const caps = compileProofCompilerCapCensus();
    const { chargedQueries } = caps;
    const fieldSize = prime ** 3n;
    const lookupEntryCount =
        BigInt(relation.lookupEntries) * BigInt(agreement.systematicSize);
    if (lookupEntryCount >= prime)
        throw new Error('Lookup multiplicities can vanish in the base field.');
    const lookupRootDegree =
        lookupEntryCount + BigInt(agreement.systematicSize) - 1n;
    const lookupChallengeSpace = prime * prime * (prime - 1n);
    const affineRootDegree = relation.affineRows;
    const correlatedRowCount = 2n * BigInt(originalOracles + virtualOracles);
    // BCIKS20 Theorem 6.1, plus the coalesced first fold from BGKTTZ23
    // Corollary 5.5. The restricted lookup challenge costs less than two.
    const batchingAndFirstFoldNumerator =
        (correlatedRowCount + 1n) * BigInt(agreement.domainSize);
    const ordinaryAlgebraicNumerator = [
        2n * lookupRootDegree,
        affineRootDegree + 1n,
        batchingAndFirstFoldNumerator,
    ].reduce((maximum, value) => (value > maximum ? value : maximum), 0n);
    const queryDenominator =
        BigInt(agreement.distanceDenominator) ** BigInt(queryCount);
    const roundErrorNumerator =
        BigInt(agreement.distanceDenominator - agreement.distanceNumerator) **
            BigInt(queryCount) *
            fieldSize +
        ordinaryAlgebraicNumerator * queryDenominator;
    const roundErrorDenominator = queryDenominator * fieldSize;
    const tagSpace = 1n << tagBits;
    // Prefix-BCS extension: full verifier messages, at most four reference
    // labels per hash input, and a two-fold modulo-density charge.
    const failureNumerator =
        roleBudget *
        (24n * chargedQueries ** 2n * roundErrorNumerator * tagSpace +
            (120n * chargedQueries ** 3n + 2n * chargedQueries) *
                roundErrorDenominator);
    const failureDenominator = roundErrorDenominator * tagSpace;
    let failureBits = 0;
    while (failureNumerator << BigInt(failureBits + 1) <= failureDenominator)
        failureBits++;
    return {
        ...caps,
        ...layout,
        originalOracles,
        virtualOracles,
        queryCount,
        lookupEntryCount,
        lookupRootDegree,
        lookupChallengeSpace,
        affineRootDegree,
        correlatedRowCount,
        batchingAndFirstFoldNumerator,
        ordinaryAlgebraicNumerator,
        failureNumerator,
        failureDenominator,
        failureBits,
    };
};
