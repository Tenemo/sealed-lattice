import { compileBallotEncryptionRelationCensus } from '#tests/ballot-encryption-relation-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileLinkedReleaseRelationCensus } from '#tests/linked-release-relation-model.js';
import { deriveSetupContributionShape } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { compileWeightedFriBound } from '#tests/weighted-fri-bound-model.js';

type ProofPurpose = 'setup' | 'ballot' | 'release';

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

// The actual supported-profile relation constructors: two fixed words and
// one setup word sized for that relation's complete combination message.
export const proofVerifierMessageBytes = (
    purpose: ProofPurpose,
    oracles: number,
    queryCount: number,
    largestLeafBytes: number,
) =>
    purpose === 'setup'
        ? wideChallengeLayout(oracles, queryCount, largestLeafBytes)
              .challengeBytes
        : 262_144;

// The compiler's charged caps are the same for every supported profile. The
// ledger charges them, and the proof chronology model checks that one poll of
// every profile against the reference population. The clear-candidate global
// population and semantic-use inventory remain separate obligations. The query cap bounds every oracle
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
    name: ProofPurpose,
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

const activeProofEvents = (profile: SupportedProfile) => {
    const setup = deriveSetupContributionShape(profile);
    const ballot = compileBallotEncryptionRelationCensus(profile);
    const release = compileLinkedReleaseRelationCensus(profile);
    return [
        proofEvents('setup', { ...setup, zeroProducts: setup.disjointPairs }),
        proofEvents('ballot', {
            ...ballot,
            zeroProducts: ballot.additionalQuadraticConstraints,
        }),
        proofEvents('release', { ...release, zeroProducts: 1 }),
    ];
};

type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const largestFraction = (values: readonly Fraction[]) =>
    values.reduce((maximum, value) =>
        value.numerator * maximum.denominator >
        maximum.numerator * value.denominator
            ? value
            : maximum,
    );

// Current conditional ordinary RBR operands for each fixed protocol family.
// No role-population union, QROM composition or end-to-end level is asserted.
export const compileProofRoundErrorCensus = (profile: SupportedProfile) => {
    const field = compileSmallLimbProofFieldCensus();
    const prime = field.modulus;
    const fieldSize = prime ** 3n;
    const agreement = compileCommonAgreementDegreeCensus();
    const domain = BigInt(agreement.domainSize);
    const systematic = BigInt(agreement.systematicSize);
    if (2 * agreement.codeDimension !== agreement.domainSize)
        throw new Error('The weighted FRI screen requires rate one half.');
    const alphaNumerator = BigInt(
        agreement.distanceDenominator - agreement.distanceNumerator,
    );
    const alphaDenominator = BigInt(agreement.distanceDenominator);
    const weightedFri = compileWeightedFriBound(
        domain,
        alphaNumerator,
        alphaDenominator,
    );
    const queryError = {
        numerator: alphaNumerator ** BigInt(agreement.queries),
        denominator: alphaDenominator ** BigInt(agreement.queries),
    };
    const roles = activeProofEvents(profile).map((role) => {
        const oracles = role.originalOracles + role.virtualOracles;
        const largestLeafBytes = Number(
            BigInt(role.lookupEntries + 2) *
                field.packedExtensionElementByteLength,
        );
        const layout = wideChallengeLayout(
            oracles,
            agreement.queries,
            largestLeafBytes,
        );
        const density = jointModuloDensityBound(
            prime,
            256,
            layout.baseFieldSamples,
        );
        const lookupEntryCount = BigInt(role.lookupEntries) * systematic;
        if (lookupEntryCount >= prime)
            throw new Error(
                'Lookup multiplicities can vanish in the base field.',
            );
        const lookupRootDegree = lookupEntryCount + systematic - 1n;
        const lookupChallengeSpace = prime * prime * (prime - 1n);
        const batchingNumerator = 2n * BigInt(oracles) * domain;
        const uniformAlgebraic = largestFraction([
            { numerator: lookupRootDegree, denominator: lookupChallengeSpace },
            { numerator: role.affineRows + 1n, denominator: fieldSize },
            {
                numerator:
                    batchingNumerator * weightedFri.upper.denominator +
                    weightedFri.upper.numerator,
                denominator: weightedFri.upper.denominator * fieldSize,
            },
        ]);
        const sampledAlgebraic = {
            numerator: density.numerator * uniformAlgebraic.numerator,
            denominator: density.denominator * uniformAlgebraic.denominator,
        };
        return {
            ...role,
            ...layout,
            messageBytes: proofVerifierMessageBytes(
                role.name,
                oracles,
                agreement.queries,
                largestLeafBytes,
            ),
            density,
            lookupEntryCount,
            lookupRootDegree,
            lookupChallengeSpace,
            batchingNumerator,
            uniformAlgebraic,
            sampledAlgebraic,
            queryDominates:
                queryError.numerator * sampledAlgebraic.denominator >=
                sampledAlgebraic.numerator * queryError.denominator,
            roundError: largestFraction([queryError, sampledAlgebraic]),
        };
    });
    return {
        prime,
        fieldSize,
        weightedFri,
        queryError,
        roles,
        maximumRoundError: largestFraction(
            roles.map((role) => role.roundError),
        ),
    };
};

// Ordinary IOP event counts for one profile's full word relation, which is
// the largest proof operator of that profile: the union over accepted proof
// roles charges every role these counts, so the ballot and
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
    const ballot = compileBallotEncryptionRelationCensus(profile);
    const release = compileLinkedReleaseRelationCensus(profile);
    for (const role of [
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
    const sampledRounds = compileProofRoundErrorCensus(profile);
    // BCIKS20 correlated batching and the weighted-state first fold share
    // one verifier message, so their bounds add. The historical unweighted
    // extra L term did not cover the actual remaining consistency weights.
    const batchingAndFirstFoldNumerator =
        correlatedRowCount * BigInt(agreement.domainSize) +
        sampledRounds.weightedFri.ceiling;
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
    // Historical role-union reference arithmetic: retain its conservative
    // two-fold density charge and query-plus-algebraic sum. The current
    // per-role exact maximum above has no assumed corrupt-role population.
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
        weightedFri: sampledRounds.weightedFri,
        sampledRoundError: sampledRounds.maximumRoundError,
        failureNumerator,
        failureDenominator,
        failureBits,
    };
};
