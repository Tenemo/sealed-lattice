import assert from 'node:assert/strict';

import { compileCurrentSignatureSamplingBounds } from '#tests/authentication-work-model.js';
import { compileBallotRandomnessBudget } from '#tests/ballot-randomness-budget-model.js';
import { compileCommitmentEquivocationBound } from '#tests/commitment-equivocation-model.js';
import { compileCommitmentExtractionBound } from '#tests/commitment-extraction-bound-model.js';
import {
    compileCommonMatrixInitializationCensus,
    compileCommonMatrixSamplingCensus,
} from '#tests/common-matrix-sampling-model.js';
import {
    prefixOracleQueriesPerAccess,
    sparseRoutingWork,
} from '#tests/compressed-oracle-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFixedModulusBfvCensus } from '#tests/fixed-modulus-bfv-model.js';
import { prefixReplacementBaseQueriesPerAccess } from '#tests/oracle-domain-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileProofRandomnessBudgets } from '#tests/proof-randomness-budget-model.js';
import { compileRecipientKeyUniquenessBound } from '#tests/recipient-key-uniqueness-model.js';
import { compileSetupRandomnessCensus } from '#tests/setup-randomness-model.js';
import { compileSupportedThresholdCompletionProfiles } from '#tests/threshold-completion-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

// Frozen requirement VI.2. A protocol has this many bits when every adversary
// whose complete experiment costs T gates has advantage at most T/2^bits.
export const securityTargetBits = 80n;

// FIPS 202 section 3: Keccak-f[1600] has lane width w=b/25, l=log2(w) and
// 12+2l rounds, and chi multiplies two state bits for every state bit in every
// round. SHAKE128 has capacity 256, the widest rate of either SHAKE function.
export const keccakReferenceCost = (() => {
    const stateBits = 1600n;
    const laneBits = stateBits / 25n;
    let laneExponent = 0n;
    while (1n << laneExponent < laneBits) laneExponent += 1n;
    const rounds = 12n + 2n * laneExponent;
    return {
        stateBits,
        rounds,
        widestRateBits: stateBits - 256n,
        // A call is charged chi's multiplications only, fewer gates than any
        // complete circuit for the reference permutation.
        permutationCharge: stateBits * rounds,
    };
})();

export type Rational = Readonly<{ numerator: bigint; denominator: bigint }>;

export const rational = (numerator: bigint, denominator = 1n): Rational => {
    assert.ok(numerator >= 0n && denominator > 0n);
    return { numerator, denominator };
};

const addRationals = (...values: readonly Rational[]): Rational =>
    values.reduce(
        (sum, value) =>
            rational(
                sum.numerator * value.denominator +
                    value.numerator * sum.denominator,
                sum.denominator * value.denominator,
            ),
        rational(0n),
    );

const multiplyRationals = (left: Rational, right: Rational): Rational =>
    rational(
        left.numerator * right.numerator,
        left.denominator * right.denominator,
    );

// Smallest integer k with value <= 2^k.
export const ceilingLog2 = (value: Rational): bigint => {
    assert.ok(value.numerator > 0n);
    let exponent = 0n;
    while (value.numerator > value.denominator << exponent) exponent += 1n;
    while (value.numerator << 1n <= value.denominator << exponent)
        exponent -= 1n;
    return exponent;
};

const statisticalDenominatorBits = 256n;

// Round a probability upward to a multiple of 2^-256 so the subtotal is an
// exact upper bound.
const dyadic = (numerator: bigint, denominator: bigint): bigint => {
    assert.ok(numerator >= 0n && denominator > 0n && numerator <= denominator);
    return (
        (numerator * (1n << statisticalDenominatorBits) + denominator - 1n) /
        denominator
    );
};

const power = (bits: bigint) =>
    bits >= statisticalDenominatorBits
        ? 1n
        : 1n << (statisticalDenominatorBits - bits);

export const supportedParticipantCounts =
    compileSupportedThresholdCompletionProfiles().map(
        (profile) => profile.participantCount,
    );
const largestParticipantCount = Math.max(...supportedParticipantCounts);

type StatisticalTerm = Readonly<{ name: string; numerator: bigint }>;

let credentialIndependentTerms:
    | Readonly<{ adversaryQueries: bigint; terms: readonly StatisticalTerm[] }>
    | undefined;

// Terms that do not depend on the honest credential population. Terms that
// depend on the roster take the largest supported roster; the others keep
// their ten-participant models.
const statisticalTermsWithoutCredentials = () => {
    if (credentialIndependentTerms !== undefined)
        return credentialIndependentTerms;
    const compiler = compileWideChallengeCompilerCensus();
    const extraction = compileCommitmentExtractionBound(
        largestParticipantCount,
        prefixReplacementBaseQueriesPerAccess *
            prefixOracleQueriesPerAccess *
            compiler.adversaryQueries,
    );
    const matrices = compileCommonMatrixSamplingCensus();
    const matrixInitialization = compileCommonMatrixInitializationCensus();
    const sharing = compileWideShareLiftingCensus();
    const releaseJournal = compileParticipantReleaseCustody();
    const ranking = compileFixedModulusBfvCensus();
    assert.ok(ranking.releaseCorrect && ranking.jointStatisticalBoundHolds);
    const sampling = compileSetupRandomnessCensus();
    credentialIndependentTerms = {
        adversaryQueries: compiler.adversaryQueries,
        terms: [
            {
                name: 'Fixed common matrix sampling',
                numerator: dyadic(
                    matrices.distanceUpperNumerator,
                    matrices.distanceUpperDenominator,
                ),
            },
            {
                name: 'Fixed common matrix fibre initialization',
                numerator: dyadic(
                    matrixInitialization.biasNumerator,
                    matrixInitialization.biasDenominator,
                ),
            },
            ...compileCurrentSignatureSamplingBounds().map((row) => ({
                name: `${row.purpose} all-seed read bound`,
                numerator: dyadic(row.numerator, 1n << row.denominatorBits),
            })),
            {
                name: 'Bounded recipient-key collision',
                numerator: power(
                    compileRecipientKeyUniquenessBound()
                        .uniformMatrixFailureExponent,
                ),
            },
            {
                name: 'Preparation Gaussian sampling',
                numerator: dyadic(
                    sampling.preparationVariationNumerator,
                    sampling.preparationVariationDenominator,
                ),
            },
            {
                name: 'Integer sharing translation',
                numerator: dyadic(
                    sharing.privacyNumerator,
                    2n * sharing.sharingRadius,
                ),
            },
            {
                name: 'One-target release coupling',
                numerator: power(BigInt(ranking.statisticalBits)),
            },
            {
                name: 'Corrupt-body extraction',
                numerator: dyadic(
                    extraction.combinedFailureNumerator,
                    extraction.denominator,
                ),
            },
            {
                name: 'Wide-message proof soundness',
                numerator: dyadic(
                    compiler.failureNumerator,
                    compiler.failureDenominator,
                ),
            },
            {
                name: 'Merkle privacy',
                numerator: power(BigInt(compiler.merklePrivacyBits)),
            },
            {
                name: 'Proof reprogramming',
                numerator: power(BigInt(compiler.reprogrammingBits)),
            },
            {
                name: 'Ballot journal exhaustion',
                numerator: power(
                    compileBallotRandomnessBudget().exhaustionBits,
                ),
            },
            {
                name: 'Release journal exhaustion',
                numerator: dyadic(
                    releaseJournal.exhaustionBound.numerator,
                    1n << releaseJournal.exhaustionBound.denominatorBits,
                ),
            },
            ...compileProofRandomnessBudgets().map((value) => ({
                name: `${value.role.charAt(0).toUpperCase()}${value.role.slice(1)} simulator field sampling`,
                numerator: dyadic(
                    value.failure.numerator,
                    1n << value.failure.denominatorBits,
                ),
            })),
        ],
    };
    return credentialIndependentTerms;
};

// Statistical terms evaluated at the proof compiler's query cap. A charged
// oracle call costs at least one permutation charge, so the cap covers every
// experiment of at most 2^80 gates, and every term is nondecreasing in the
// query count. The subtotal therefore bounds Adv(T)/T for 1 <= T <= 2^80.
const compileStatisticalLedger = (
    potentialCredentialCount = BigInt(largestParticipantCount),
) => {
    const fixed = statisticalTermsWithoutCredentials();
    assert.ok(
        fixed.adversaryQueries * keccakReferenceCost.permutationCharge >=
            1n << securityTargetBits,
    );
    const equivocation = compileCommitmentEquivocationBound(
        largestParticipantCount,
        potentialCredentialCount,
    );
    assert.equal(equivocation.quantumQueryCount, fixed.adversaryQueries);
    const terms: readonly StatisticalTerm[] = [
        ...fixed.terms,
        {
            name: 'Honest-body equivocation',
            numerator: dyadic(equivocation.numerator, equivocation.denominator),
        },
        {
            name: 'Honest signing credential collision',
            numerator: dyadic(
                equivocation.credentialCollisionNumerator,
                equivocation.credentialCollisionDenominator,
            ),
        },
    ];
    const subtotalNumerator = terms.reduce(
        (sum, term) => sum + term.numerator,
        0n,
    );
    return {
        participantCount: largestParticipantCount,
        potentialCredentialCount,
        adversaryQueries: fixed.adversaryQueries,
        denominatorBits: statisticalDenominatorBits,
        terms,
        subtotalNumerator,
        subtotalExponent: ceilingLog2(
            rational(subtotalNumerator, 1n << statisticalDenominatorBits),
        ),
    };
};

// Gates of the maintained sparse-oracle routing circuit per stored entry and
// per call, split into the coefficients of c0 + c1*in + c2*out.
export const sparseRoutingCoefficients = (() => {
    const routing = (entries: bigint, inputBits: bigint, outputBits: bigint) =>
        sparseRoutingWork(entries, inputBits, outputBits).routingGates;
    const entryAt = (inputBits: bigint, outputBits: bigint) =>
        routing(1n, inputBits, outputBits) - routing(0n, inputBits, outputBits);
    const entryPerInputBit = entryAt(2n, 1n) - entryAt(1n, 1n);
    const entryPerOutputBit = entryAt(1n, 2n) - entryAt(1n, 1n);
    const callPerInputBit = routing(0n, 2n, 1n) - routing(0n, 1n, 1n);
    const callPerOutputBit = routing(0n, 1n, 2n) - routing(0n, 1n, 1n);
    return {
        entryConstant: entryAt(1n, 1n) - entryPerInputBit - entryPerOutputBit,
        entryPerInputBit,
        entryPerOutputBit,
        callConstant: routing(0n, 1n, 1n) - callPerInputBit - callPerOutputBit,
        callPerInputBit,
        callPerOutputBit,
        localUpdatePerOutputBit:
            sparseRoutingWork(0n, 1n, 2n).localUpdateGates -
            sparseRoutingWork(0n, 1n, 1n).localUpdateGates,
    };
})();

const maximumOf = (...values: readonly bigint[]) =>
    values.reduce((maximum, value) => (value > maximum ? value : maximum));

let reductionOperandCache:
    | Readonly<{ programmedMessageBudget: bigint; senderPrefixBits: bigint }>
    | undefined;

const reductionOperands = () =>
    (reductionOperandCache ??= {
        programmedMessageBudget:
            compileWideChallengeCompilerCensus().programmedMessageBudget,
        senderPrefixBits:
            8n * compileContributionBodyCensus().senderPrefixBytes,
    });

// Reduction work relative to the complete experiment's charged cost T, which
// includes every honest operation, in the gate basis of the compressed-oracle
// circuits and without quantum random-access memory. Tred(T)/T is at most
// plain + linear + extraction + quadratic*T for a reduction that extracts, and
// at most plain for one that does not.
export const compileReductionWork = (
    potentialCredentialCount: bigint,
    extractedCommitmentCount: bigint,
    callCharge: Readonly<{
        callsPerCharge: Rational;
        storedBitsPerCharge: Rational;
    }> = {
        // A call on in input bits and out >= 1 output bits runs
        // ceil((in+6)/r)+ceil(out/r)-1 >= 1 permutations, so in+out <= 2r per
        // permutation, and an entry of in+out+1 stored bits costs at least
        // permutationCharge/(2r+1) per bit.
        callsPerCharge: rational(1n, keccakReferenceCost.permutationCharge),
        storedBitsPerCharge: rational(
            2n * keccakReferenceCost.widestRateBits + 1n,
            keccakReferenceCost.permutationCharge,
        ),
    },
) => {
    assert.ok(potentialCredentialCount >= 1n && extractedCommitmentCount >= 0n);
    const { callsPerCharge, storedBitsPerCharge } = callCharge;
    const coefficients = sparseRoutingCoefficients;
    // An entry routes in c0 + c1*in + c2*out <= perStoredBit*(in+out+1) +
    // entryExcess gates.
    const perStoredBit = maximumOf(
        coefficients.entryPerInputBit,
        coefficients.entryPerOutputBit,
    );
    const entryExcess = coefficients.entryConstant - perStoredBit;
    assert.ok(entryExcess >= 0n);
    const baseCallsPerAccess =
        prefixReplacementBaseQueriesPerAccess * prefixOracleQueriesPerAccess;
    // Every base call routes over every stored entry in both directions. At
    // most T*callsPerCharge accesses meet at most T*storedBitsPerCharge
    // stored bits in T*callsPerCharge entries.
    const quadraticCoefficient = multiplyRationals(
        rational(2n * baseCallsPerAccess),
        addRationals(
            multiplyRationals(
                rational(perStoredBit),
                multiplyRationals(storedBitsPerCharge, callsPerCharge),
            ),
            multiplyRationals(
                rational(entryExcess),
                multiplyRationals(callsPerCharge, callsPerCharge),
            ),
        ),
    );
    // A call visits at most one length-class and output-chunk cell per class,
    // so at most (80+2)^2 cells for widths below 2^80, each at most twice the
    // call's widths. The per-call part is at most its largest coefficient per
    // bit of in+out+1.
    const callPerBit = maximumOf(
        coefficients.callConstant,
        coefficients.callPerInputBit,
        coefficients.callPerOutputBit,
    );
    const maximumCells = (securityTargetBits + 2n) ** 2n;
    const linearCoefficient = multiplyRationals(
        rational(
            baseCallsPerAccess *
                (2n * callPerBit * 2n * maximumCells +
                    coefficients.localUpdatePerOutputBit),
        ),
        storedBitsPerCharge,
    );
    // Each extraction evaluates a clean relation reading every stored bit at
    // most twice and selects the first match.
    const extractionCoefficient = multiplyRationals(
        rational(extractedCommitmentCount * (4n * perStoredBit + 6n)),
        storedBitsPerCharge,
    );
    const operands = reductionOperands();
    const programmedPoints =
        operands.programmedMessageBudget + potentialCredentialCount;
    const plainCoefficient = addRationals(
        // The experiment, a shadow and a background call per access, and
        // corrupt-input recovery, bounded by the experiment's own verification.
        rational(4n),
        // Sender membership among every potential honest credential.
        multiplyRationals(
            rational(
                potentialCredentialCount *
                    perStoredBit *
                    operands.senderPrefixBits,
            ),
            callsPerCharge,
        ),
        // Comparison with every programmed point.
        multiplyRationals(
            rational(programmedPoints * perStoredBit),
            storedBitsPerCharge,
        ),
    );
    return {
        callsPerCharge,
        storedBitsPerCharge,
        perStoredBit,
        entryExcess,
        baseCallsPerAccess,
        programmedPoints,
        plainCoefficient,
        linearCoefficient,
        extractionCoefficient,
        quadraticCoefficient,
    };
};

export type ReductionClass = 'plain' | 'extraction';

export const reductionRatioAt = (
    work: ReturnType<typeof compileReductionWork>,
    reduction: ReductionClass,
    experimentCost: bigint,
): Rational =>
    reduction === 'plain'
        ? work.plainCoefficient
        : addRationals(
              work.plainCoefficient,
              work.linearCoefficient,
              work.extractionCoefficient,
              multiplyRationals(
                  work.quadraticCoefficient,
                  rational(experimentCost),
              ),
          );

// The computational groups share the 2^-80 budget with the statistical
// subtotal, each receiving 2^-(80+budgetBits).
export const ledgerGroups = [
    'Statistical terms',
    'ML-DSA-65 multi-user existential unforgeability',
    'Identity collisions',
    'Share-encryption Ring-LWE',
    'Auxiliary Ring-LWE',
    'Evaluation-key circular security',
    'FHE Ring-LWE',
] as const;

export const ledgerBudgetBits = (() => {
    let bits = 0n;
    while (1n << bits < BigInt(ledgerGroups.length)) bits += 1n;
    return bits;
})();

// Every honest participant can contribute, receive shares and vote. A
// ciphertext replacement passes through a uniform value, so it takes two
// steps, and a key that must end good leaves for uniform and returns.
export const computationalHybrids = (participantCount: bigint) =>
    [
        {
            assumption: 'Share-encryption Ring-LWE',
            hybrid: 'Honest recipient keys out and back around their honest-to-honest sharing ciphertexts',
            reduction: 'plain',
            multiplicity: 2n * participantCount * (participantCount + 1n),
        },
        {
            assumption: 'Auxiliary Ring-LWE',
            hybrid: 'Honest auxiliary key coordinates',
            reduction: 'plain',
            multiplicity: participantCount,
        },
        {
            assumption: 'Auxiliary Ring-LWE',
            hybrid: 'Programmed auxiliary key, then its honest ballots with the key out and back',
            reduction: 'extraction',
            multiplicity: 2n * participantCount + 3n,
        },
        {
            assumption: 'Evaluation-key circular security',
            hybrid: 'Honest evaluation-key tuples',
            reduction: 'extraction',
            multiplicity: participantCount,
        },
        {
            assumption: 'FHE Ring-LWE',
            hybrid: 'Honest FHE ballots under the uniform programmed key, then its good key',
            reduction: 'extraction',
            multiplicity: 2n * participantCount + 1n,
        },
    ] as const satisfies readonly {
        assumption: (typeof ledgerGroups)[number];
        hybrid: string;
        reduction: ReductionClass;
        multiplicity: bigint;
    }[];

// Smallest lambda with multiplicity*Tred(T)/2^lambda <= T/2^(80+budgetBits)
// at T = 2^80, where Tred(T)/T is constant or increasing in T.
export const requiredAssumptionBits = (
    multiplicity: bigint,
    ratioAtTarget: Rational,
) =>
    ceilingLog2(
        multiplyRationals(
            rational(multiplicity << (securityTargetBits + ledgerBudgetBits)),
            ratioAtTarget,
        ),
    );

// The ML-DSA-65 category 3 claim read as advantage at most T^2/2^192 for a
// T-gate quantum adversary. The multi-user reduction guesses the forged key,
// runs the real experiment and compares every accepted frame with the signed
// frames, at most doubling the experiment's cost.
export const signatureCategoryBits = 192n;
export const signatureReductionFactor = 2n;

export const compileComposedSecurityLedger = (
    potentialCredentialCount?: bigint,
) => {
    const statistical = compileStatisticalLedger(
        potentialCredentialCount ?? BigInt(largestParticipantCount),
    );
    const target = 1n << securityTargetBits;
    const profiles = supportedParticipantCounts.map((participantCount) => {
        const credentials =
            potentialCredentialCount ?? BigInt(participantCount);
        assert.ok(credentials >= BigInt(participantCount));
        const extracted =
            compileCommitmentExtractionBound(
                participantCount,
            ).extractedCommitmentCount;
        const work = compileReductionWork(credentials, extracted);
        return {
            participantCount,
            potentialCredentialCount: credentials,
            extractedCommitmentCount: extracted,
            hybrids: computationalHybrids(BigInt(participantCount)).map(
                (row) => {
                    const ratio = reductionRatioAt(work, row.reduction, target);
                    return {
                        ...row,
                        reductionRatioExponent: ceilingLog2(ratio),
                        requiredBits: requiredAssumptionBits(
                            row.multiplicity,
                            ratio,
                        ),
                    };
                },
            ),
        };
    });
    // U*(2T)^2/2^192 <= T/2^(80+budgetBits) at T = 2^80.
    const maximumCredentialPopulation =
        (1n <<
            (signatureCategoryBits -
                2n * securityTargetBits -
                ledgerBudgetBits)) /
        signatureReductionFactor ** 2n;
    // SHA-512 collision resistance read as advantage at most T^3/2^512, and the
    // ideal 512-bit identity bound 296*(q+2)^3/2^512 with q <= T, over T.
    const identityCollisionRatio = addRationals(
        rational(target * target, 1n << 512n),
        rational(296n * (target + 2n) ** 3n, (1n << 512n) * target),
    );
    const assumptions = [
        ...new Set(computationalHybrids(1n).map((row) => row.assumption)),
    ];
    return {
        securityTargetBits,
        groups: ledgerGroups,
        budgetBits: ledgerBudgetBits,
        statistical,
        profiles,
        maximumCredentialPopulation,
        identityCollisionExponent: ceilingLog2(identityCollisionRatio),
        maximumRequiredBits: assumptions.map((assumption) => ({
            assumption,
            requiredBits: maximumOf(
                ...profiles.flatMap((profile) =>
                    profile.hybrids
                        .filter((row) => row.assumption === assumption)
                        .map((row) => row.requiredBits),
                ),
            ),
        })),
    };
};

// The same extraction reduction if every oracle call cost one gate: an entry
// could then hold the complete contribution input with a 512-bit output.
export const compileUnitCallCostSensitivity = () => {
    const participantCount = largestParticipantCount;
    const widestEntryBits =
        8n * compileContributionBodyCensus().maximumHashInputBytes + 512n + 1n;
    const work = compileReductionWork(
        BigInt(participantCount),
        compileCommitmentExtractionBound(participantCount)
            .extractedCommitmentCount,
        {
            callsPerCharge: rational(1n),
            storedBitsPerCharge: rational(widestEntryBits),
        },
    );
    const ratio = reductionRatioAt(
        work,
        'extraction',
        1n << securityTargetBits,
    );
    const fhe = computationalHybrids(BigInt(participantCount)).find(
        (row) => row.assumption === 'FHE Ring-LWE',
    )!;
    return {
        participantCount,
        widestEntryBits,
        reductionRatioExponent: ceilingLog2(ratio),
        requiredBits: requiredAssumptionBits(fhe.multiplicity, ratio),
    };
};
