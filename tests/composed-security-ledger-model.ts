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
import {
    contributionSenderPrefix,
    compileContributionBodyCensus,
} from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { prefixReplacementBaseQueriesPerAccess } from '#tests/oracle-domain-model.js';
import { contributionSeedBytes } from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import {
    compileProofCompilerChronology,
    proofPurposes,
} from '#tests/proof-compiler-chronology-model.js';
import { compileProofRandomnessBudgets } from '#tests/proof-randomness-budget-model.js';
import { compileRecipientKeyUniquenessBound } from '#tests/recipient-key-uniqueness-model.js';
import { registrationSigningPublicKeyBytes } from '#tests/registration-enrollment-model.js';
import { compileSetupRandomnessCensus } from '#tests/setup-randomness-model.js';
import { compileSparseSupportSamplingCensus } from '#tests/sparse-sampling-bound-model.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { compileSupportedThresholdCompletionProfiles } from '#tests/threshold-completion-model.js';
import {
    compileProofCompilerCapCensus,
    compileWideChallengeCompilerCensus,
    proofCompilerCaps,
} from '#tests/wide-challenge-compiler-model.js';

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

// Smallest integer r with value <= r^2, for the small counts the ledger takes
// square roots of.
const ceilingSquareRoot = (value: bigint) => {
    assert.ok(value >= 0n && value <= 1n << 20n);
    let root = 0n;
    while (root * root < value) root += 1n;
    return root;
};

const power = (bits: bigint) =>
    bits >= statisticalDenominatorBits
        ? 1n
        : 1n << (statisticalDenominatorBits - bits);

// Exceeding the proof-only draw cap of a balanced sparse sampler on its
// original tape is an error event of the sampler step, whose power-of-two
// per-call bound every call pays. The sum is exact before rounding.
const sparseSupportExhaustion = (
    rows: readonly Readonly<{
        calls: bigint;
        numerator: bigint;
        denominator: bigint;
    }>[],
) => {
    const denominator = rows.reduce(
        (largest, row) =>
            row.denominator > largest ? row.denominator : largest,
        1n,
    );
    return dyadic(
        rows.reduce((sum, row) => {
            assert.equal(denominator % row.denominator, 0n);
            return (
                sum +
                row.calls * row.numerator * (denominator / row.denominator)
            );
        }, 0n),
        denominator,
    );
};

export const supportedParticipantCounts =
    compileSupportedThresholdCompletionProfiles().map(
        (profile) => profile.participantCount,
    );
const largestParticipantCount = Math.max(...supportedParticipantCounts);

// A corrupt organizer working with the relay can show disjoint groups of
// registrants separate rosters of one poll (frozen II.1). Each honest
// registration commits to at most one roster, and a roster that reaches an
// honest opening has at most f corrupt members, so it holds at least n-f of
// the poll's honest registrations. The poll definition does not fix the roster
// size, so every supported size can occur in one poll.
const rosterSizes = compileSupportedThresholdCompletionProfiles().map(
    (profile) => ({
        participantCount: BigInt(profile.participantCount),
        honestMembers: BigInt(
            profile.participantCount - profile.maximumCorruptParticipantCount,
        ),
    }),
);

export const minimumHonestRosterMembers = rosterSizes.reduce(
    (minimum, { honestMembers }) =>
        honestMembers < minimum ? honestMembers : minimum,
    rosterSizes[0].honestMembers,
);

// The rosters of a poll with this many honest registrations that can reach an
// honest opening.
export const rosterCountAt = (honestRegistrations: bigint) =>
    honestRegistrations / minimumHonestRosterMembers;

// The proof roles honest participants accept across those rosters: one per
// purpose and position of each, so at most 4n/(n-f) per honest member.
export const acceptedProofRolesAt = (honestRegistrations: bigint) =>
    rosterSizes.reduce((maximum, { participantCount, honestMembers }) => {
        const roles =
            (BigInt(proofPurposes.length) *
                participantCount *
                honestRegistrations) /
            honestMembers;
        return roles > maximum ? roles : maximum;
    }, 0n);

type StatisticalTerm = Readonly<{
    name: string;
    numerator: bigint;
    // The first profile at which a profile-dependent term is largest. A term
    // that depends on the roster alone names no option count.
    largestAt?: Readonly<{ participantCount: number; optionCount?: number }>;
}>;

// Terms of one supported profile that do not depend on the honest credential
// population.
export const profileStatisticalTerms = (
    profile: SupportedProfile,
): readonly StatisticalTerm[] => {
    const caps = compileProofCompilerCapCensus();
    const compiler = compileWideChallengeCompilerCensus(profile);
    const extraction = compileCommitmentExtractionBound(
        profile.participantCount,
        prefixReplacementBaseQueriesPerAccess *
            prefixOracleQueriesPerAccess *
            caps.adversaryQueries,
    );
    const matrices = compileCommonMatrixSamplingCensus(profile);
    const matrixInitialization =
        compileCommonMatrixInitializationCensus(profile);
    const sharing = profile.shareLifting;
    const releaseJournal = compileParticipantReleaseCustody(profile);
    const sampling = compileSetupRandomnessCensus(profile);
    return [
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
        {
            // Each guessing step's reduction programs the FHE common streams
            // for its guessed modulus, which moves the guessed world by at
            // most the complete sampling distance and fibre bias, and loses
            // twice that per guess.
            name: 'FHE common-stream programming per guessing reduction',
            numerator: dyadic(
                2n *
                    fheCommonStreamGuesses() *
                    guessingSteps(BigInt(profile.participantCount)) *
                    (matrices.distanceUpperNumerator *
                        matrixInitialization.biasDenominator +
                        matrixInitialization.biasNumerator *
                            matrices.distanceUpperDenominator),
                matrices.distanceUpperDenominator *
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
            // Every roster participant draws each contribution secret once.
            name: 'Contribution sparse-support cap exhaustion',
            numerator: sparseSupportExhaustion(
                compileSparseSupportSamplingCensus(profile)
                    .filter((row) => row.scope === 'contribution')
                    .map((row) => ({
                        ...row,
                        calls:
                            BigInt(profile.participantCount) *
                            row.callsPerOperation,
                    })),
            ),
        },
        {
            // Every roster participant expands its generation and
            // continuation randomness from two uniform seeds through the
            // ideal SHAKE256, and nothing else reads a seed. Replacing all 2n
            // streams by uniform bytes costs, by the semi-classical
            // one-way-to-hiding lemma over q oracle calls of the complete
            // experiment and s-bit seeds, 2*sqrt((q+1)*4q*2n/2^s), at most
            // 4(q+1)*sqrt(2n)/2^(s/2).
            name: 'Contribution seed expansion',
            numerator: dyadic(
                4n *
                    (caps.adversaryQueries + 1n) *
                    ceilingSquareRoot(2n * BigInt(profile.participantCount)),
                1n << (4n * contributionSeedBytes),
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
            // A profile exists only when its flooded release meets the
            // joint translated-cube bound at the statistical target.
            name: 'One-target release coupling',
            numerator: power(BigInt(fixedModulusBfvInputs.statisticalBits)),
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
                soundnessHops(BigInt(profile.participantCount)) *
                    compiler.failureNumerator,
                compiler.failureDenominator,
            ),
        },
        {
            name: 'Merkle privacy',
            numerator: power(BigInt(caps.merklePrivacyBits)),
        },
        {
            name: 'Proof reprogramming',
            numerator: power(BigInt(caps.reprogrammingBits)),
        },
        {
            name: 'Ballot journal exhaustion',
            numerator: power(
                compileBallotRandomnessBudget(profile).exhaustionBits,
            ),
        },
        {
            name: 'Release journal exhaustion',
            numerator: dyadic(
                releaseJournal.exhaustionBound.numerator,
                1n << releaseJournal.exhaustionBound.denominatorBits,
            ),
        },
        ...compileProofRandomnessBudgets(profile).map((value) => ({
            name: `${value.role.charAt(0).toUpperCase()}${value.role.slice(1)} simulator field sampling`,
            numerator: dyadic(
                value.failure.numerator,
                1n << value.failure.denominatorBits,
            ),
        })),
    ];
};

// No efficient game can test a corrupt statement while a key is uniform, so
// soundness is not a stop event. Every hop whose identity holds only for true
// corrupt statements pays it: the released output, the recovery subset before
// and after each honest recipient key leaves, the three recovery switches and
// the terminal output.
export const soundnessHops = (participantCount: bigint) =>
    2n * participantCount + 5n;

let credentialIndependentTerms:
    | Readonly<{ adversaryQueries: bigint; terms: readonly StatisticalTerm[] }>
    | undefined;

// Terms that do not depend on the honest credential population, each at its
// largest value over every supported profile. Every roster of a poll has one
// profile, so their sum bounds each roster's terms.
const statisticalTermsWithoutCredentials = () => {
    if (credentialIndependentTerms !== undefined)
        return credentialIndependentTerms;
    const evaluated = listSupportedProfiles().map((profile) => ({
        profile,
        terms: profileStatisticalTerms(profile),
    }));
    const terms = evaluated[0].terms.map((first, index): StatisticalTerm => {
        let largest = { profile: evaluated[0].profile, term: first };
        let varies = false;
        for (const { profile, terms: values } of evaluated) {
            const term = values[index];
            assert.equal(term.name, first.name);
            if (term.numerator !== first.numerator) varies = true;
            if (term.numerator > largest.term.numerator)
                largest = { profile, term };
        }
        return {
            name: first.name,
            numerator: largest.term.numerator,
            ...(varies && {
                largestAt: {
                    participantCount: largest.profile.participantCount,
                    optionCount: largest.profile.optionCount,
                },
            }),
        };
    });
    credentialIndependentTerms = {
        adversaryQueries: proofCompilerCaps.adversaryQueries,
        terms,
    };
    return credentialIndependentTerms;
};

// Statistical terms evaluated at the proof compiler's query cap. A charged
// oracle call costs at least one permutation charge, so the cap covers every
// experiment of at most 2^80 gates, and every term is nondecreasing in the
// query count. The subtotal therefore bounds Adv(T)/T for 1 <= T <= 2^80.
// Each roster that reaches an honest opening runs its own hybrids, so the
// ledger charges the whole subtotal once per such roster, which overcounts
// the terms that every roster shares.
const compileStatisticalLedger = (
    potentialCredentialCount = BigInt(largestParticipantCount),
    rosterCount = 1n,
) => {
    assert.ok(rosterCount >= 1n);
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
    const largestRoster = { participantCount: largestParticipantCount };
    const terms: readonly StatisticalTerm[] = [
        ...fixed.terms,
        {
            name: 'Honest-body equivocation',
            numerator: dyadic(equivocation.numerator, equivocation.denominator),
            largestAt: largestRoster,
        },
        {
            name: 'Honest signing credential collision',
            numerator: dyadic(
                equivocation.credentialCollisionNumerator,
                equivocation.credentialCollisionDenominator,
            ),
            largestAt: largestRoster,
        },
        {
            // Every potential honest credential draws its recipient secret
            // once; that sampler is the same for every profile.
            name: 'Registration sparse-support cap exhaustion',
            numerator: sparseSupportExhaustion(
                compileSparseSupportSamplingCensus(listSupportedProfiles()[0])
                    .filter((row) => row.scope === 'registration')
                    .map((row) => ({
                        ...row,
                        calls: potentialCredentialCount * row.callsPerOperation,
                    })),
            ),
        },
    ];
    const subtotalNumerator = terms.reduce(
        (sum, term) => sum + term.numerator,
        0n,
    );
    const chargedNumerator = rosterCount * subtotalNumerator;
    return {
        participantCount: largestParticipantCount,
        potentialCredentialCount,
        rosterCount,
        adversaryQueries: fixed.adversaryQueries,
        denominatorBits: statisticalDenominatorBits,
        terms,
        subtotalNumerator,
        subtotalExponent: ceilingLog2(
            rational(subtotalNumerator, 1n << statisticalDenominatorBits),
        ),
        chargedNumerator,
        chargedExponent: ceilingLog2(
            rational(chargedNumerator, 1n << statisticalDenominatorBits),
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

// The sender prefix and the programming cap are the same for every profile.
const reductionOperands = () => ({
    programmedMessageBudget: proofCompilerCaps.programmedMessageBudget,
    senderPrefixBits:
        8n *
        BigInt(
            contributionSenderPrefix(
                new Uint8Array(Number(registrationSigningPublicKeyBytes)),
            ).length,
        ),
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

// Every profile reduces the same fixed FHE common streams modulo its own
// ciphertext modulus, and the adversary may fix the profile after querying
// them, so a reduction that programs its challenge into those streams guesses
// the ciphertext modulus. The share-encryption and auxiliary common
// polynomials have one modulus and sample width for every profile.
let ciphertextModulusGuesses: bigint | undefined;
export const fheCommonStreamGuesses = (): bigint => {
    ciphertextModulusGuesses ??= BigInt(
        new Set(
            listSupportedProfiles().map(
                (profile) => profile.ciphertext.modulus,
            ),
        ).size,
    );
    return ciphertextModulusGuesses;
};

// The hybrid steps whose reductions guess the ciphertext modulus.
const guessingSteps = (participantCount: bigint) =>
    computationalHybrids(participantCount)
        .filter((row) => row.guesses > 1n)
        .reduce((sum, row) => sum + row.multiplicity, 0n);

// Every honest participant can contribute, receive shares and vote. A
// ciphertext replacement passes through a uniform value, so it takes two
// steps, and a key that must end good leaves for uniform and returns. Every
// honest registration publishes its recipient key before any roster exists,
// so the share-encryption steps take every registration key out and back, not
// only the recipients'. Every other step belongs to one roster and repeats for
// each roster that reaches an honest opening, charged here at this roster
// size. Each step's reduction succeeds only when its guesses are right.
export const computationalHybrids = (
    participantCount: bigint,
    honestRegistrations = participantCount,
    rosterCount = 1n,
) =>
    [
        {
            assumption: 'Share-encryption Ring-LWE',
            hybrid: 'Honest registration keys out and back around their honest-to-honest sharing ciphertexts',
            reduction: 'plain',
            multiplicity:
                2n * honestRegistrations +
                2n * participantCount ** 2n * rosterCount,
            guesses: 1n,
        },
        {
            assumption: 'Auxiliary Ring-LWE',
            hybrid: 'Honest auxiliary key coordinates',
            reduction: 'plain',
            multiplicity: participantCount * rosterCount,
            guesses: 1n,
        },
        {
            assumption: 'Auxiliary Ring-LWE',
            hybrid: 'Programmed auxiliary key, then its honest ballots with the key out and back',
            reduction: 'extraction',
            multiplicity: (2n * participantCount + 3n) * rosterCount,
            guesses: 1n,
        },
        {
            assumption: 'Evaluation-key circular security',
            hybrid: 'Honest evaluation-key tuples',
            reduction: 'extraction',
            multiplicity: participantCount * rosterCount,
            guesses: fheCommonStreamGuesses(),
        },
        {
            assumption: 'FHE Ring-LWE',
            hybrid: 'Honest FHE ballots under the uniform programmed key, then its good key',
            reduction: 'extraction',
            multiplicity: (2n * participantCount + 1n) * rosterCount,
            guesses: fheCommonStreamGuesses(),
        },
    ] as const satisfies readonly {
        assumption: (typeof ledgerGroups)[number];
        hybrid: string;
        reduction: ReductionClass;
        multiplicity: bigint;
        guesses: bigint;
    }[];

// Smallest lambda with multiplicity*guesses*Tred(T)/2^lambda <=
// T/2^(80+budgetBits) at T = 2^80, where Tred(T)/T is constant or increasing
// in T.
export const requiredAssumptionBits = (
    multiplicity: bigint,
    guesses: bigint,
    ratioAtTarget: Rational,
) =>
    ceilingLog2(
        multiplyRationals(
            rational(
                (multiplicity * guesses) <<
                    (securityTargetBits + ledgerBudgetBits),
            ),
            ratioAtTarget,
        ),
    );

// The ML-DSA-65 category 3 claim read as advantage at most T^2/2^192 for a
// T-gate quantum adversary. The multi-user reduction guesses the forged key,
// runs the real experiment and compares every accepted frame with the signed
// frames, at most doubling the experiment's cost.
export const signatureCategoryBits = 192n;
export const signatureReductionFactor = 2n;

// The largest honest credential population with
// U*(2T)^2/2^192 <= T/2^(80+budgetBits) at T = 2^80.
const signatureCredentialPopulation =
    (1n <<
        (signatureCategoryBits - 2n * securityTargetBits - ledgerBudgetBits)) /
    signatureReductionFactor ** 2n;

// Whether the honest registrations of a poll, split into every roster they
// can complete, stay within the signature group, the proof compiler's caps
// and the statistical share of the budget.
const populationWithinClaim = (honestRegistrations: bigint) =>
    honestRegistrations <= signatureCredentialPopulation &&
    acceptedProofRolesAt(honestRegistrations) <= proofCompilerCaps.roleBudget &&
    BigInt(proofPurposes.length) * honestRegistrations <=
        proofCompilerCaps.honestProofBudget &&
    compileStatisticalLedger(
        honestRegistrations,
        rosterCountAt(honestRegistrations),
    ).chargedNumerator <<
        (securityTargetBits + ledgerBudgetBits) <=
        1n << statisticalDenominatorBits;

// The largest honest credential population of one poll that the claim
// covers. Every constraint only tightens as the population grows.
let claimedCredentialPopulation: bigint | undefined;
const maximumCredentialPopulation = () => {
    if (claimedCredentialPopulation !== undefined)
        return claimedCredentialPopulation;
    let covered = BigInt(largestParticipantCount);
    assert.ok(populationWithinClaim(covered));
    let excluded = signatureCredentialPopulation + 1n;
    while (excluded - covered > 1n) {
        const middle = (covered + excluded) / 2n;
        if (populationWithinClaim(middle)) covered = middle;
        else excluded = middle;
    }
    // The terms charge the proof compiler's caps, which the proofs,
    // programming points and commitments of every profile must meet with a
    // registration for every honest credential of the population in every
    // roster it can complete.
    for (const profile of listSupportedProfiles())
        assert.ok(
            compileProofCompilerChronology(
                profile,
                covered,
                rosterCountAt(covered),
            ).withinCaps,
        );
    claimedCredentialPopulation = covered;
    return covered;
};

export const compileComposedSecurityLedger = (
    potentialCredentialCount?: bigint,
) => {
    // One potential honest credential per participant is one roster; a
    // population is split into every roster it can complete.
    const rosterCount =
        potentialCredentialCount === undefined
            ? 1n
            : rosterCountAt(potentialCredentialCount);
    const claimedPopulation = maximumCredentialPopulation();
    if (
        potentialCredentialCount !== undefined &&
        (potentialCredentialCount > claimedPopulation ||
            potentialCredentialCount < BigInt(largestParticipantCount))
    )
        throw new RangeError('The population lies outside the claim.');
    const statistical = compileStatisticalLedger(
        potentialCredentialCount ?? BigInt(largestParticipantCount),
        rosterCount,
    );
    const target = 1n << securityTargetBits;
    const profiles = supportedParticipantCounts.map((participantCount) => {
        const credentials =
            potentialCredentialCount ?? BigInt(participantCount);
        // Every roster is charged at this size, so the largest size bounds
        // a poll whose rosters differ in size.
        const extracted =
            rosterCount *
            compileCommitmentExtractionBound(participantCount)
                .extractedCommitmentCount;
        const work = compileReductionWork(credentials, extracted);
        return {
            participantCount,
            potentialCredentialCount: credentials,
            rosterCount,
            extractedCommitmentCount: extracted,
            hybrids: computationalHybrids(
                BigInt(participantCount),
                credentials,
                rosterCount,
            ).map((row) => {
                const ratio = reductionRatioAt(work, row.reduction, target);
                return {
                    ...row,
                    reductionRatioExponent: ceilingLog2(ratio),
                    requiredBits: requiredAssumptionBits(
                        row.multiplicity,
                        row.guesses,
                        ratio,
                    ),
                };
            }),
        };
    });
    // Every identity is a 512-bit SHAKE256 output: the ideal identity bound
    // 296*(q+2)^3/2^512 with q <= T, over T.
    const identityCollisionRatio = rational(
        296n * (target + 2n) ** 3n,
        (1n << 512n) * target,
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
        signatureCredentialPopulation,
        maximumCredentialPopulation: claimedPopulation,
        maximumRosterCount: rosterCountAt(claimedPopulation),
        maximumAcceptedProofRoles: acceptedProofRolesAt(claimedPopulation),
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
// could then hold the widest supported contribution input with a 512-bit
// output.
export const compileUnitCallCostSensitivity = () => {
    const participantCount = largestParticipantCount;
    const widestEntryBits =
        8n *
            maximumOf(
                ...listSupportedProfiles().map(
                    (profile) =>
                        compileContributionBodyCensus(profile)
                            .maximumHashInputBytes,
                ),
            ) +
        512n +
        1n;
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
        requiredBits: requiredAssumptionBits(
            fhe.multiplicity,
            fhe.guesses,
            ratio,
        ),
    };
};
