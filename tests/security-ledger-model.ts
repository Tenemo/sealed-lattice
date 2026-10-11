import assert from 'node:assert/strict';

import {
    compileCompleteAuthenticationFrameWork,
    compileCompleteCredentialIntentBounds,
    compileCurrentSignatureHashInputs,
    compileCurrentSignatureSamplingBounds,
} from '#tests/authentication-work-model.js';
import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileClearPreparationLedger } from '#tests/clear-preparation-ledger-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    compileCommonMatrixInitializationCensus,
    compileCommonMatrixSamplingCensus,
} from '#tests/common-matrix-sampling-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { merkleSaltSeedBytes } from '#tests/full-word-proof-layout-model.js';
import {
    mlDsa65KeySeedBytes,
    mlDsa65PublicMatrixSeedBytes,
} from '#tests/ml-dsa-65-parameters.js';
import {
    compilePrivateRandomnessScopes,
    operationSeedBytes,
} from '#tests/operation-seed-model.js';
import { shakePermutationGateCharge } from '#tests/oracle-budget-model.js';
import { compileProofHashDomainCensus } from '#tests/proof-hash-domain-model.js';
import {
    byteAlignedSpongePermutations,
    compileProofHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { compileProofRandomnessBudgets } from '#tests/proof-randomness-budget-model.js';
import { compileRecipientKeyUniquenessBound } from '#tests/recipient-key-uniqueness-model.js';
import {
    budgetSplitBits,
    compileLatticePopulationLimits,
    decisiveExperimentGates,
    largestPopulationWithin,
    latticeAssumptionGroups,
    latticeGroupComparisons,
    latticeGroupFloors,
    latticeRequirementAt,
    securityTargetBits,
    supportedLevelBits,
    unpricedWorkAllowance,
    type LatticeAssumptionGroup,
} from '#tests/security-margin-screen-model.js';
import { compileSetupRandomnessCensus } from '#tests/setup-randomness-model.js';
import {
    boundSparseSupportSampling,
    compileSparseSupportSamplingCensus,
} from '#tests/sparse-sampling-bound-model.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import {
    compileProofCompilerCapCensus,
    compileProofRoundErrorCensus,
} from '#tests/wide-challenge-compiler-model.js';

// Exact nonnegative rationals for probabilities and cost ratios.
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

const scale = (value: Rational, factor: bigint): Rational =>
    rational(value.numerator * factor, value.denominator);

const divide = (value: Rational, divisor: bigint): Rational =>
    rational(value.numerator, value.denominator * divisor);

export const atMost = (left: Rational, right: Rational) =>
    left.numerator * right.denominator <= right.numerator * left.denominator;

const largest = (values: readonly Rational[]) =>
    values.reduce((maximum, value) =>
        atMost(value, maximum) ? maximum : value,
    );

// Smallest integer r with value <= r^2. Newton's iteration from above
// descends to the integer square root's floor.
export const ceilingSquareRoot = (value: bigint) => {
    assert.ok(value >= 0n);
    if (value < 2n) return value;
    let root = value;
    let next = (value + 1n) / 2n;
    while (next < root) {
        root = next;
        next = (root + value / root) / 2n;
    }
    return root * root < value ? root + 1n : root;
};

// Smallest integer k with value <= 2^k, for a positive value.
export const rationalCeilingLog2 = (value: Rational) => {
    assert.ok(value.numerator > 0n);
    const fits = (exponent: bigint) =>
        exponent >= 0n
            ? value.numerator <= value.denominator << exponent
            : value.numerator << -exponent <= value.denominator;
    let exponent =
        BigInt(value.numerator.toString(2).length) -
        BigInt(value.denominator.toString(2).length);
    while (!fits(exponent)) exponent += 1n;
    while (fits(exponent - 1n)) exponent -= 1n;
    return exponent;
};

// Each of the seven assumption groups may contribute at most T/2^(80+3) to
// an adversary's advantage at every experiment cost T up to 2^80 gates, so
// each group's requirement bounds the ratio of its contribution to T.
export const groupBudget = rational(
    1n,
    1n << (securityTargetBits + budgetSplitBits),
);

const largestExperimentGates = 1n << securityTargetBits;

// The convention charges every SHAKE call at least one permutation, so an
// experiment of cost T makes at most T/c logical calls and at most T/c honest
// operations of any kind that calls SHAKE, and every experiment costs at
// least c. Each wrapper of the proof compiler's hybrids makes at most four
// calls for every original call, so a hybrid game makes at most 4T/c.
const permutationCharge = shakePermutationGateCharge;

const callsPerChargedQuery = () => {
    const caps = compileProofCompilerCapCensus();
    assert.equal(caps.chargedQueries % caps.adversaryQueries, 0n);
    return caps.chargedQueries / caps.adversaryQueries;
};

export const maximumChargedQueries = () =>
    callsPerChargedQuery() * (largestExperimentGates / permutationCharge);

// The accepted reading of ML-DSA-65's category 3 claim: one key, against an
// adversary of cost T, is forged with probability at most T^2/2^192. A union
// over the original honest credentials charges each key's reduction. That
// reduction receives one challenge key and its deterministic signing oracle,
// generates every other key itself and runs the real experiment with genuine
// witnesses; it never programs the oracle. Each first-evaluated signing intent
// calls the signing oracle once and is cached, so a repeated evaluation reuses
// the same signature, and the honest signing work the oracle replaces exceeds
// the caching. Its only added work is the forgery test: each honest
// verification under the challenge key compares the frame digest it computes
// with the digests of the at most s frames that key's intents fixed, at most
// s*(2*512+1) gates, while every verification computes at least its frame
// digest, its challenge digest and one challenge-sampling permutation. The
// reduction therefore costs at most (1+rho)T, with rho the comparison work
// over that verification work.
const mlDsaSecurityExponent = 192n;
const frameDigestBits = 512n;

export const compileAuthenticationGroup = () => {
    const participantCounts = [
        ...new Set(
            listSupportedProfiles().map((profile) => profile.participantCount),
        ),
    ];
    const signedFramesPerKey = participantCounts
        .flatMap((participantCount) =>
            compileCompleteCredentialIntentBounds(participantCount),
        )
        .reduce(
            (maximum, row) =>
                row.firstEvaluatedIntentBound > maximum
                    ? row.firstEvaluatedIntentBound
                    : maximum,
            0n,
        );
    const comparisonGates = signedFramesPerKey * (2n * frameDigestBits + 1n);
    const challengeDigest = compileCurrentSignatureHashInputs().rows.find(
        (row) => row.purpose === 'Challenge digest',
    );
    assert.ok(
        challengeDigest !== undefined && challengeDigest.outputBytes !== null,
    );
    const shortestFrameInputBytes = compileCompleteAuthenticationFrameWork()
        .map((frame) => frame.representativeInputBytes)
        .reduce((minimum, value) => (value < minimum ? value : minimum));
    const shakeRate = 136n;
    const verificationPermutations =
        byteAlignedSpongePermutations(
            shortestFrameInputBytes,
            frameDigestBits / 8n,
            shakeRate,
        ) +
        byteAlignedSpongePermutations(
            challengeDigest.inputBytes,
            challengeDigest.outputBytes,
            shakeRate,
        ) +
        1n;
    const verificationGates = verificationPermutations * permutationCharge;
    // H*((1+rho)T)^2/2^192 <= T/2^(80+split) for every T up to 2^80, which
    // the largest experiment decides.
    const reducedGates = verificationGates + comparisonGates;
    const honestRegistrations =
        ((1n << mlDsaSecurityExponent) * verificationGates ** 2n) /
        ((1n << (securityTargetBits + budgetSplitBits)) *
            largestExperimentGates *
            reducedGates ** 2n);
    return {
        signedFramesPerKey,
        comparisonGates,
        shortestFrameInputBytes,
        verificationPermutations,
        verificationGates,
        reductionRatio: rational(reducedGates, verificationGates),
        honestRegistrations,
    };
};

// Every foundation and custody identity, retained tag and signed-frame digest
// is a 512-bit SHAKE256 output prefix, and their binding fails only if the
// experiment's calls contain two inputs with equal prefixes: one event for the
// whole ideal function, whatever the population. Zha19 Theorem 2's compressed
// oracle grows a colliding database's amplitude by at most 2*sqrt(q/2^n) per
// query, and Lemma 5 charges the two output pairs, giving at most
// (sqrt(4(q+2)^3/2^n)+sqrt(2/2^n))^2 <= (8(q+2)^3+4)/2^n. With
// (a+b)^3 <= 4(a^3+b^3), q <= 4T/c and T >= c, its ratio to T is at most
// (128*Q^2+260)/(c*2^n) at the largest charged query count Q.
const identityDigestBits = 512n;

export const compileIdentityCollisionGroup = () => {
    const queries = maximumChargedQueries();
    const ratio = rational(
        32n * callsPerChargedQuery() * queries ** 2n + 260n,
        permutationCharge << identityDigestBits,
    );
    return {
        digestBits: identityDigestBits,
        maximumChargedQueries: queries,
        ratio,
        withinBudget: atMost(ratio, groupBudget),
    };
};

// Each lattice group's single-message comparisons at h original honest
// registrations are at most constant + slope*h for every h: the FHE, circular
// and share-encryption counts are linear in h, and the auxiliary group adds at
// most h ballot messages to its one key comparison.
export const compileComparisonGrowth = (profile: SupportedProfile) => {
    const none = compileClearPreparationLedger(profile, 0n);
    const one = compileClearPreparationLedger(profile, 1n);
    return latticeAssumptionGroups.map((group) => {
        if (group === 'Auxiliary Ring-LWE')
            return {
                group,
                constant: none.auxiliaryKeyComparisons,
                slope: 1n,
            };
        const constant = latticeGroupComparisons(group, none);
        assert.equal(constant, 0n);
        return { group, constant, slope: latticeGroupComparisons(group, one) };
    });
};

// Every comparison whose endpoint games use true accepted corrupt statements
// pays corrupt-proof soundness once at each endpoint: every lattice
// comparison, whose endpoints recover corrupt offers through genuine
// recipient keys and corrupt ballots through the auxiliary or FHE key, and
// four steps outside them.
export const semanticUseStepsOutsideComparisons = [
    'Original-history recovery and prescribed release',
    'Corrupt-ballot recovery switch to the auxiliary key',
    'Corrupt-ballot recovery switch to the FHE aggregate',
    'Terminal identity',
] as const;

export const compileSemanticUseCharges = (profile: SupportedProfile) => {
    const growth = compileComparisonGrowth(profile);
    const sum = (field: 'constant' | 'slope') =>
        growth.reduce((total, row) => total + row[field], 0n);
    return {
        constant:
            2n *
            (BigInt(semanticUseStepsOutsideComparisons.length) +
                sum('constant')),
        slope: 2n * sum('slope'),
    };
};

// One semantic-use charge of the finite-family tagged soundness bound,
// 12*t^2*J + 2*M/2^Lambda with t = 2Q + M and
// J = epsilon + (W*(t+1) + b + 2t)/2^kappa, as a polynomial in the charged
// queries Q of its game. The family is the whole suite's, so epsilon is the
// largest round error of every supported profile.
type SoundnessCharge = Readonly<{
    roundError: Rational;
    tagBits: bigint;
    inputBits: bigint;
    sentinels: bigint;
    expansionQueries: bigint;
    messageBits: bigint;
    coefficients: readonly Rational[];
}>;
let soundnessCharge: SoundnessCharge | undefined;

export const compileSoundnessCharge = (): SoundnessCharge => {
    if (soundnessCharge !== undefined) return soundnessCharge;
    const domain = compileProofHashDomainCensus();
    const roundError = largest(
        listSupportedProfiles().map(
            (profile) =>
                compileProofRoundErrorCensus(profile).maximumRoundError,
        ),
    );
    const tagBits = compileProofCompilerCapCensus().tagBits;
    const inputBits = domain.maximumInputBits;
    const sentinels = domain.sentinelCount;
    const expansionQueries = domain.maximumAcceptedExpansionQueries;
    const messageBits = domain.maximumMessageBits;
    const tagSpace = rational(1n, 1n << tagBits);
    // J = J0 + J1*Q with J0 = epsilon + (W+b)/2^kappa + (W+2)*M/2^kappa and
    // J1 = 2*(W+2)/2^kappa, and t^2 = M^2 + 4MQ + 4Q^2.
    const perTagWidth = scale(tagSpace, inputBits + 2n);
    const constantJ = addRationals(
        roundError,
        scale(tagSpace, inputBits + sentinels),
        scale(perTagWidth, expansionQueries),
    );
    const linearJ = scale(perTagWidth, 2n);
    const m = expansionQueries;
    soundnessCharge = {
        roundError,
        tagBits,
        inputBits,
        sentinels,
        expansionQueries,
        messageBits,
        coefficients: [
            addRationals(
                scale(constantJ, 12n * m * m),
                rational(2n * m, 1n << messageBits),
            ),
            addRationals(
                scale(linearJ, 12n * m * m),
                scale(constantJ, 48n * m),
            ),
            addRationals(scale(linearJ, 48n * m), scale(constantJ, 48n)),
            scale(linearJ, 48n),
        ],
    };
    return soundnessCharge;
};

export const soundnessChargeAt = (chargedQueries: bigint) =>
    addRationals(
        ...compileSoundnessCharge().coefficients.map((coefficient, power) =>
            scale(coefficient, chargedQueries ** BigInt(power)),
        ),
    );

// One statistical term's bound on its contribution divided by the experiment's
// cost, over every experiment of at most 2^80 gates with at most the given
// original honest registrations. Terms outside the proofs do not depend on the
// proof-compiler gate.
export type StatisticalTerm = Readonly<{
    name: string;
    scope: 'outside the proofs' | 'proofs';
    ratioAt: (honestRegistrations: bigint) => Rational;
}>;

// A once-global term v has ratio at most v/c, and so does a term of v per
// operation of one kind, since every such operation costs at least c.
const perCharge = (value: Rational) => () => divide(value, permutationCharge);

type SuiteTerms = Readonly<{
    matrixSampling: Rational;
    matrixInitialization: Rational;
    largestStreamProgramming: Rational;
}>;
let suiteTerms: SuiteTerms | undefined;

// The suite's fixed common matrices are global, so every profile's sampling
// distance and fibre bias is charged once. A comparison that programs its
// guessed modulus's common streams moves its guessed world by that family's
// distance and bias, twice per comparison.
const compileSuiteTerms = (): SuiteTerms => {
    if (suiteTerms !== undefined) return suiteTerms;
    const rows = listSupportedProfiles().map((profile) => {
        const sampling = compileCommonMatrixSamplingCensus(profile);
        const initialization = compileCommonMatrixInitializationCensus(profile);
        return {
            sampling: rational(
                sampling.distanceUpperNumerator,
                sampling.distanceUpperDenominator,
            ),
            initialization: rational(
                initialization.biasNumerator,
                initialization.biasDenominator,
            ),
        };
    });
    suiteTerms = {
        matrixSampling: addRationals(...rows.map((row) => row.sampling)),
        matrixInitialization: addRationals(
            ...rows.map((row) => row.initialization),
        ),
        largestStreamProgramming: scale(
            largest(
                rows.map((row) =>
                    addRationals(row.sampling, row.initialization),
                ),
            ),
            2n,
        ),
    };
    return suiteTerms;
};

const sparseBound = (degree: bigint, support: bigint) => {
    const bound = boundSparseSupportSampling(degree, support);
    return rational(bound.numerator, bound.denominator);
};

const statisticalTermsCache = new Map<
    SupportedProfile,
    readonly StatisticalTerm[]
>();

export const compileStatisticalTerms = (
    profile: SupportedProfile,
): readonly StatisticalTerm[] => {
    const cached = statisticalTermsCache.get(profile);
    if (cached !== undefined) return cached;
    const suite = compileSuiteTerms();
    const caps = compileProofCompilerCapCensus();
    const wrap = callsPerChargedQuery();
    const queries = maximumChargedQueries();
    const soundness = compileSoundnessCharge();
    const growth = compileComparisonGrowth(profile);
    const charges = compileSemanticUseCharges(profile);
    const one = compileClearPreparationLedger(profile, 1n);
    // Per original honest registration: its source coordinates, potential
    // commitment sender scopes and corrupt registration-source extractions.
    const coordinatesPerRegistration = one.generatedSourceEntries;
    const maskScopesPerRegistration = one.sourceMaskScopes;
    const extractionsPerRegistration = one.maximumCorruptSourceExtractions;
    // Each original honest credential has at most one contribution, ballot and
    // release intent, unfinished work included.
    const scopesAt = (honestRegistrations: bigint) =>
        compilePrivateRandomnessScopes(
            coordinatesPerRegistration * honestRegistrations,
            honestRegistrations,
            honestRegistrations,
            honestRegistrations,
        );
    const sampling = compileSparseSupportSamplingCensus(profile);
    const samplingRows = (scope: string) =>
        addRationals(
            ...sampling
                .filter((row) => row.scope === scope)
                .map((row) =>
                    scale(
                        rational(row.numerator, row.denominator),
                        row.callsPerOperation,
                    ),
                ),
        );
    const fheSecret = sparseBound(
        fixedModulusBfvInputs.polynomialDegree,
        fixedModulusBfvInputs.secretSupportWeight,
    );
    const preparation = compileSetupRandomnessCensus(profile);
    const slopeOf = (group: LatticeAssumptionGroup) => {
        const row = growth.find((value) => value.group === group);
        assert.ok(row !== undefined);
        return row.slope;
    };
    // The seed-expansion lemma's 4(q+1)*sqrt(k)/2^(s/2), with q+1 at most
    // (wrap+1)T/c.
    const seedExpansion = (seeds: bigint, seedBytes: bigint) =>
        rational(
            4n * (wrap + 1n) * ceilingSquareRoot(seeds),
            permutationCharge << (4n * seedBytes),
        );
    const credentialSeedPair = addRationals(
        rational(1n, 1n << (8n * mlDsa65KeySeedBytes)),
        rational(1n, 1n << (8n * mlDsa65PublicMatrixSeedBytes)),
    );
    const terms: StatisticalTerm[] = [
        {
            name: 'Fixed common matrix sampling of every profile',
            scope: 'outside the proofs',
            ratioAt: perCharge(suite.matrixSampling),
        },
        {
            name: 'Fixed common matrix fibre initialization of every profile',
            scope: 'outside the proofs',
            ratioAt: perCharge(suite.matrixInitialization),
        },
        {
            name: 'Bounded recipient-key collision',
            scope: 'outside the proofs',
            ratioAt: perCharge(
                rational(
                    1n,
                    1n <<
                        compileRecipientKeyUniquenessBound()
                            .uniformMatrixFailureExponent,
                ),
            ),
        },
        ...compileCurrentSignatureSamplingBounds().map(
            (row): StatisticalTerm => ({
                name: `ML-DSA ${row.purpose.toLowerCase()} over every seed`,
                scope: 'outside the proofs',
                ratioAt: perCharge(
                    rational(row.numerator, 1n << row.denominatorBits),
                ),
            }),
        ),
        {
            // The FHE and circular comparisons are linear in the
            // registrations, each of which costs at least c.
            name: 'Common-stream programming of every FHE and circular comparison',
            scope: 'outside the proofs',
            ratioAt: perCharge(
                scale(
                    suite.largestStreamProgramming,
                    slopeOf('FHE Ring-LWE') +
                        slopeOf('Evaluation-key circular security'),
                ),
            ),
        },
        {
            name: 'Integer sharing translation per honest offer',
            scope: 'outside the proofs',
            ratioAt: perCharge(
                rational(
                    profile.shareLifting.privacyNumerator,
                    2n * profile.shareLifting.sharingRadius,
                ),
            ),
        },
        {
            name: 'Prescribed-release coupling per certified roster',
            scope: 'outside the proofs',
            ratioAt: perCharge(
                rational(
                    1n,
                    1n << BigInt(fixedModulusBfvInputs.statisticalBits),
                ),
            ),
        },
        {
            name: 'Preparation Gaussian sampling per contribution',
            scope: 'outside the proofs',
            ratioAt: perCharge(
                rational(
                    preparation.preparationVariationNumerator,
                    preparation.preparationVariationDenominator,
                ),
            ),
        },
        {
            // The recipient secret and one FHE source secret per coordinate.
            name: 'Sparse-support caps per registration',
            scope: 'outside the proofs',
            ratioAt: perCharge(
                addRationals(
                    samplingRows('registration'),
                    scale(fheSecret, coordinatesPerRegistration),
                ),
            ),
        },
        {
            name: 'Sparse-support caps per contribution',
            scope: 'outside the proofs',
            ratioAt: perCharge(samplingRows('contribution')),
        },
        {
            name: 'Sparse-support caps per ballot',
            scope: 'outside the proofs',
            ratioAt: perCharge(
                addRationals(
                    fheSecret,
                    sparseBound(
                        auxiliaryInputEncryptionParameters.degree,
                        auxiliaryInputEncryptionParameters.support,
                    ),
                ),
            ),
        },
        {
            // AHU19 one-way to hiding for every potential sender scope,
            // 2*M*Q/2^(s/2) with 512-bit salts and Q <= 4T/c.
            name: 'Registration-source commitment simulation',
            scope: 'outside the proofs',
            ratioAt: (honestRegistrations) =>
                rational(
                    2n * wrap * maskScopesPerRegistration * honestRegistrations,
                    permutationCharge << 256n,
                ),
        },
        {
            // DFMS21 Corollary 4.8 with both normalized ratios at most
            // 2^-512 and l <= f*h extractions: 24*l*Q + 12*l*(l+1) over
            // 2^256 and 296*(Q+l+1)^3 + 2 over 2^512, since 8*sqrt(2) < 12
            // and 40*e^2 < 296, with (a+b)^3 <= 4(a^3+b^3), Q <= 4T/c and
            // T >= c*max(1,h).
            name: 'Registration-source extraction',
            scope: 'outside the proofs',
            ratioAt: (honestRegistrations) => {
                const perRegistration = extractionsPerRegistration;
                const extractions = perRegistration * honestRegistrations;
                return addRationals(
                    rational(
                        24n * wrap * extractions +
                            12n * perRegistration * (extractions + 1n),
                        permutationCharge << 256n,
                    ),
                    rational(
                        1184n *
                            (wrap * queries ** 2n +
                                (perRegistration + 1n) ** 3n *
                                    honestRegistrations ** 2n) +
                            2n,
                        permutationCharge << 512n,
                    ),
                );
            },
        },
        {
            // Registration-source and operation seeds, all of 64 bytes;
            // Merkle seeds belong to the proofs.
            name: 'Private seed expansion',
            scope: 'outside the proofs',
            ratioAt: (honestRegistrations) =>
                seedExpansion(
                    coordinatesPerRegistration * honestRegistrations +
                        scopesAt(honestRegistrations).operationSeeds,
                    operationSeedBytes,
                ),
        },
        {
            // Every pair of seed draws, at most D*h of them for D draws per
            // registration, against T >= c*max(1,h).
            name: 'Private seed collisions',
            scope: 'outside the proofs',
            ratioAt: (honestRegistrations) => {
                const scopes = scopesAt(1n);
                return rational(
                    scopes.maximumSeedDraws ** 2n * honestRegistrations,
                    2n * permutationCharge * scopes.seedCollisionDenominator,
                );
            },
        },
        {
            // h(h-1)/2 pairs of original credentials, against T >= c*h.
            name: 'Honest signing-credential seed collisions',
            scope: 'outside the proofs',
            ratioAt: (honestRegistrations) =>
                honestRegistrations < 2n
                    ? rational(0n)
                    : divide(
                          scale(credentialSeedPair, honestRegistrations - 1n),
                          2n * permutationCharge,
                      ),
        },
        {
            name: 'Merkle salt seed expansion',
            scope: 'proofs',
            ratioAt: (honestRegistrations) =>
                seedExpansion(
                    scopesAt(honestRegistrations).treeSeedScopes,
                    merkleSaltSeedBytes,
                ),
        },
        {
            // Two salted-leaf replacements per committed node.
            name: 'Merkle privacy per honest proof',
            scope: 'proofs',
            ratioAt: perCharge(
                rational(
                    2n * caps.committedNodeBudget,
                    1n << caps.relativeBalanceBits,
                ),
            ),
        },
        {
            name: 'Salted message-root balance per honest proof',
            scope: 'proofs',
            ratioAt: perCharge(
                rational(1n, 1n << (caps.relativeBalanceBits + 1n)),
            ),
        },
        {
            // Its exponent exceeds any representable width, so the term is
            // bounded at 2^-1024.
            name: 'All-input hash-balance exception',
            scope: 'proofs',
            ratioAt: perCharge(
                rational(
                    1n,
                    1n <<
                        (caps.balanceFailureExponent < 1024n
                            ? caps.balanceFailureExponent
                            : 1024n),
                ),
            ),
        },
        {
            // GHHM21 Theorem 1 per programmed message, sqrt(Qp) + Qp/2 with
            // p = 2/2^kappa and one message per honest proof. With
            // Q <= 4T/c and T >= c*P for P honest proofs, the ratio is at
            // most sqrt(4pP)/c + 2pP/c.
            name: 'Adaptive reprogramming of every honest proof',
            scope: 'proofs',
            ratioAt: (honestRegistrations) => {
                const proofs = compileClearPreparationLedger(
                    profile,
                    honestRegistrations,
                ).maximumHonestProofScopes;
                return addRationals(
                    rational(
                        ceilingSquareRoot(2n * wrap * proofs),
                        permutationCharge << (caps.tagBits / 2n),
                    ),
                    rational(wrap * proofs, permutationCharge << caps.tagBits),
                );
            },
        },
        ...compileProofRandomnessBudgets(profile).map(
            (budget): StatisticalTerm => ({
                // The budget's failure is a union over its invocation cap.
                name: `Simulator field sampling per ${budget.role} proof`,
                scope: 'proofs',
                ratioAt: perCharge(
                    rational(
                        budget.failure.numerator,
                        budget.invocationCap << budget.failure.denominatorBits,
                    ),
                ),
            }),
        ),
        {
            // charges(h) <= C0 + C1*h. The constant coefficient is charged
            // against T >= c*max(1,h), the others against T >= c*Q/4 at the
            // largest charged query count.
            name: 'Proof soundness at every semantic-use charge',
            scope: 'proofs',
            ratioAt: (honestRegistrations) => {
                const [constant, ...growing] = soundness.coefficients;
                const perQuery = addRationals(
                    ...growing.map((coefficient, power) =>
                        scale(coefficient, queries ** BigInt(power)),
                    ),
                );
                return divide(
                    addRationals(
                        scale(constant, charges.constant + charges.slope),
                        scale(
                            perQuery,
                            wrap *
                                (charges.constant +
                                    charges.slope * honestRegistrations),
                        ),
                    ),
                    permutationCharge,
                );
            },
        },
    ];
    statisticalTermsCache.set(profile, terms);
    return terms;
};

// The terms' sum, each term rounded up to a multiple of 2^-1024 so that
// million-bit denominators do not enter the sum. The result still bounds the
// exact sum from above.
export const ratioResolutionBits = 1024n;

export const statisticalRatioAt = (
    profile: SupportedProfile,
    honestRegistrations: bigint,
    scope?: StatisticalTerm['scope'],
) =>
    rational(
        compileStatisticalTerms(profile)
            .filter((term) => scope === undefined || term.scope === scope)
            .reduce((sum, term) => {
                const { numerator, denominator } =
                    term.ratioAt(honestRegistrations);
                return (
                    sum +
                    ((numerator << ratioResolutionBits) + denominator - 1n) /
                        denominator
                );
            }, 0n),
        1n << ratioResolutionBits,
    );

const profilesByParticipantCount = () => {
    const groups = new Map<number, SupportedProfile[]>();
    for (const profile of listSupportedProfiles()) {
        const group = groups.get(profile.participantCount) ?? [];
        group.push(profile);
        groups.set(profile.participantCount, group);
    }
    return [...groups.entries()]
        .sort(([left], [right]) => left - right)
        .map(([participantCount, profiles]) => ({
            participantCount,
            profiles,
        }));
};

// The statistical group's own limit for each participant count: the largest
// population whose summed ratio stays within the group's budget at every
// option count, or undefined when every option count stays within it at the
// search cap.
const compileStatisticalPopulationLimits = () =>
    profilesByParticipantCount().map(({ participantCount, profiles }) => {
        let honestRegistrations: bigint | undefined;
        for (const profile of profiles) {
            const within = (population: bigint) =>
                atMost(statisticalRatioAt(profile, population), groupBudget);
            if (
                honestRegistrations !== undefined &&
                within(honestRegistrations)
            )
                continue;
            const limit = largestPopulationWithin(within, honestRegistrations);
            if (limit !== undefined) honestRegistrations = limit;
        }
        return { participantCount, honestRegistrations };
    });

export type LedgerGroup =
    | LatticeAssumptionGroup
    | 'ML-DSA authentication'
    | 'Identity collisions'
    | 'Statistical terms';

export const ledgerGroups: readonly LedgerGroup[] = [
    ...latticeAssumptionGroups,
    'ML-DSA authentication',
    'Identity collisions',
    'Statistical terms',
];

// The poll's original-credential limit for each participant count is the
// smallest group limit. The lattice groups use their criterion floors, and
// the stress test replaces those by their quantum floors. A group with no
// limit below the search cap imposes none.
let securityLedger: ReturnType<typeof solveSecurityLedger> | undefined;

export const compileSecurityLedger = () => {
    securityLedger ??= solveSecurityLedger();
    return securityLedger;
};

const solveSecurityLedger = () => {
    const authentication = compileAuthenticationGroup();
    const identity = compileIdentityCollisionGroup();
    assert.ok(
        identity.withinBudget,
        'Identity collisions exceed their budget.',
    );
    const lattice = latticeAssumptionGroups.map((group) => ({
        group,
        limits: compileLatticePopulationLimits(group),
    }));
    return compileStatisticalPopulationLimits().map(
        ({ participantCount, honestRegistrations }) => {
            const column = (floor: 'criterion' | 'stressTest') => {
                const limits = new Map<LedgerGroup, bigint | undefined>();
                for (const { group, limits: rows } of lattice) {
                    const row = rows.find(
                        (value) => value.participantCount === participantCount,
                    );
                    assert.ok(row !== undefined);
                    limits.set(group, row[floor]?.honestRegistrations);
                }
                limits.set(
                    'ML-DSA authentication',
                    authentication.honestRegistrations,
                );
                limits.set('Identity collisions', undefined);
                limits.set('Statistical terms', honestRegistrations);
                let binding: { group: LedgerGroup; limit: bigint } | undefined;
                for (const [group, limit] of limits)
                    if (
                        limit !== undefined &&
                        (binding === undefined || limit < binding.limit)
                    )
                        binding = { group, limit };
                assert.ok(binding !== undefined);
                return { limits, binding };
            };
            return {
                participantCount,
                criterion: column('criterion'),
                stressTest: column('stressTest'),
            };
        },
    );
};

// Each simulated proof replaces one honest proof, and the direct simulator
// runs the unchanged proof writer on public dummy columns. Beyond the writer
// it samples those dummy entries, adds their public affine pairing, adjusts
// one constant coefficient and samples the message that the replacement
// wrapper programs. Every honest proof costs at least its prover's hash
// permutations, so an experiment of cost T holds at most T/(c*p) simulated
// proofs, for the least prover permutations p of any proof role. The decisive
// experiment has the largest reduction ratio, so the added work fits within a
// lattice group's level at every experiment when it is at most c*p*A/T* per
// simulated proof, where A is the further work that the group's levels still
// absorb at the poll's limit and T* is the decisive experiment. Dividing by
// the proof's dummy entries, every systematic coordinate of its original
// oracles, gives the largest work per entry that keeps record creation within
// every level.
export const compileRecordCreationPricing = () => {
    const systematic = BigInt(
        compileCommonAgreementDegreeCensus().systematicSize,
    );
    return compileSecurityLedger().map((row) => {
        const honestRegistrations = row.criterion.binding.limit;
        let allowance: bigint | undefined;
        let leastProverPermutations: bigint | undefined;
        let largestDummyEntries = 0n;
        for (const profile of listSupportedProfiles().filter(
            (value) => value.participantCount === row.participantCount,
        )) {
            for (const group of latticeAssumptionGroups) {
                const screen = latticeGroupFloors(
                    group,
                    BigInt(profile.ciphertext.bits),
                ).criterion;
                if (screen === undefined) continue;
                const at = latticeRequirementAt(
                    group,
                    profile,
                    honestRegistrations,
                );
                const value = unpricedWorkAllowance(
                    at.comparisons,
                    at.reductionGates,
                    supportedLevelBits(screen),
                );
                if (allowance === undefined || value < allowance)
                    allowance = value;
            }
            for (const hashProfile of proofHashProfiles(profile)) {
                const permutations = compileProofHashWork(profile, hashProfile)
                    .proverHashSubtotal.permutations;
                if (
                    leastProverPermutations === undefined ||
                    permutations < leastProverPermutations
                )
                    leastProverPermutations = permutations;
            }
            for (const role of compileProofRoundErrorCensus(profile).roles) {
                const entries = BigInt(role.originalOracles) * systematic;
                if (entries > largestDummyEntries)
                    largestDummyEntries = entries;
            }
        }
        assert.ok(
            allowance !== undefined &&
                allowance > 0n &&
                leastProverPermutations !== undefined,
        );
        const workPerProof =
            (permutationCharge * leastProverPermutations * allowance) /
            decisiveExperimentGates;
        return {
            participantCount: row.participantCount,
            honestRegistrations,
            allowance,
            leastProverPermutations,
            largestDummyEntries,
            workPerProof,
            workPerEntry: workPerProof / largestDummyEntries,
        };
    });
};
