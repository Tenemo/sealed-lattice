import assert from 'node:assert/strict';

import {
    compilePurposeSignatureWork,
    purposeSignatureParameters,
} from '#tests/authentication-work-model.js';
import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileCommittedOfferCensus } from '#tests/committed-offer-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileBallotWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compilePreparationLedger } from '#tests/preparation-ledger-model.js';
import { compileProofHashDomainCensus } from '#tests/proof-hash-domain-model.js';
import { proofRelationCatalogue } from '#tests/proof-relation-catalogue-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { sourceCommonSampleBits } from '#tests/registration-source-randomness-model.js';
import {
    ceilingSquareRoot,
    type Rational,
} from '#tests/security-ledger/rational.js';
import {
    latticeAssumptionGroups,
    type LatticeAssumptionGroup,
} from '#tests/security-margin/attack-screens.js';
import {
    reductionConstructorDimensions,
    reductionConstructorModuli,
} from '#tests/security-margin/constructor-operands.js';
import {
    compileLatticePopulationLimits,
    largestPopulationWithin,
} from '#tests/security-margin/population-limits.js';
import {
    compileReductionWork,
    maximumExperimentGates,
    minimumReductionWork,
    originalQueryDivisor,
    securityTargetBits,
} from '#tests/security-margin/reduction-work.js';
import { latticeGroupComparisons } from '#tests/security-margin-screen-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { listSupportedProfiles } from '#tests/supported-profile-model.js';
import { compileProofRoundErrorCensus } from '#tests/wide-challenge-compiler-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

const gcd = (left: bigint, right: bigint): bigint =>
    right === 0n ? left : gcd(right, left % right);
const rational = (numerator: bigint, denominator = 1n): Rational => {
    assert.ok(numerator >= 0n && denominator > 0n);
    const divisor = gcd(numerator, denominator);
    return {
        numerator: numerator / divisor,
        denominator: denominator / divisor,
    };
};
const add = (...values: Rational[]) =>
    values.reduce(
        (left, right) =>
            rational(
                left.numerator * right.denominator +
                    right.numerator * left.denominator,
                left.denominator * right.denominator,
            ),
        rational(0n),
    );
const scale = (value: Rational, count: bigint) =>
    rational(value.numerator * count, value.denominator);
const multiply = (left: Rational, right: Rational) =>
    rational(
        left.numerator * right.numerator,
        left.denominator * right.denominator,
    );
const atMost = (left: Rational, right: Rational) =>
    left.numerator * right.denominator <= right.numerator * left.denominator;
const largest = (values: Rational[]) =>
    values.reduce((left, right) => (atMost(left, right) ? right : left));
const targetAt = (work: bigint) => rational(work, 1n << securityTargetBits);

export type LedgerGroup =
    | LatticeAssumptionGroup
    | 'Purpose authentication'
    | 'Identity collisions'
    | 'Statistical terms';
export const ledgerGroups: readonly LedgerGroup[] = [
    ...latticeAssumptionGroups,
    'Purpose authentication',
    'Identity collisions',
    'Statistical terms',
];
export const ledgerGroupBudget = (group: LedgerGroup) =>
    group === 'Statistical terms'
        ? rational(447n, 512n)
        : group === 'Purpose authentication' || group === 'Identity collisions'
          ? rational(1n, 1024n)
          : rational(1n, 32n);

// Bounds of the constructed descriptor, independently checked against every
// active role. The native proof still uses its exact role dimensions.
export const securityProofEnvelope = {
    columns: reductionConstructorDimensions.maximumColumns,
    lookups: reductionConstructorDimensions.maximumLookups,
    oracles: reductionConstructorDimensions.maximumOracles,
    inputBits: 1n << 40n,
    expansionQueries: 1n << 24n,
    programmedPrefixBits: 1n << 24n,
    pricedQueries: reductionConstructorDimensions.pricedQueries,
} as const;

// Complete-function queries allowed per credential for the known
// authentication bank, which needs two adapter calls per bank call.
const authenticationBankQueries = 1n << 20n;

export const semanticMacroEdges = [
    'Original authentication and retained-record normalization',
    'Original credential label comparison',
    'Operation-parent label comparison',
    'Proof-tree label comparison',
    'Registration-source label comparison',
    'Finite mask sampler comparison',
    'Finite sparse sampler comparison',
    'Common-matrix and conditional-fibre initialization',
    'Genuine source-package reconstruction',
    'Genuine retained recipient-key reconstruction',
    'Setup proof-view replacement',
    'Ballot proof-view replacement',
    'Release proof-view replacement',
    'Corrupt-share recovery interface',
    'Corrupt FHE-ballot recovery interface',
    'Prescribed-release interface and joint flooding',
    'Recipient-excluded recovery interface',
    'Joint sharing projection',
    'Immutable source decoding and early first-coordinate interface',
    'Fixed-family affine aggregate embedding',
    'FHE-to-auxiliary corrupt-ballot recovery switch',
    'Good-endpoint recovery restoration',
    'Certified-close and terminal output identity',
    'Public-column setup and retained public-header refinement',
    'Added bounded sampler conversions',
] as const;

export const semanticEndpointBudget = {
    fixedMacroCapacity: 32n,
    authenticationEmbeddingsPerCredential:
        purposeSignatureParameters.treeLeaves,
    credentialSeedEndpointsPerCredential: 2n,
    earlyRepresentationEndpoints: 4n,
    normalizationMultiplier: 2n * 4n,
} as const;

export const validatePricedRoleShape = (shape: {
    columns: bigint;
    lookups: bigint;
    oracles: bigint;
    affineRows: bigint;
}) => {
    assert.ok(
        shape.columns > 0n && shape.columns <= securityProofEnvelope.columns,
    );
    assert.ok(
        shape.lookups >= 0n && shape.lookups <= securityProofEnvelope.lookups,
    );
    assert.ok(
        shape.oracles > 0n && shape.oracles <= securityProofEnvelope.oracles,
    );
    assert.ok(shape.affineRows >= 0n && shape.affineRows <= 1n << 32n);
};

let operands: ReturnType<typeof deriveOperands> | undefined;
const deriveOperands = () => {
    const profiles = listSupportedProfiles();
    const degree = fixedModulusBfvInputs.polynomialDegree;
    assert.equal(degree, reductionConstructorDimensions.degree);
    const agreement = compileCommonAgreementDegreeCensus();
    const queries = BigInt(agreement.queries);
    assert.equal(queries, 704n);
    // Every query-dependent statistical and constructor charge uses the
    // priced count, which must cover the proof's actual queries.
    assert.ok(queries <= securityProofEnvelope.pricedQueries);
    const domain = 4n * degree;
    const prime = compileSmallLimbProofFieldCensus().modulus;
    const roundError = rational(193n ** queries, 256n ** queries);
    const hashDomain = compileProofHashDomainCensus();
    assert.ok(hashDomain.maximumInputBits <= securityProofEnvelope.inputBits);
    assert.ok(
        hashDomain.maximumMessageBits <=
            securityProofEnvelope.programmedPrefixBits,
    );
    assert.ok(
        hashDomain.maximumAcceptedExpansionQueries <=
            securityProofEnvelope.expansionQueries,
    );
    assert.ok(hashDomain.minimumMessageBits >= 512n);
    assert.ok(hashDomain.sentinelCount <= 1n);
    for (const role of proofRelationCatalogue()) {
        const encodedWords = BigInt(role.encodedParameters.length / 4);
        const oracleCount =
            encodedWords -
            7n -
            BigInt(role.relationParameters.length) -
            2n * BigInt(role.lookups.length);
        validatePricedRoleShape({
            columns: BigInt(role.wordColumns + role.booleanColumns),
            lookups: BigInt(role.lookups.length),
            oracles: oracleCount,
            affineRows: 0n,
        });
    }
    const maximumParticipants = Math.max(
        ...profiles.map((profile) => profile.participantCount),
    );
    assert.ok(
        BigInt(maximumParticipants) <=
            reductionConstructorDimensions.participants,
    );
    const maximumSourceFamilies = profiles.reduce((maximum, profile) => {
        const count = compileRegistrationSetupBindingScreen(
            profile.participantCount,
            profile.optionCount,
        ).coordinateCount;
        return count > maximum ? count : maximum;
    }, 0n);
    assert.ok(
        maximumSourceFamilies <= reductionConstructorDimensions.sourceFamilies,
    );
    assert.ok(
        BigInt(semanticMacroEdges.length) <=
            semanticEndpointBudget.fixedMacroCapacity,
    );
    assert.ok(fixedModulusBfvInputs.secretSupportWeight <= 1024n);
    // Accepted seven-bit error words include rank zero, which encodes -64.
    // Their norm bound is independent of the honest sampler's probabilities.
    assert.equal(fixedModulusBfvInputs.errorBound, 64n);
    assert.ok(shareEncryptionParameters.encryptionSupportWeight <= 256n);
    assert.equal(auxiliaryInputEncryptionParameters.degree, 4096n);
    assert.ok(auxiliaryInputEncryptionParameters.modulus < 1n << 63n);
    assert.ok(auxiliaryInputEncryptionParameters.support <= 256n);
    const signatureWork = compilePurposeSignatureWork();
    const credentialPredecessor = signatureWork.credentialPredecessorGates;
    // The late interval begins no later than one complete honest credential
    // construction, which precedes every reduction factory.
    assert.ok(minimumReductionWork <= credentialPredecessor);
    assert.ok(
        2n * signatureWork.maximumKnownBankCallsPerCredential <=
            authenticationBankQueries,
    );
    assert.equal(
        reductionConstructorModuli.shareModulus,
        shareEncryptionParameters.modulus,
    );
    assert.equal(
        reductionConstructorModuli.auxiliaryModulus,
        auxiliaryInputEncryptionParameters.modulus,
    );
    assert.equal(
        reductionConstructorModuli.sourceSampleBits,
        sourceCommonSampleBits,
    );
    // A result needs the minimum turnout, of which at most the fault bound
    // can be corrupt; the rest are original honest ballots.
    const honestBallotFloor = profiles.reduce((least, profile) => {
        const honest = BigInt(
            profile.minimumTurnout - profile.maximumCorruptParticipantCount,
        );
        return honest < least ? honest : least;
    }, BigInt(Number.MAX_SAFE_INTEGER));
    assert.ok(honestBallotFloor >= 2n);
    const ballotRowBytes = 336n;
    const releasePredecessor =
        honestBallotFloor *
        domain *
        (ballotRowBytes / 168n) *
        originalQueryDivisor;
    const auxiliary = auxiliaryInputEncryptionParameters;
    const rawBias = (modulus: bigint, width: bigint) => {
        const space = 1n << width,
            remainder = space % modulus;
        return rational(remainder * (modulus - remainder), modulus * space);
    };
    const sharingRatios: Rational[] = [],
        releaseRatios: Rational[] = [],
        initializations: Rational[] = [];
    let maximumPrimitiveSlope = 0n;
    for (const profile of profiles) {
        assert.ok(
            profile.gadgetLength <= reductionConstructorDimensions.gadgets &&
                profile.ciphertext.bits <= 1024,
        );
        assert.ok(profile.optionCount <= 20);
        assert.ok(
            BigInt(profile.setupContributorCount) <=
                reductionConstructorDimensions.selectedContributors,
        );
        assert.ok(profile.releaseThreshold <= 7);
        assert.ok(profile.shareLifting.sharingCoefficientBits <= 127);
        assert.ok(profile.releaseNoiseBits <= 1024);
        assert.ok(profile.release.bits <= 1024);
        assert.ok(
            atMost(
                compileProofRoundErrorCensus(profile).maximumRoundError,
                roundError,
            ),
        );
        for (const role of compileProofRoundErrorCensus(profile).roles)
            assert.ok(role.affineRows >= 0n && role.affineRows <= 1n << 32n);
        assert.ok(
            atMost(
                compileCommittedOfferCensus(profile).sampledAlgebraic,
                roundError,
            ),
        );
        assert.ok(
            compileBallotWordProofLayout(profile).firstWidth >= ballotRowBytes,
        );
        const sharingNumerator =
            fixedModulusBfvInputs.secretSupportWeight *
            ((1n << BigInt(profile.releaseThreshold - 1)) - 1n);
        sharingRatios.push(
            rational(
                sharingNumerator * (1n << securityTargetBits),
                (1n << BigInt(profile.shareLifting.sharingCoefficientBits)) *
                    credentialPredecessor,
            ),
        );
        const releaseShift =
            degree *
            profile.interpolation.maximumJointSimulationOneNormSum *
            profile.releaseError;
        releaseRatios.push(
            rational(
                releaseShift * (1n << securityTargetBits),
                (1n << BigInt(profile.releaseNoiseBits)) * releasePredecessor,
            ),
        );
        const sampling = compileCommonMatrixSamplingCensus(profile);
        assert.ok(sampling.fheBitsPerCoefficient <= 1280);
        assert.ok(sampling.fixedFamilyBitsPerCoefficient <= 448);
        const groups = [
            {
                count: 3n * profile.gadgetLength * degree,
                modulus: profile.ciphertext.modulus,
                bits: BigInt(sampling.fheBitsPerCoefficient),
            },
            {
                count: degree,
                modulus: shareEncryptionParameters.modulus,
                bits: BigInt(sampling.fixedFamilyBitsPerCoefficient),
            },
            {
                count: 2n * auxiliary.degree,
                modulus: auxiliary.modulus,
                bits: BigInt(sampling.fixedFamilyBitsPerCoefficient),
            },
            {
                count: 4n * degree,
                modulus: auxiliary.modulus,
                bits: sourceCommonSampleBits,
            },
        ];
        const coefficients = groups.reduce(
            (sum, group) => sum + group.count,
            0n,
        );
        initializations.push(
            add(
                ...groups.map((group) =>
                    scale(rawBias(group.modulus, group.bits), group.count),
                ),
                rational(2n * coefficients, 1n << 514n),
                rational(1n, 1n << 512n),
            ),
        );
        const ledger = compilePreparationLedger(profile, 1n);
        const slope =
            latticeAssumptionGroups.reduce(
                (sum, group) => sum + latticeGroupComparisons(group, ledger),
                0n,
            ) - 3n;
        if (slope > maximumPrimitiveSlope) maximumPrimitiveSlope = slope;
    }
    const sharingRatio = largest(sharingRatios),
        releaseRatio = largest(releaseRatios);
    assert.ok(atMost(sharingRatio, rational(5n, 8n)));
    assert.ok(atMost(releaseRatio, rational(1n, 8n)));
    const treeCount = BigInt(domain.toString(2).length);
    const masks = 2n * securityProofEnvelope.pricedQueries + 1n;
    const maskCells =
        masks *
            (securityProofEnvelope.columns +
                3n * securityProofEnvelope.lookups +
                7n) +
        18n * degree;
    return {
        degree,
        domain,
        prime,
        queries,
        roundError,
        maximumParticipants: BigInt(maximumParticipants),
        maximumSourceFamilies,
        maximumPrimitiveSlope,
        credentialPredecessor,
        releasePredecessor,
        sharingRatio,
        releaseRatio,
        initialization: largest(initializations),
        treeCount,
        maskCells,
    };
};
export const compileSecurityOperands = () => (operands ??= deriveOperands());

const semanticEndpointMultiplier = (honestRegistrations: bigint) => {
    const value = compileSecurityOperands();
    const comparisons = 3n + value.maximumPrimitiveSlope * honestRegistrations;
    const budget = semanticEndpointBudget;
    return (
        budget.normalizationMultiplier *
        (2n *
            (budget.fixedMacroCapacity +
                comparisons +
                budget.authenticationEmbeddingsPerCredential *
                    honestRegistrations) +
            budget.credentialSeedEndpointsPerCredential * honestRegistrations +
            budget.earlyRepresentationEndpoints)
    );
};

const authenticationParts = (work: bigint, population: bigint) => {
    // Late games also carry the reduction's fixed external queries.
    const lateQueries =
        work >= minimumReductionWork
            ? compileReductionWork(population).fixedExternalQueries
            : 0n;
    const queries = add(
        rational(2n * work, originalQueryDivisor),
        rational(
            authenticationBankQueries * (population + 1n) +
                128n * (work + population + 1n) +
                lateQueries,
        ),
    );
    const labelQueries = add(queries, rational(1n));
    const chainQueries = scale(queries, 2n);
    const { chains, radix } = purposeSignatureParameters;
    const squared = multiply(chainQueries, chainQueries);
    const expression = add(
        scale(
            squared,
            chains ** 2n *
                (radix - 1n) ** 2n *
                (20n * radix - 4n) ** 2n *
                (chains + 1n),
        ),
        rational(chains + 1n + 3n * radix ** 2n * chains ** 2n),
    );
    const oneTime = rational(
        4n * 16n * population * expression.numerator,
        expression.denominator * (1n << 512n),
    );
    const labels = add(
        rational(population * (population - 1n), 1n << 512n),
        rational(
            4n * labelQueries.numerator * ceilingSquareRoot(population),
            labelQueries.denominator * (1n << 256n),
        ),
        rational(
            4n * queries.numerator * population,
            queries.denominator * (1n << 512n),
        ),
    );
    const base = add(scale(queries, 2n), rational(2n)),
        cube = multiply(base, multiply(base, base));
    const binding = rational(
        12n * cube.numerator + 4n * cube.denominator,
        cube.denominator * (1n << 512n),
    );
    const attempts = 128n * (work + population + 1n);
    const tags = add(
        rational(attempts, 1n << 512n),
        rational(attempts * (attempts - 1n), 1n << 513n),
    );
    const endpoints = 2n * semanticEndpointMultiplier(population);
    return {
        authentication: scale(add(oneTime, labels, tags), endpoints),
        identity: scale(binding, endpoints),
    };
};

const compileStatisticalTerms = (honestRegistrations: bigint, work: bigint) => {
    assert.ok(
        honestRegistrations > 0n &&
            work >= minimumReductionWork &&
            work <= maximumExperimentGates,
    );
    const value = compileSecurityOperands(),
        envelope = compileReductionWork(honestRegistrations);
    const queries = add(
        rational(2n * work, originalQueryDivisor),
        rational(envelope.fixedExternalQueries),
    );
    const endpoints = semanticEndpointMultiplier(honestRegistrations);
    const expanded = add(
        scale(queries, 2n),
        rational(securityProofEnvelope.expansionQueries),
    );
    const lift = add(
        scale(expanded, securityProofEnvelope.inputBits + 2n),
        rational(securityProofEnvelope.inputBits + 1n),
    );
    const liftedRound = add(
        value.roundError,
        rational(lift.numerator, lift.denominator * (1n << 512n)),
    );
    const soundness = add(
        scale(multiply(liftedRound, multiply(expanded, expanded)), 12n),
        rational(2n * securityProofEnvelope.expansionQueries, 1n << 512n),
    );
    const parents = (value.maximumSourceFamilies + 4n) * honestRegistrations;
    const trees = 3n * honestRegistrations * value.treeCount;
    const sources = value.maximumSourceFamilies * honestRegistrations;
    const labelQueries = add(queries, rational(1n));
    const privateLabels = add(
        rational(
            parents * (parents - 1n) +
                trees * (trees - 1n) +
                sources * (sources - 1n),
            1n << 512n,
        ),
        rational(
            4n *
                labelQueries.numerator *
                (ceilingSquareRoot(parents) +
                    ceilingSquareRoot(trees) +
                    ceilingSquareRoot(sources)),
            labelQueries.denominator * (1n << 256n),
        ),
        rational(
            4n * queries.numerator * sources,
            queries.denominator * (1n << 512n),
        ),
    );
    const proofView = add(
        rational(1n, 1n << 1024n),
        rational(
            3n * work * (4n * value.domain - 4n),
            minimumReductionWork * (1n << 192n),
        ),
        scale(
            add(
                rational(
                    2n * queries.numerator + queries.denominator,
                    queries.denominator * (1n << 256n),
                ),
                rational(
                    2n * queries.numerator,
                    queries.denominator * (1n << 512n),
                ),
            ),
            3n * honestRegistrations,
        ),
    );
    const rejectedFieldWords = (1n << 128n) - value.prime;
    const factories =
        (value.maximumSourceFamilies + 4n) * honestRegistrations + 1n;
    const sparse =
        (2n * value.maximumSourceFamilies + value.maximumParticipants + 4n) *
        honestRegistrations;
    const uniform =
        (4n * 32n + 2n * value.maximumParticipants + 16n) *
        value.degree *
        factories;
    return [
        {
            name: 'Sharing translation',
            value: multiply(targetAt(work), value.sharingRatio),
        },
        {
            name: 'Prescribed release',
            value: multiply(targetAt(work), value.releaseRatio),
        },
        { name: 'Semantic soundness', value: scale(soundness, endpoints) },
        { name: 'Private labels', value: scale(privateLabels, endpoints) },
        { name: 'Complete proof view', value: scale(proofView, endpoints) },
        {
            name: 'Original proof-mask sampling',
            value: rational(
                endpoints *
                    3n *
                    value.maskCells *
                    rejectedFieldWords ** 3n *
                    work,
                minimumReductionWork * (1n << 384n),
            ),
        },
        {
            name: 'Public initialization',
            value: scale(value.initialization, 2n * endpoints),
        },
        {
            name: 'Original sparse sampling',
            value: rational(endpoints * sparse, 1n << 512n),
        },
        {
            name: 'Added sampler conversions',
            value: scale(
                add(
                    rational(32n * factories, 1n << 512n),
                    rational(uniform, 1n << 514n),
                ),
                2n * endpoints,
            ),
        },
    ];
};

export const compileErrorGroups = (
    honestRegistrations: bigint,
    work: bigint,
) => {
    assert.ok(
        honestRegistrations > 0n && work > 0n && work <= maximumExperimentGates,
    );
    const early = authenticationParts(work, honestRegistrations);
    if (work < minimumReductionWork)
        return {
            authentication: early.authentication,
            identity: early.identity,
            statistical: rational(0n),
        };
    const envelope = compileReductionWork(honestRegistrations);
    const queries = add(
        rational(2n * work, originalQueryDivisor),
        rational(envelope.fixedExternalQueries),
    );
    const base = add(scale(queries, 2n), rational(2n)),
        cube = multiply(base, multiply(base, base));
    const binding = rational(
        12n * cube.numerator + 4n * cube.denominator,
        cube.denominator * (1n << 512n),
    );
    return {
        authentication: early.authentication,
        identity: add(
            early.identity,
            scale(binding, semanticEndpointMultiplier(honestRegistrations)),
        ),
        statistical: add(
            ...compileStatisticalTerms(honestRegistrations, work).map(
                (term) => term.value,
            ),
        ),
    };
};

// At fixed H, each ratio is a nonnegative sum of T^-1,1,T,T^2.
// Convexity proves the entire nontrivial interval from these endpoints.
export const compileErrorEnvelope = (honestRegistrations: bigint) =>
    [
        1n,
        minimumReductionWork - 1n,
        minimumReductionWork,
        maximumExperimentGates,
    ].map((work) => ({
        work,
        ...compileErrorGroups(honestRegistrations, work),
    }));

const nonLatticeLimit = (
    group:
        'Purpose authentication' | 'Identity collisions' | 'Statistical terms',
) => {
    const key =
        group === 'Purpose authentication'
            ? 'authentication'
            : group === 'Identity collisions'
              ? 'identity'
              : 'statistical';
    return largestPopulationWithin((population) =>
        compileErrorEnvelope(population).every((row) =>
            atMost(
                row[key],
                multiply(targetAt(row.work), ledgerGroupBudget(group)),
            ),
        ),
    );
};
let extraLimits: Map<LedgerGroup, bigint> | undefined;
const statisticalLimits = () =>
    (extraLimits ??= new Map([
        ['Purpose authentication', nonLatticeLimit('Purpose authentication')],
        ['Identity collisions', nonLatticeLimit('Identity collisions')],
        ['Statistical terms', nonLatticeLimit('Statistical terms')],
    ]));
let ledger: ReturnType<typeof deriveSecurityLedger> | undefined;
const deriveSecurityLedger = () => {
    const lattices = latticeAssumptionGroups.map((group) => ({
        group,
        rows: compileLatticePopulationLimits(group),
    }));
    return lattices[0].rows.map(({ participantCount }) => {
        const column = (kind: 'criterion' | 'stressTest') => {
            const limits = new Map(statisticalLimits());
            for (const { group, rows } of lattices)
                limits.set(
                    group,
                    rows.find(
                        (row) => row.participantCount === participantCount,
                    )![kind].honestRegistrations,
                );
            const [group, limit] = [...limits].reduce((left, right) =>
                left[1] <= right[1] ? left : right,
            );
            return { limits, binding: { group, limit } };
        };
        return {
            participantCount,
            criterion: column('criterion'),
            stressTest: column('stressTest'),
        };
    });
};
export const compileSecurityLedger = () => (ledger ??= deriveSecurityLedger());
