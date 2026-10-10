import { describe, expect, it } from 'vitest';

import { compileClearPreparationLedger } from '#tests/clear-preparation-ledger-model.js';
import { compilePrivateRandomnessScopes } from '#tests/operation-seed-model.js';
import {
    compileProofHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import {
    atMost,
    rationalCeilingLog2,
    ceilingSquareRoot,
    compileAuthenticationGroup,
    compileComparisonGrowth,
    compileIdentityCollisionGroup,
    compileRecordCreationPricing,
    compileSecurityLedger,
    compileSemanticUseCharges,
    compileSoundnessCharge,
    compileStatisticalTerms,
    groupBudget,
    rational,
    ratioResolutionBits,
    semanticUseStepsOutsideComparisons,
    soundnessChargeAt,
    statisticalRatioAt,
    type Rational,
} from '#tests/security-ledger-model.js';
import {
    compileFhePopulationLimits,
    compileLatticePopulationLimits,
    instanceKnownAttackFloor,
    latticeAssumptionGroups,
    latticeGroupComparisons,
    latticeGroupFloors,
    latticeRequirementAt,
    populationSearchCap,
    supportedLevelBits,
    unpricedWorkAllowance,
} from '#tests/security-margin-screen-model.js';
import {
    deriveSupportedProfile,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';
import { compileProofRoundErrorCensus } from '#tests/wide-challenge-compiler-model.js';

// FIPS 202: Keccak-f[1600] has 12+2*log2(64) rounds, and chi multiplies two
// state bits for each of the 1600 state bits in every round.
const permutationCharge = 24n * 1600n;
const largestExperiment = 1n << 80n;
// Every wrapper of the compiler's hybrids makes at most four calls per call.
const callsPerQuery = 4n;
const budget = rational(1n, 1n << 83n);

// FIPS 202 pads after the SHAKE suffix, so absorbing m bytes at rate r takes
// floor(m/r)+1 permutations, and an output of at most r bytes adds none.
const shake256Permutations = (inputBytes: bigint) => inputBytes / 136n + 1n;

// FIPS 204 Table 1 for ML-DSA-65.
const mlDsa65 = {
    modulus: 8_380_417n,
    rowCount: 6n,
    collisionStrength: 192n,
    publicKeyDigestBytes: 64n,
};

// Every purpose an original credential signs: the organizer's poll
// definition, registration, roster proposal, contribution offer, selection
// proposal and endorsement, optional ballot, close intent, response and
// proposal, target certification and release envelope.
const organizerPurposes = [
    ['poll-definition', 'v2'],
    ['registration', 'v1'],
    ['roster-proposal', 'v1'],
    ['contribution-offer', 'v1'],
    ['setup-selection-proposal', 'v1'],
    ['setup-selection-endorsement', 'v1'],
    ['ballot-envelope', 'v1'],
    ['close-intent', 'v1'],
    ['close-response', 'v1'],
    ['close-proposal', 'v1'],
    ['target-certification', 'v1'],
    ['release-envelope', 'v1'],
] as const;

const maximumCorrupt = (participantCount: number) =>
    BigInt(Math.floor((participantCount - 1) / 3));

// Whether value/experiment <= bound, compared exactly.
const ratioWithin = (value: Rational, experiment: bigint, bound: Rational) =>
    value.numerator * bound.denominator <=
    bound.numerator * value.denominator * experiment;

const experimentsFrom = (minimum: bigint) =>
    [
        minimum,
        minimum << 10n,
        (largestExperiment / permutationCharge) * permutationCharge,
        largestExperiment,
    ].filter((gates) => gates >= minimum && gates <= largestExperiment);

const queriesAt = (gates: bigint) =>
    callsPerQuery * (gates / permutationCharge);

const populationsUpTo = (limit: bigint) =>
    [0n, 1n, 2n, 1_000n, 1n << 30n, limit].filter((value) => value <= limit);

describe('security ledger', () => {
    const ledger = compileSecurityLedger();
    const fheLimits = compileFhePopulationLimits();
    const profiles = listSupportedProfiles();
    const sampleProfiles = [
        deriveSupportedProfile(3, 2),
        deriveSupportedProfile(4, 5),
        deriveSupportedProfile(13, 20),
        deriveSupportedProfile(20, 20),
    ];

    it('computes exact integer square roots and base-two logarithms', () => {
        for (const [value, root] of [
            [0n, 0n],
            [1n, 1n],
            [2n, 2n],
            [4n, 2n],
            [5n, 3n],
            [(1n << 64n) ** 2n, 1n << 64n],
            [(1n << 64n) ** 2n + 1n, (1n << 64n) + 1n],
        ] as const)
            expect(ceilingSquareRoot(value)).toBe(root);
        expect(rationalCeilingLog2(rational(1n))).toBe(0n);
        expect(rationalCeilingLog2(rational(1n, 2n))).toBe(-1n);
        expect(rationalCeilingLog2(rational(1n, 3n))).toBe(-1n);
        expect(rationalCeilingLog2(rational(3n, 2n))).toBe(1n);
        expect(rationalCeilingLog2(rational(1n, 1n << 300n))).toBe(-300n);
        expect(
            rationalCeilingLog2(rational((1n << 300n) + 1n, 1n << 300n)),
        ).toBe(1n);
        expect(groupBudget).toEqual(budget);
    });

    it('bounds ML-DSA authentication from the FIPS operands', () => {
        const authentication = compileAuthenticationGroup();
        expect(authentication.signedFramesPerKey).toBe(
            BigInt(organizerPurposes.length),
        );
        // tr || M' with M' = 0 || |ctx| || ctx || a 64-byte digest.
        const shortestContext = organizerPurposes
            .filter(([purpose]) => !purpose.endsWith('-envelope'))
            .map(
                ([purpose, version]) =>
                    `sealed-lattice/${purpose}/${version}`.length,
            )
            .reduce((minimum, value) => Math.min(minimum, value));
        const frameInputBytes =
            mlDsa65.publicKeyDigestBytes + 2n + BigInt(shortestContext) + 64n;
        expect(authentication.shortestFrameInputBytes).toBe(frameInputBytes);
        // w1 has (q-1)/(2*gamma2) values per coefficient with
        // gamma2 = (q-1)/32.
        const roundingBound = (mlDsa65.modulus - 1n) / 32n;
        const highValues = (mlDsa65.modulus - 1n) / (2n * roundingBound);
        const highBits = BigInt((highValues - 1n).toString(2).length);
        const challengeInputBytes = 64n + 32n * mlDsa65.rowCount * highBits;
        expect(challengeInputBytes).toBe(832n);
        expect((mlDsa65.collisionStrength * 2n) / 8n).toBeLessThanOrEqual(136n);
        const verification =
            shake256Permutations(frameInputBytes) +
            shake256Permutations(challengeInputBytes) +
            1n;
        expect(verification).toBe(10n);
        expect(authentication.verificationPermutations).toBe(verification);
        const verificationGates = verification * permutationCharge;
        const comparisonGates = BigInt(organizerPurposes.length) * 1025n;
        const limit =
            ((1n << 192n) * verificationGates ** 2n) /
            ((1n << 83n) *
                largestExperiment *
                (verificationGates + comparisonGates) ** 2n);
        expect(authentication.honestRegistrations).toBe(limit);
        // The limit holds at the largest experiment and one more key fails.
        const holds = (keys: bigint) =>
            keys *
                (verificationGates + comparisonGates) ** 2n *
                largestExperiment *
                (1n << 83n) <=
            (1n << 192n) * verificationGates ** 2n;
        expect(holds(limit)).toBe(true);
        expect(holds(limit + 1n)).toBe(false);
        expect(Number(limit) / 2 ** 29).toBeGreaterThan(0.93);
        expect(Number(limit) / 2 ** 29).toBeLessThan(0.94);
    });

    it('dominates both DFMS21 extraction coefficients with exact integers', () => {
        // Summing e through 1/3! and bounding the tail geometrically by
        // (1/4!)/(1-1/5) gives e <= 261/96 = 87/32.
        expect(96 + 96 + 48 + 16 + 5).toBe(3 * 87);
        // Hence 40*e^2 < 296, and sqrt(2) < 3/2 gives 8*sqrt(2) < 12.
        expect(40n * 87n ** 2n).toBeLessThan(296n * 32n ** 2n);
        expect(12n ** 2n).toBeGreaterThan(8n ** 2n * 2n);
    });

    it('keeps identity collisions within their budget at every experiment', () => {
        const identity = compileIdentityCollisionGroup();
        expect(identity.withinBudget).toBe(true);
        for (const gates of experimentsFrom(permutationCharge)) {
            const queries = queriesAt(gates);
            // (sqrt(4(q+2)^3/2^n)+sqrt(2/2^n))^2 <= (8(q+2)^3+4)/2^n.
            const collision = rational(
                8n * (queries + 2n) ** 3n + 4n,
                1n << 512n,
            );
            expect(ratioWithin(collision, gates, identity.ratio)).toBe(true);
        }
        expect(rationalCeilingLog2(identity.ratio)).toBeLessThan(-300n);
    });

    it('bounds every lattice group comparison count by its affine growth', () => {
        for (const profile of sampleProfiles) {
            const corrupt = maximumCorrupt(profile.participantCount);
            const participants = BigInt(profile.participantCount);
            const endorsers = participants - 2n * corrupt;
            const growth = compileComparisonGrowth(profile);
            const share = growth.find(
                (row) => row.group === 'Share-encryption Ring-LWE',
            )!;
            expect(share.slope).toBe(2n + 2n * participants);
            for (const registrations of [
                0n,
                1n,
                2n,
                3n,
                endorsers - 1n,
                endorsers,
                endorsers + 1n,
                97n,
                (1n << 20n) + 1n,
                (1n << 40n) + 7n,
            ]) {
                const counts = compileClearPreparationLedger(
                    profile,
                    registrations,
                );
                for (const row of growth)
                    expect(
                        latticeGroupComparisons(row.group, counts),
                    ).toBeLessThanOrEqual(
                        row.constant + row.slope * registrations,
                    );
                for (const row of growth.filter(
                    (value) => value.group !== 'Auxiliary Ring-LWE',
                ))
                    expect(latticeGroupComparisons(row.group, counts)).toBe(
                        row.slope * registrations,
                    );
                // The auxiliary key comparison and, once a roster can be
                // certified, every honest ballot message.
                const certified = registrations / endorsers;
                const ballots =
                    certified * participants < registrations
                        ? certified * participants
                        : registrations;
                expect(
                    latticeGroupComparisons('Auxiliary Ring-LWE', counts),
                ).toBe(1n + ballots);
                const charges = compileSemanticUseCharges(profile);
                const total = latticeAssumptionGroups.reduce(
                    (sum, group) =>
                        sum + latticeGroupComparisons(group, counts),
                    0n,
                );
                expect(
                    2n *
                        (BigInt(semanticUseStepsOutsideComparisons.length) +
                            total),
                ).toBeLessThanOrEqual(
                    charges.constant + charges.slope * registrations,
                );
            }
        }
    });

    it('expands the semantic-use soundness charge exactly', () => {
        const soundness = compileSoundnessCharge();
        const tagSpace = 1n << soundness.tagBits;
        expect(soundness.tagBits).toBe(512n);
        expect(soundness.sentinels).toBe(1n);
        for (const queries of [
            0n,
            1n,
            1n << 20n,
            queriesAt(largestExperiment),
        ]) {
            const t = 2n * queries + soundness.expansionQueries;
            // J = epsilon + (W(t+1) + b + 2t)/2^kappa.
            const tagged =
                soundness.inputBits * (t + 1n) + soundness.sentinels + 2n * t;
            const j = rational(
                soundness.roundError.numerator * tagSpace +
                    tagged * soundness.roundError.denominator,
                soundness.roundError.denominator * tagSpace,
            );
            const messageSpace = 1n << soundness.messageBits;
            const direct = rational(
                12n * t * t * j.numerator * messageSpace +
                    2n * soundness.expansionQueries * j.denominator,
                j.denominator * messageSpace,
            );
            const expanded = soundnessChargeAt(queries);
            expect(
                direct.numerator * expanded.denominator ===
                    expanded.numerator * direct.denominator,
            ).toBe(true);
        }
        // The query error dominates the round error, and one charge at the
        // largest experiment stays far below the budget.
        expect(rationalCeilingLog2(soundness.roundError)).toBe(-286n);
        expect(
            rationalCeilingLog2(
                soundnessChargeAt(queriesAt(largestExperiment)),
            ),
        ).toBeLessThan(-140n);
    });

    it('bounds each population-dependent statistical term at every experiment', () => {
        for (const profile of [
            deriveSupportedProfile(3, 2),
            deriveSupportedProfile(20, 20),
        ]) {
            const terms = new Map(
                compileStatisticalTerms(profile).map((term) => [
                    term.name,
                    term,
                ]),
            );
            const soundness = compileSoundnessCharge();
            const directSoundness = (queries: bigint) => {
                const t = 2n * queries + soundness.expansionQueries;
                const tagSpace = 1n << soundness.tagBits;
                const tagged =
                    soundness.inputBits * (t + 1n) +
                    soundness.sentinels +
                    2n * t;
                const messageSpace = 1n << soundness.messageBits;
                return rational(
                    12n *
                        t *
                        t *
                        (soundness.roundError.numerator * tagSpace +
                            tagged * soundness.roundError.denominator) *
                        messageSpace +
                        2n *
                            soundness.expansionQueries *
                            soundness.roundError.denominator *
                            tagSpace,
                    soundness.roundError.denominator * tagSpace * messageSpace,
                );
            };
            // Each term's true value as a function of the registrations and
            // the experiment, with the least experiment it implies.
            const cases: readonly (readonly [
                string,
                (
                    registrations: bigint,
                    counts: ReturnType<typeof compileClearPreparationLedger>,
                ) => bigint,
                (
                    registrations: bigint,
                    counts: ReturnType<typeof compileClearPreparationLedger>,
                    queries: bigint,
                ) => Rational,
            ])[] = [
                [
                    'Registration-source commitment simulation',
                    (registrations) => registrations,
                    (_, counts, queries) =>
                        rational(
                            2n * counts.sourceMaskScopes * queries,
                            1n << 256n,
                        ),
                ],
                [
                    'Registration-source extraction',
                    (registrations) => registrations,
                    (_, counts, queries) => {
                        const extractions =
                            counts.maximumCorruptSourceExtractions;
                        return rational(
                            (12n * extractions * (queries + extractions) +
                                12n * extractions * (queries + 1n)) *
                                (1n << 256n) +
                                296n * (queries + extractions + 1n) ** 3n +
                                2n,
                            1n << 512n,
                        );
                    },
                ],
                [
                    'Private seed expansion',
                    (registrations) => registrations,
                    (registrations, counts, queries) =>
                        rational(
                            4n *
                                (queries + 1n) *
                                ceilingSquareRoot(
                                    counts.generatedSourceEntries +
                                        4n * registrations,
                                ),
                            1n << 256n,
                        ),
                ],
                [
                    'Private seed collisions',
                    (registrations) => registrations,
                    (registrations, counts) =>
                        rational(
                            compilePrivateRandomnessScopes(
                                counts.generatedSourceEntries,
                                registrations,
                                registrations,
                                registrations,
                            ).seedCollisionPairs,
                            1n << 512n,
                        ),
                ],
                [
                    'Honest signing-credential seed collisions',
                    (registrations) => registrations,
                    (registrations) =>
                        rational(
                            registrations < 2n
                                ? 0n
                                : registrations * (registrations - 1n),
                            1n << 256n,
                        ),
                ],
                [
                    'Merkle salt seed expansion',
                    (registrations) => registrations,
                    (registrations, counts, queries) =>
                        rational(
                            4n *
                                (queries + 1n) *
                                ceilingSquareRoot(
                                    compilePrivateRandomnessScopes(
                                        counts.generatedSourceEntries,
                                        registrations,
                                        registrations,
                                        registrations,
                                    ).treeSeedScopes,
                                ),
                            1n << 256n,
                        ),
                ],
                [
                    'Adaptive reprogramming of every honest proof',
                    (_, counts) => counts.maximumHonestProofScopes,
                    (_, counts, queries) =>
                        rational(
                            counts.maximumHonestProofScopes *
                                (ceilingSquareRoot(2n * queries) *
                                    (1n << 256n) +
                                    queries),
                            1n << 512n,
                        ),
                ],
                [
                    'Proof soundness at every semantic-use charge',
                    (registrations) => registrations,
                    (_, counts, queries) => {
                        const charges =
                            2n *
                            (BigInt(semanticUseStepsOutsideComparisons.length) +
                                latticeAssumptionGroups.reduce(
                                    (sum, group) =>
                                        sum +
                                        latticeGroupComparisons(group, counts),
                                    0n,
                                ));
                        const value = directSoundness(queries);
                        return rational(
                            charges * value.numerator,
                            value.denominator,
                        );
                    },
                ],
            ];
            for (const population of [1n << 30n, populationSearchCap])
                for (const [name, operations, value] of cases) {
                    const term = terms.get(name);
                    expect(term).toBeDefined();
                    const bound = term!.ratioAt(population);
                    for (const registrations of populationsUpTo(population)) {
                        const counts = compileClearPreparationLedger(
                            profile,
                            registrations,
                        );
                        const least =
                            permutationCharge *
                            [
                                1n,
                                registrations,
                                operations(registrations, counts),
                            ].reduce((maximum, count) =>
                                count > maximum ? count : maximum,
                            );
                        for (const gates of experimentsFrom(least))
                            expect(
                                ratioWithin(
                                    value(
                                        registrations,
                                        counts,
                                        queriesAt(gates),
                                    ),
                                    gates,
                                    bound,
                                ),
                            ).toBe(true);
                    }
                }
        }
    });

    it('stays within the statistical budget at the search cap', () => {
        for (const profile of sampleProfiles) {
            const terms = compileStatisticalTerms(profile);
            const exact = terms.map((term) =>
                term.ratioAt(populationSearchCap),
            );
            const sum = statisticalRatioAt(profile, populationSearchCap);
            // The rounded sum bounds the exact one from above, by at most
            // one resolution step per term.
            const resolution = 1n << ratioResolutionBits;
            for (const value of exact) expect(atMost(value, sum)).toBe(true);
            const floorSum = exact.reduce(
                (total, value) =>
                    total + (value.numerator * resolution) / value.denominator,
                0n,
            );
            expect(sum.numerator).toBeGreaterThanOrEqual(floorSum);
            expect(sum.numerator - floorSum).toBeLessThanOrEqual(
                BigInt(terms.length),
            );
            expect(atMost(sum, budget)).toBe(true);
            // Outside the proofs and in them, the sum never falls as the
            // population grows.
            let previous = rational(0n);
            for (const population of [
                0n,
                1n,
                1n << 20n,
                1n << 40n,
                1n << 63n,
            ]) {
                const value = statisticalRatioAt(profile, population);
                expect(atMost(previous, value)).toBe(true);
                previous = value;
            }
        }
        for (const row of ledger)
            expect(row.criterion.limits.get('Statistical terms')).toBe(
                undefined,
            );
    });

    it('takes the poll limit as the smallest group limit', () => {
        const authentication = compileAuthenticationGroup();
        expect(ledger.map((row) => row.participantCount)).toEqual(
            fheLimits.map((row) => row.participantCount),
        );
        for (const row of ledger) {
            const fhe = fheLimits.find(
                (value) => value.participantCount === row.participantCount,
            )!;
            for (const [column, fheLimit] of [
                [row.criterion, fhe.criterion.honestRegistrations],
                [row.stressTest, fhe.stressTest.honestRegistrations],
            ] as const) {
                expect(column.limits.get('FHE Ring-LWE')).toBe(fheLimit);
                expect(column.limits.get('ML-DSA authentication')).toBe(
                    authentication.honestRegistrations,
                );
                expect(column.limits.get('Identity collisions')).toBe(
                    undefined,
                );
                expect(column.limits.get('Share-encryption Ring-LWE')).toBe(
                    undefined,
                );
                const defined = [...column.limits.values()].filter(
                    (limit) => limit !== undefined,
                );
                expect(column.binding.limit).toBe(
                    defined.reduce((least, limit) =>
                        limit < least ? limit : least,
                    ),
                );
                expect(column.limits.get(column.binding.group)).toBe(
                    column.binding.limit,
                );
                // Circular security charges fewer comparisons than the FHE
                // instance at the same floor.
                const circular = column.limits.get(
                    'Evaluation-key circular security',
                );
                expect(circular).toBeDefined();
                expect(circular!).toBeGreaterThanOrEqual(fheLimit);
            }
            expect(row.criterion.binding.group).toBe(
                row.participantCount === 3
                    ? 'ML-DSA authentication'
                    : 'FHE Ring-LWE',
            );
            expect(row.stressTest.binding.group).toBe('FHE Ring-LWE');
            expect(row.criterion.limits.get('Auxiliary Ring-LWE')).toBe(
                undefined,
            );
            expect(
                row.stressTest.limits.get('Auxiliary Ring-LWE'),
            ).toBeGreaterThan(1n << 59n);
        }
        // Only the primal hybrids report finite share-encryption costs, and
        // the one without Babai lifting is the cheapest in both cost models.
        const shareFloor = instanceKnownAttackFloor('share encryption');
        expect(shareFloor.criterion?.attack).toBe('primal hybrid');
        expect(Math.floor(shareFloor.criterion!.log2Cost)).toBe(610);
        expect(shareFloor.stressTest?.attack).toBe('primal hybrid');
        expect(Math.floor(shareFloor.stressTest!.log2Cost)).toBe(593);
        expect(
            Math.floor(
                instanceKnownAttackFloor('auxiliary').criterion!.log2Cost,
            ),
        ).toBe(282);
        // The fixed instances' floors leave every comparison within level
        // at the search cap, so neither has a limit below it there.
        for (const [group, floors] of [
            ['Share-encryption Ring-LWE', ['criterion', 'stressTest']],
            ['Auxiliary Ring-LWE', ['criterion']],
        ] as const)
            for (const floor of floors)
                for (const profile of sampleProfiles) {
                    const screen = latticeGroupFloors(
                        group,
                        BigInt(profile.ciphertext.bits),
                    )[floor];
                    expect(screen).toBeDefined();
                    expect(
                        latticeRequirementAt(
                            group,
                            profile,
                            populationSearchCap,
                        ).requiredBits,
                    ).toBeLessThanOrEqual(supportedLevelBits(screen!));
                }
    });

    it('solves for the circular-security limit within its own level', () => {
        const group = 'Evaluation-key circular security';
        for (const row of compileLatticePopulationLimits(group))
            for (const floor of ['criterion', 'stressTest'] as const) {
                const limit = row[floor];
                expect(limit).toBeDefined();
                const binding = deriveSupportedProfile(
                    row.participantCount,
                    limit!.optionCount,
                );
                expect(
                    latticeRequirementAt(
                        group,
                        binding,
                        limit!.honestRegistrations + 1n,
                    ).requiredBits,
                ).toBeGreaterThan(limit!.levelBits);
                // Every option count stays within its own level.
                for (const profile of profiles.filter(
                    (value) => value.participantCount === row.participantCount,
                )) {
                    const screen = latticeGroupFloors(
                        group,
                        BigInt(profile.ciphertext.bits),
                    )[floor];
                    expect(
                        latticeRequirementAt(
                            group,
                            profile,
                            limit!.honestRegistrations,
                        ).requiredBits,
                    ).toBeLessThanOrEqual(supportedLevelBits(screen!));
                }
            }
    });

    it('prices record creation within every lattice level at the poll limit', () => {
        const decisiveExperiment =
            (largestExperiment / permutationCharge) * permutationCharge;
        // Every proof role commits its oracles over the 2^16 systematic
        // coordinates of the ring degree.
        const systematicSize = 1n << 16n;
        const pricing = compileRecordCreationPricing();
        expect(pricing.map((row) => row.participantCount)).toEqual(
            ledger.map((row) => row.participantCount),
        );
        for (const row of pricing) {
            const ledgerRow = ledger.find(
                (value) => value.participantCount === row.participantCount,
            )!;
            expect(row.honestRegistrations).toBe(
                ledgerRow.criterion.binding.limit,
            );
            const rosterProfiles = profiles.filter(
                (value) => value.participantCount === row.participantCount,
            );
            // The allowance is the least unpriced work of any lattice group
            // with a criterion floor, over every option count.
            const allowances = rosterProfiles.flatMap((profile) =>
                latticeAssumptionGroups.flatMap((group) => {
                    const screen = latticeGroupFloors(
                        group,
                        BigInt(profile.ciphertext.bits),
                    ).criterion;
                    if (screen === undefined) return [];
                    const at = latticeRequirementAt(
                        group,
                        profile,
                        row.honestRegistrations,
                    );
                    return [
                        unpricedWorkAllowance(
                            at.comparisons,
                            at.reductionGates,
                            supportedLevelBits(screen),
                        ),
                    ];
                }),
            );
            expect(allowances.length).toBeGreaterThan(0);
            expect(row.allowance).toBe(
                allowances.reduce((least, value) =>
                    value < least ? value : least,
                ),
            );
            const permutations = rosterProfiles.flatMap((profile) =>
                proofHashProfiles(profile).map(
                    (hashProfile) =>
                        compileProofHashWork(profile, hashProfile)
                            .proverHashSubtotal.permutations,
                ),
            );
            expect(row.leastProverPermutations).toBe(
                permutations.reduce((least, value) =>
                    value < least ? value : least,
                ),
            );
            const dummyEntries = rosterProfiles.flatMap((profile) =>
                compileProofRoundErrorCensus(profile).roles.map(
                    (role) => BigInt(role.originalOracles) * systematicSize,
                ),
            );
            expect(row.largestDummyEntries).toBe(
                dummyEntries.reduce((largest, value) =>
                    value > largest ? value : largest,
                ),
            );
            // The decisive experiment holds at most one honest proof per
            // prover's permutation charges. Their added work fits within the
            // allowance, and one more gate per proof would not.
            const proofCharge = permutationCharge * row.leastProverPermutations;
            const proofs = decisiveExperiment / proofCharge;
            expect(proofs * row.workPerProof).toBeLessThanOrEqual(
                row.allowance,
            );
            expect(
                (row.workPerProof + 1n) * decisiveExperiment,
            ).toBeGreaterThan(proofCharge * row.allowance);
            expect(
                row.workPerEntry * row.largestDummyEntries,
            ).toBeLessThanOrEqual(row.workPerProof);
            // Each dummy entry adds a few field operations, far below this.
            expect(row.workPerEntry).toBeGreaterThan(1n << 64n);
        }
    });
});
