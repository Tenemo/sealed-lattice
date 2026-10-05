import { describe, expect, it } from 'vitest';

import {
    compileCommonMatrixInitializationCensus,
    compileCommonMatrixSamplingCensus,
} from '#tests/common-matrix-sampling-model.js';
import {
    acceptedProofRolesAt,
    compileComposedSecurityLedger,
    compileReductionWork,
    compileUnitCallCostSensitivity,
    computationalHybrids,
    fheCommonStreamGuesses,
    keccakReferenceCost,
    ledgerBudgetBits,
    minimumHonestRosterMembers,
    profileStatisticalTerms,
    rational,
    reductionRatioAt,
    requiredAssumptionBits,
    rosterCountAt,
    securityTargetBits,
    signatureCategoryBits,
    signatureReductionFactor,
    soundnessHops,
    sparseRoutingCoefficients,
    supportedParticipantCounts,
} from '#tests/composed-security-ledger-model.js';
import { sparseRoutingWork } from '#tests/compressed-oracle-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    deriveSupportedProfile,
    deriveSupportedShareLifting,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';
import {
    compileWideChallengeCompilerCensus,
    proofCompilerCaps,
} from '#tests/wide-challenge-compiler-model.js';

// Only the first max(f + 1, 2) roster positions contribute setup key
// material, with f = floor((n - 1) / 3).
const setupContributors = (participantCount: number) =>
    Math.max(Math.floor((participantCount - 1) / 3) + 1, 2);

const ledger = compileComposedSecurityLedger();
const target = 1n << securityTargetBits;

// FIPS 202: SHAKE128 is KECCAK[256] and SHAKE256 is KECCAK[512] over
// Keccak-f[1600], whose 24 rounds each apply chi to every state bit.
const fips202 = {
    rounds: 24n,
    shake128RateBits: 1344n,
    shake256RateBits: 1088n,
};

type Call = Readonly<{ inputBits: bigint; outputBits: bigint }>;

// Permutations of one SHAKE128 evaluation, the widest-rate SHAKE function.
const permutations = ({ inputBits, outputBits }: Call) => {
    const rate = fips202.shake128RateBits;
    const absorbed = (inputBits + 6n + rate - 1n) / rate;
    const squeezed = (outputBits + rate - 1n) / rate;
    return absorbed + squeezed - 1n;
};

// Exact entry-routing gates of every base call of a schedule, with one sparse
// database per exact call shape, and the schedule's charged cost.
const executeSchedule = (
    calls: readonly Call[],
    charge: (call: Call) => bigint,
) => {
    const cells = new Map<string, { call: Call; entries: bigint }>();
    let routing = 0n;
    let cost = 0n;
    for (const call of calls) {
        for (const cell of cells.values())
            routing +=
                2n *
                4n *
                (sparseRoutingWork(
                    cell.entries,
                    cell.call.inputBits,
                    cell.call.outputBits,
                ).routingGates -
                    sparseRoutingWork(
                        0n,
                        cell.call.inputBits,
                        cell.call.outputBits,
                    ).routingGates);
        const key = `${call.inputBits}:${call.outputBits}`;
        const cell = cells.get(key) ?? { call, entries: 0n };
        cell.entries += 1n;
        cells.set(key, cell);
        cost += charge(call);
    }
    return { routing, cost };
};

const repeat = (count: number, call: Call) =>
    Array.from({ length: count }, () => call);

const hostileSchedules: Readonly<Record<string, readonly Call[]>> = {
    'narrow calls': repeat(3000, { inputBits: 256n, outputBits: 512n }),
    'wide entries then minimal calls': [
        ...repeat(8, { inputBits: 1n << 22n, outputBits: 512n }),
        ...repeat(3000, { inputBits: 1n, outputBits: 1n }),
    ],
    'long outputs then minimal calls': [
        ...repeat(8, { inputBits: 1n, outputBits: 1n << 20n }),
        ...repeat(3000, { inputBits: 1n, outputBits: 1n }),
    ],
    'full-rate calls': repeat(2000, {
        inputBits: fips202.shake128RateBits - 6n,
        outputBits: fips202.shake128RateBits,
    }),
};

describe('composed security ledger', () => {
    it('charges every oracle call its FIPS 202 permutations', () => {
        expect(keccakReferenceCost.rounds).toBe(fips202.rounds);
        expect(keccakReferenceCost.widestRateBits).toBe(
            fips202.shake128RateBits,
        );
        expect(fips202.shake256RateBits).toBeLessThan(
            keccakReferenceCost.widestRateBits,
        );
        expect(keccakReferenceCost.permutationCharge).toBe(
            1600n * fips202.rounds,
        );
    });

    it('takes routing coefficients from the maintained sparse-oracle circuit', () => {
        // sparseOracleQuerySchedule prices the prior-query slope as
        // 2*(c0 + c1*in + c2*out) for uniform widths.
        for (const [inputBits, outputBits] of [
            [1n, 1n],
            [17n, 512n],
            [4096n, 3n],
        ] as const) {
            const slope =
                sparseRoutingWork(5n, inputBits, outputBits).routingGates -
                sparseRoutingWork(4n, inputBits, outputBits).routingGates;
            expect(slope).toBe(
                sparseRoutingCoefficients.entryConstant +
                    sparseRoutingCoefficients.entryPerInputBit * inputBits +
                    sparseRoutingCoefficients.entryPerOutputBit * outputBits,
            );
            const work = compileReductionWork(20n, 0n);
            expect(
                work.perStoredBit * (inputBits + outputBits + 1n) +
                    work.entryExcess,
            ).toBeGreaterThanOrEqual(slope);
        }
    });

    it('bounds the extraction routing of hostile call schedules', () => {
        const work = compileReductionWork(20n, 120n);
        const charge = (call: Call) =>
            permutations(call) * keccakReferenceCost.permutationCharge;
        for (const [name, calls] of Object.entries(hostileSchedules)) {
            const { routing, cost } = executeSchedule(calls, charge);
            const bound =
                (work.quadraticCoefficient.numerator * cost * cost) /
                work.quadraticCoefficient.denominator;
            expect(routing, name).toBeLessThanOrEqual(bound);
        }
        // Charging one gate per call lets cheap calls route over wide
        // entries, so the same schedule exceeds the reference-charge bound.
        const unit = executeSchedule(
            hostileSchedules['wide entries then minimal calls'],
            () => 1n,
        );
        expect(unit.routing).toBeGreaterThan(
            (work.quadraticCoefficient.numerator * unit.cost * unit.cost) /
                work.quadraticCoefficient.denominator,
        );
    });

    it('derives each requirement at its worst experiment cost', () => {
        for (const participantCount of [3, 10, 20]) {
            const profile = ledger.profiles.find(
                (row) => row.participantCount === participantCount,
            );
            expect(profile).toBeDefined();
            const work = compileReductionWork(
                BigInt(participantCount),
                profile!.extractedCommitmentCount,
            );
            for (const row of profile!.hybrids) {
                // Every T = 2^k from one gate to the target must satisfy
                // multiplicity*Tred(T)/T <= 2^(lambda-80-budget).
                let worst = rational(0n);
                for (
                    let exponent = 0n;
                    exponent <= securityTargetBits;
                    exponent++
                ) {
                    const ratio = reductionRatioAt(
                        work,
                        row.reduction,
                        1n << exponent,
                    );
                    if (
                        ratio.numerator * worst.denominator >
                        worst.numerator * ratio.denominator
                    )
                        worst = ratio;
                }
                const scaled = rational(
                    worst.numerator *
                        row.multiplicity *
                        row.guesses *
                        (1n << (securityTargetBits + ledgerBudgetBits)),
                    worst.denominator,
                );
                expect(scaled.numerator).toBeLessThanOrEqual(
                    scaled.denominator << row.requiredBits,
                );
                expect(scaled.numerator).toBeGreaterThan(
                    scaled.denominator << (row.requiredBits - 1n),
                );
            }
        }
    });

    it('counts hybrid multiplicities from the honest roles', () => {
        for (const [participantCount, extraRegistrations, rosterCount] of [
            ...supportedParticipantCounts.map(
                (count) => [count, 0, 1] as const,
            ),
            [3, 2, 1],
            [20, 7, 1],
            [3, 1, 3],
            [10, 4, 2],
        ] as const) {
            // A corrupt organizer can complete disjoint rosters. The honest
            // setup contributors of each can contribute, and all of its
            // honest participants can receive shares and vote.
            const contributors = setupContributors(participantCount);
            const rosters = Array.from(
                { length: rosterCount },
                (_unused, roster) =>
                    Array.from(
                        { length: participantCount },
                        (_member, index) => roster * participantCount + index,
                    ),
            );
            const honest = rosters.flat();
            // Registrations no roster takes publish keys too, but no share is
            // encrypted to them.
            const registrations = Array.from(
                { length: honest.length + extraRegistrations },
                (_unused, index) => index,
            );
            // Each step replaces one assumption instance. A ciphertext moves
            // to uniform and then to its replacement; a key that must end
            // good leaves for uniform and returns.
            const replaceCiphertext = (label: string) => [
                `${label} to uniform`,
                `${label} to replacement`,
            ];
            const steps = new Map<string, readonly string[]>([
                [
                    'Share-encryption Ring-LWE:plain',
                    registrations.flatMap((registration) => [
                        `registration key ${registration} out`,
                        ...(registration < honest.length
                            ? rosters[
                                  Math.floor(registration / participantCount)
                              ]
                                  .slice(0, contributors)
                                  .flatMap((contributor) =>
                                      replaceCiphertext(
                                          `share ${contributor} to ${registration}`,
                                      ),
                                  )
                            : []),
                        `registration key ${registration} back`,
                    ]),
                ],
                [
                    'Auxiliary Ring-LWE:plain',
                    rosters.flatMap((members) =>
                        members
                            .slice(0, contributors)
                            .map((contributor) => `coordinate ${contributor}`),
                    ),
                ],
                [
                    'Auxiliary Ring-LWE:extraction',
                    rosters.flatMap((members, roster) => [
                        `roster ${roster} uniform aggregate to good key`,
                        `roster ${roster} aggregate out`,
                        ...members.flatMap((voter) =>
                            replaceCiphertext(`auxiliary ballot ${voter}`),
                        ),
                        `roster ${roster} aggregate back`,
                    ]),
                ],
                [
                    'Evaluation-key circular security:extraction',
                    rosters.flatMap((members) =>
                        members
                            .slice(0, contributors)
                            .map((contributor) => `tuple ${contributor}`),
                    ),
                ],
                [
                    'FHE Ring-LWE:extraction',
                    rosters.flatMap((members, roster) => [
                        ...members.flatMap((voter) =>
                            replaceCiphertext(`FHE ballot ${voter}`),
                        ),
                        `roster ${roster} uniform aggregate to good key`,
                    ]),
                ],
            ]);
            const rows = computationalHybrids(
                BigInt(participantCount),
                BigInt(registrations.length),
                BigInt(rosterCount),
            );
            expect(rows).toHaveLength(steps.size);
            for (const row of rows) {
                const rowSteps = steps.get(
                    `${row.assumption}:${row.reduction}`,
                )!;
                expect(new Set(rowSteps).size).toBe(rowSteps.length);
                expect(row.multiplicity).toBe(BigInt(rowSteps.length));
            }
        }
    });

    it('guesses the ciphertext modulus only where a challenge enters the shared FHE common streams', () => {
        // One modulus of each supported length, the largest of its prime
        // form: 576 to 960 bits in steps of 32.
        const lengths = new Set(
            listSupportedProfiles().map(
                (profile) => profile.ciphertext.modulus.toString(2).length,
            ),
        );
        expect(fheCommonStreamGuesses()).toBe(BigInt(lengths.size));
        expect(fheCommonStreamGuesses()).toBe(13n);
        for (const row of computationalHybrids(10n))
            expect(row.guesses).toBe(
                row.assumption === 'FHE Ring-LWE' ||
                    row.assumption === 'Evaluation-key circular security'
                    ? 13n
                    : 1n,
            );
        // Each of the 2n+d+1 guessing steps, with n = 8 and d = 3, loses
        // twice the complete programming distance per guess, rounded up to a
        // multiple of 2^-256.
        const profile = deriveSupportedProfile(8, 18);
        const matrices = compileCommonMatrixSamplingCensus(profile);
        const initialization = compileCommonMatrixInitializationCensus(profile);
        const exactNumerator =
            2n *
            13n *
            20n *
            (matrices.distanceUpperNumerator * initialization.biasDenominator +
                initialization.biasNumerator *
                    matrices.distanceUpperDenominator);
        const exactDenominator =
            matrices.distanceUpperDenominator * initialization.biasDenominator;
        const term = profileStatisticalTerms(profile).find(
            (value) =>
                value.name ===
                'FHE common-stream programming per guessing reduction',
        )!;
        expect(term.numerator * exactDenominator).toBeGreaterThanOrEqual(
            exactNumerator << 256n,
        );
        expect((term.numerator - 1n) * exactDenominator).toBeLessThan(
            exactNumerator << 256n,
        );
    });

    it('keeps the statistical subtotal within its share of the budget', () => {
        expect(ledger.budgetBits).toBe(ledgerBudgetBits);
        expect(1n << ledgerBudgetBits).toBeGreaterThanOrEqual(
            BigInt(ledger.groups.length),
        );
        const subtotal = ledger.statistical.terms.reduce(
            (sum, term) => sum + term.numerator,
            0n,
        );
        expect(subtotal).toBe(ledger.statistical.subtotalNumerator);
        expect(
            subtotal << (securityTargetBits + ledgerBudgetBits),
        ).toBeLessThanOrEqual(1n << ledger.statistical.denominatorBits);
        // The sharing translation meets the statistical target for every
        // supported roster; every setup contributor shares its own secret.
        const secretOneNorm = 2n * fixedModulusBfvInputs.secretSupportWeight;
        for (const participantCount of supportedParticipantCounts) {
            const degree =
                compileThresholdCompletionProfile(participantCount)
                    .resultReleaseThreshold - 1;
            const lifting = deriveSupportedShareLifting(participantCount);
            const numerator =
                BigInt(setupContributors(participantCount)) *
                ((1n << BigInt(degree)) - 1n) *
                secretOneNorm;
            expect(lifting.privacyNumerator).toBe(numerator);
            expect(
                numerator << BigInt(fixedModulusBfvInputs.statisticalBits),
            ).toBeLessThanOrEqual(2n * lifting.sharingRadius);
        }
    });

    it('charges every sparse sampler call its cap-exhaustion bound', () => {
        // A balanced sparse sampler of support s over degree d fails its
        // draw cap of 2s with probability at most (4(s-1)/d)^s. Every setup
        // contributor draws one fresh FHE auxiliary secret and one ephemeral
        // per recipient; every participant draws one FHE and one
        // auxiliary ballot ephemeral; every registration one recipient
        // secret.
        const bound = (degree: bigint, support: bigint) => ({
            numerator: (4n * (support - 1n)) ** support,
            denominator: degree ** support,
        });
        const unitsAbove = (
            rows: readonly Readonly<{
                calls: bigint;
                numerator: bigint;
                denominator: bigint;
            }>[],
        ) => {
            // The smallest multiple of 2^-256 at or above the exact sum.
            let numerator = 0n;
            let denominator = 1n;
            for (const row of rows) {
                numerator =
                    numerator * row.denominator +
                    row.calls * row.numerator * denominator;
                denominator *= row.denominator;
            }
            return ((numerator << 256n) + denominator - 1n) / denominator;
        };
        for (const [participantCount, optionCount] of [
            [3, 2],
            [20, 20],
        ] as const) {
            const participants = BigInt(participantCount);
            const contributors = BigInt(setupContributors(participantCount));
            const eligible =
                contributors + BigInt(Math.floor((participantCount - 1) / 3));
            const expected = unitsAbove([
                { calls: eligible, ...bound(65_536n, 1_024n) },
                {
                    calls: eligible * participants,
                    ...bound(65_536n, 256n),
                },
            ]);
            const term = profileStatisticalTerms(
                deriveSupportedProfile(participantCount, optionCount),
            ).find(
                (value) =>
                    value.name === 'Contribution sparse-support cap exhaustion',
            )!;
            expect(term.numerator).toBe(expected);
            expect(term.numerator).toBeGreaterThan(0n);
            const ballot = profileStatisticalTerms(
                deriveSupportedProfile(participantCount, optionCount),
            ).find(
                (value) =>
                    value.name === 'Ballot sparse-support cap exhaustion',
            )!;
            expect(ballot.numerator).toBe(
                unitsAbove([
                    { calls: participants, ...bound(65_536n, 1_024n) },
                    { calls: participants, ...bound(4_096n, 256n) },
                ]),
            );
            expect(ballot.numerator).toBeGreaterThan(0n);
        }
        const population = ledger.maximumCredentialPopulation;
        const registration = compileComposedSecurityLedger(
            population,
        ).statistical.terms.find(
            (value) =>
                value.name === 'Registration sparse-support cap exhaustion',
        )!;
        expect(registration.numerator).toBe(
            unitsAbove([{ calls: population, ...bound(65_536n, 256n) }]),
        );
    });

    it('charges the seeded operation randomness its one-way-to-hiding bound', () => {
        // Two 512-bit seeds per eligible contributor and two per participant,
        // and 2^80 oracle calls in any experiment within the target:
        // 2*sqrt((q+1)*4q*m/2^512) is at most 4(q+1)*ceil(sqrt(m))/2^256.
        const calls = 1n << 80n;
        for (const [participantCount, optionCount, root] of [
            [3, 2, 4n],
            [10, 10, 6n],
            [20, 20, 9n],
        ] as const) {
            const seeds =
                2n *
                    BigInt(
                        setupContributors(participantCount) +
                            Math.floor((participantCount - 1) / 3),
                    ) +
                2n * BigInt(participantCount);
            expect(root * root).toBeGreaterThanOrEqual(seeds);
            expect((root - 1n) * (root - 1n)).toBeLessThan(seeds);
            const term = profileStatisticalTerms(
                deriveSupportedProfile(participantCount, optionCount),
            ).find((value) => value.name === 'Operation seed expansion')!;
            expect(term.numerator).toBe(4n * (calls + 1n) * root);
            // Squared and scaled by 2^512, the exact bound 16(q+1)qm is at
            // most the charged term squared.
            expect(16n * (calls + 1n) * calls * seeds).toBeLessThanOrEqual(
                term.numerator * term.numerator,
            );
        }
    });

    it('charges the seeded Merkle salts their one-way-to-hiding bound', () => {
        // Three oracle trees and sixteen folded layers' trees, each with a
        // 512-bit seed, for each of the 2^28 honest proofs the compiler
        // allows, and 2^80 oracle calls in any experiment within the target.
        const calls = 1n << 80n;
        const seeds = 19n << 28n;
        // 71417^2 = 5,100,387,889 and 71416^2 = 5,100,245,056 bracket
        // 19 * 2^28 = 5,100,273,664.
        const root = 71_417n;
        expect(root * root).toBeGreaterThanOrEqual(seeds);
        expect((root - 1n) * (root - 1n)).toBeLessThan(seeds);
        for (const [participantCount, optionCount] of [
            [3, 2],
            [10, 10],
            [20, 20],
        ] as const) {
            const term = profileStatisticalTerms(
                deriveSupportedProfile(participantCount, optionCount),
            ).find((value) => value.name === 'Merkle salt seed expansion')!;
            expect(term.numerator).toBe(4n * (calls + 1n) * root);
            expect(16n * (calls + 1n) * calls * seeds).toBeLessThanOrEqual(
                term.numerator * term.numerator,
            );
        }
    });

    it('charges proof soundness at every hop that relies on it', () => {
        for (const participantCount of [3, 10, 20]) {
            const honest = Array.from(
                { length: participantCount },
                (_unused, index) => index,
            );
            // Hops whose identity holds only for true corrupt statements.
            const hops = [
                'released output',
                ...honest.flatMap((recipient) => [
                    `recovery without recipient ${recipient}`,
                    `recovery with recipient ${recipient}`,
                ]),
                'recovery to the auxiliary key',
                'recovery to the FHE literal tail',
                'recovery back to the auxiliary key',
                'terminal output',
            ];
            expect(soundnessHops(BigInt(participantCount))).toBe(
                BigInt(hops.length),
            );
            const profile = deriveSupportedProfile(participantCount, 10);
            const compiler = compileWideChallengeCompilerCensus(profile);
            const exactNumerator =
                BigInt(hops.length) * compiler.failureNumerator;
            const term = profileStatisticalTerms(profile).find(
                (value) => value.name === 'Wide-message proof soundness',
            )!;
            expect(
                term.numerator * compiler.failureDenominator,
            ).toBeGreaterThanOrEqual(exactNumerator << 256n);
            expect(
                (term.numerator - 1n) * compiler.failureDenominator,
            ).toBeLessThan(exactNumerator << 256n);
        }
    });

    it('charges each credential-independent term at its largest supported profile', () => {
        const rosterTerms = new Set([
            'Honest-body equivocation',
            'Honest signing credential collision',
            'Registration sparse-support cap exhaustion',
        ]);
        const charged = ledger.statistical.terms.filter(
            (term) => !rosterTerms.has(term.name),
        );
        for (const [participantCount, optionCount] of [
            [3, 2],
            [10, 10],
            [20, 20],
        ]) {
            const terms = profileStatisticalTerms(
                deriveSupportedProfile(participantCount, optionCount),
            );
            expect(terms.map((term) => term.name)).toEqual(
                charged.map((term) => term.name),
            );
            terms.forEach((term, index) =>
                expect(term.numerator).toBeLessThanOrEqual(
                    charged[index].numerator,
                ),
            );
        }
        for (const term of charged) {
            if (term.largestAt === undefined) continue;
            const { participantCount, optionCount } = term.largestAt;
            expect(optionCount).toBeDefined();
            const attained = profileStatisticalTerms(
                deriveSupportedProfile(participantCount, optionCount!),
            ).find((value) => value.name === term.name);
            expect(attained?.numerator).toBe(term.numerator);
        }
    });

    it('bounds the rosters and proof roles of every split of the honest registrations', () => {
        // Each roster that reaches an honest opening has at most f corrupt
        // members and takes n-f honest registrations of its own. The largest
        // number of rosters and of accepted roles over every multiset of
        // supported roster sizes whose honest members fit the registrations.
        const sizes = supportedParticipantCounts.map((participantCount) => ({
            participantCount,
            honestMembers:
                participantCount -
                compileThresholdCompletionProfile(participantCount)
                    .maximumCorruptParticipantCount,
        }));
        const limit = 120;
        const rosters = Array.from({ length: limit + 1 }, () => 0);
        const roles = Array.from({ length: limit + 1 }, () => 0);
        for (let registrations = 1; registrations <= limit; registrations++) {
            rosters[registrations] = rosters[registrations - 1];
            roles[registrations] = roles[registrations - 1];
            for (const { participantCount, honestMembers } of sizes) {
                if (honestMembers > registrations) continue;
                const rest = registrations - honestMembers;
                rosters[registrations] = Math.max(
                    rosters[registrations],
                    rosters[rest] + 1,
                );
                roles[registrations] = Math.max(
                    roles[registrations],
                    roles[rest] +
                        2 * participantCount +
                        setupContributors(participantCount) +
                        Math.floor((participantCount - 1) / 3),
                );
            }
        }
        expect(minimumHonestRosterMembers).toBe(3n);
        let tight = 0;
        for (let registrations = 3; registrations <= limit; registrations++) {
            const count = BigInt(registrations);
            expect(rosterCountAt(count)).toBe(BigInt(rosters[registrations]));
            expect(acceptedProofRolesAt(count)).toBeGreaterThanOrEqual(
                BigInt(roles[registrations]),
            );
            if (acceptedProofRolesAt(count) === BigInt(roles[registrations]))
                tight++;
        }
        // Nineteen participants with six corrupt maximize roles per honest
        // member, and the bound is attained at their multiples.
        expect(tight).toBeGreaterThanOrEqual(Math.floor(limit / 13));
        expect(acceptedProofRolesAt(13n * 7n)).toBe((2n * 19n + 13n) * 7n);
    });

    it('caps the honest credential population by its rosters', () => {
        const population = ledger.maximumCredentialPopulation;
        expect(ledger.maximumRosterCount).toBe(rosterCountAt(population));
        expect(ledger.maximumAcceptedProofRoles).toBe(
            acceptedProofRolesAt(population),
        );
        // The signature group bounds a larger population than the rosters do.
        const signatureHolds = (credentials: bigint) =>
            (credentials * (signatureReductionFactor * target) ** 2n) <<
                (securityTargetBits + ledgerBudgetBits) <=
            target << signatureCategoryBits;
        expect(signatureHolds(ledger.signatureCredentialPopulation)).toBe(true);
        expect(signatureHolds(ledger.signatureCredentialPopulation + 1n)).toBe(
            false,
        );
        expect(population).toBeLessThan(ledger.signatureCredentialPopulation);
        // The per-roster subtotal only grows with the population, so the
        // population's own subtotal bounds the next one from below.
        const subtotal =
            compileComposedSecurityLedger(population).statistical
                .subtotalNumerator;
        const charged = (credentials: bigint) =>
            (rosterCountAt(credentials) * subtotal) <<
            (securityTargetBits + ledgerBudgetBits);
        const withinClaim = (credentials: bigint) =>
            charged(credentials) <= 1n << 256n &&
            acceptedProofRolesAt(credentials) <= proofCompilerCaps.roleBudget &&
            4n * credentials <= proofCompilerCaps.honestProofBudget;
        expect(withinClaim(population)).toBe(true);
        expect(withinClaim(population + 1n)).toBe(false);
        // The charged statistical terms and every requirement grow with the
        // rosters of that population.
        const large = compileComposedSecurityLedger(population);
        expect(large.statistical.rosterCount).toBe(ledger.maximumRosterCount);
        expect(large.statistical.chargedNumerator).toBe(
            ledger.maximumRosterCount * large.statistical.subtotalNumerator,
        );
        expect(large.statistical.chargedExponent).toBeLessThanOrEqual(
            -(securityTargetBits + ledgerBudgetBits),
        );
        for (const row of large.maximumRequiredBits)
            expect(row.requiredBits).toBeGreaterThan(
                ledger.maximumRequiredBits.find(
                    (value) => value.assumption === row.assumption,
                )!.requiredBits,
            );
        expect(() => compileComposedSecurityLedger(population + 1n)).toThrow(
            'The population lies outside the claim.',
        );
    });

    it('makes the reference call charge load-bearing', () => {
        const sensitivity = compileUnitCallCostSensitivity();
        const referenceFhe = ledger.maximumRequiredBits.find(
            (row) => row.assumption === 'FHE Ring-LWE',
        )!.requiredBits;
        expect(sensitivity.requiredBits).toBeGreaterThan(referenceFhe + 40n);
        // A reduction as fast as the experiment needs only the budget.
        expect(requiredAssumptionBits(1n, 1n, rational(1n))).toBe(
            securityTargetBits + ledgerBudgetBits,
        );
        expect(ledger.identityCollisionExponent).toBeLessThanOrEqual(
            -(securityTargetBits + ledgerBudgetBits),
        );
    });

    it('refuses populations and counts outside the model', () => {
        expect(() => compileReductionWork(0n, 0n)).toThrow();
        expect(() => compileReductionWork(1n, -1n)).toThrow();
        expect(() => compileComposedSecurityLedger(19n)).toThrow(
            'The population lies outside the claim.',
        );
    });
});
