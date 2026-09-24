import { describe, expect, it } from 'vitest';

import {
    compileComposedSecurityLedger,
    compileReductionWork,
    compileUnitCallCostSensitivity,
    computationalHybrids,
    keccakReferenceCost,
    ledgerBudgetBits,
    rational,
    reductionRatioAt,
    requiredAssumptionBits,
    securityTargetBits,
    signatureCategoryBits,
    signatureReductionFactor,
    sparseRoutingCoefficients,
    supportedParticipantCounts,
} from '#tests/composed-security-ledger-model.js';
import { sparseRoutingWork } from '#tests/compressed-oracle-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { deriveSupportedShareLifting } from '#tests/supported-profile-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

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
        for (const participantCount of supportedParticipantCounts) {
            const honest = Array.from(
                { length: participantCount },
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
                    honest.flatMap((recipient) => [
                        `recipient key ${recipient} out`,
                        ...honest.flatMap((contributor) =>
                            replaceCiphertext(
                                `share ${contributor} to ${recipient}`,
                            ),
                        ),
                        `recipient key ${recipient} back`,
                    ]),
                ],
                [
                    'Auxiliary Ring-LWE:plain',
                    honest.map((participant) => `coordinate ${participant}`),
                ],
                [
                    'Auxiliary Ring-LWE:extraction',
                    [
                        'uniform aggregate to good key',
                        'aggregate out',
                        ...honest.flatMap((voter) =>
                            replaceCiphertext(`auxiliary ballot ${voter}`),
                        ),
                        'aggregate back',
                    ],
                ],
                [
                    'Evaluation-key circular security:extraction',
                    honest.map((participant) => `tuple ${participant}`),
                ],
                [
                    'FHE Ring-LWE:extraction',
                    [
                        ...honest.flatMap((voter) =>
                            replaceCiphertext(`FHE ballot ${voter}`),
                        ),
                        'uniform aggregate to good key',
                    ],
                ],
            ]);
            const rows = computationalHybrids(BigInt(participantCount));
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
        // supported roster, not only the ten-participant term above.
        const secretOneNorm = 2n * fixedModulusBfvInputs.secretSupportWeight;
        for (const participantCount of supportedParticipantCounts) {
            const degree =
                compileThresholdCompletionProfile(participantCount)
                    .resultReleaseThreshold - 1;
            const lifting = deriveSupportedShareLifting(participantCount);
            const numerator =
                BigInt(participantCount) *
                ((1n << BigInt(degree)) - 1n) *
                secretOneNorm;
            expect(lifting.privacyNumerator).toBe(numerator);
            expect(
                numerator << BigInt(fixedModulusBfvInputs.statisticalBits),
            ).toBeLessThanOrEqual(2n * lifting.sharingRadius);
        }
    });

    it('caps the honest credential population by the signature term', () => {
        const population = ledger.maximumCredentialPopulation;
        const holds = (credentials: bigint) =>
            (credentials * (signatureReductionFactor * target) ** 2n) <<
                (securityTargetBits + ledgerBudgetBits) <=
            target << signatureCategoryBits;
        expect(holds(population)).toBe(true);
        expect(holds(population + 1n)).toBe(false);
        // The statistical and plain terms stay within budget at that population.
        const large = compileComposedSecurityLedger(population);
        expect(large.statistical.subtotalExponent).toBeLessThanOrEqual(
            -(securityTargetBits + ledgerBudgetBits),
        );
        for (const row of large.maximumRequiredBits)
            expect(row.requiredBits).toBeGreaterThanOrEqual(
                ledger.maximumRequiredBits.find(
                    (value) => value.assumption === row.assumption,
                )!.requiredBits,
            );
    });

    it('makes the reference call charge load-bearing', () => {
        const sensitivity = compileUnitCallCostSensitivity();
        const referenceFhe = ledger.maximumRequiredBits.find(
            (row) => row.assumption === 'FHE Ring-LWE',
        )!.requiredBits;
        expect(sensitivity.requiredBits).toBeGreaterThan(referenceFhe + 40n);
        // A reduction as fast as the experiment needs only the budget.
        expect(requiredAssumptionBits(1n, rational(1n))).toBe(
            securityTargetBits + ledgerBudgetBits,
        );
        expect(ledger.identityCollisionExponent).toBeLessThanOrEqual(
            -(securityTargetBits + ledgerBudgetBits),
        );
    });

    it('refuses populations and counts outside the model', () => {
        expect(() => compileReductionWork(0n, 0n)).toThrow();
        expect(() => compileReductionWork(1n, -1n)).toThrow();
        expect(() => compileComposedSecurityLedger(19n)).toThrow();
    });
});
