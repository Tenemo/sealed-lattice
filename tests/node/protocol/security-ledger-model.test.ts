import { describe, expect, it } from 'vitest';

import {
    ballotEnvelopeBytes,
    compileBallotBodyCensus,
} from '#tests/ballot-body-model.js';
import { candidateTransportParameters } from '#tests/candidate-publication-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { sourceCiphertextBytes } from '#tests/encrypted-registration-source-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import {
    compileBallotWordProofLayout,
    compileFullWordProofLayout,
    compileLinkedReleaseWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import {
    readRustSource,
    rustIntegerConstant,
} from '#tests/node/rust-source.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import {
    compileParticipantReleaseCustody,
    participantReleaseEnvelopeBytes,
} from '#tests/participant-release-custody-model.js';
import { purposeSignatureBytes } from '#tests/purpose-signature-model.js';
import {
    addRationals,
    atMost,
    ceilingSquareRoot,
    rational,
    rationalCeilingLog2,
} from '#tests/security-ledger/rational.js';
import {
    compileErrorEnvelope,
    compileErrorGroups,
    compileSecurityLedger,
    compileSecurityOperands,
    ledgerGroupBudget,
    ledgerGroups,
    securityProofEnvelope,
    validatePricedRoleShape,
} from '#tests/security-ledger-model.js';
import { reductionConstructorOperands } from '#tests/security-margin/constructor-operands.js';
import {
    callerPassPayloadBits,
    reductionDescriptorGeometry,
} from '#tests/security-margin/constructor-price.js';
import {
    maximumExperimentGates,
    minimumReductionWork,
} from '#tests/security-margin/reduction-work.js';
import { setupAggregateChunkBytes } from '#tests/setup-aggregate-resource-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import { listSupportedProfiles } from '#tests/supported-profile-model.js';

describe('full128-bit composition ledger', () => {
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
        expect(() => ceilingSquareRoot(-1n)).toThrow();
        expect(rationalCeilingLog2(rational(1n))).toBe(0n);
        expect(rationalCeilingLog2(rational(1n, 2n))).toBe(-1n);
        expect(rationalCeilingLog2(rational(1n, 3n))).toBe(-1n);
        expect(rationalCeilingLog2(rational(3n, 2n))).toBe(1n);
        expect(rationalCeilingLog2(rational(1n, 1n << 300n))).toBe(-300n);
        expect(
            rationalCeilingLog2(rational((1n << 300n) + 1n, 1n << 300n)),
        ).toBe(1n);
        expect(() => rationalCeilingLog2(rational(0n))).toThrow();
        expect(() => rational(1n, 0n)).toThrow();
        expect(() => rational(-1n)).toThrow();
    });
    it('rejects any role that exceeds a separately priced constructor dimension', () => {
        const boundary = {
            columns: securityProofEnvelope.columns,
            lookups: securityProofEnvelope.lookups,
            oracles: securityProofEnvelope.oracles,
            affineRows: 1n << 32n,
        };
        expect(() => validatePricedRoleShape(boundary)).not.toThrow();
        for (const key of Object.keys(boundary) as (keyof typeof boundary)[])
            expect(() =>
                validatePricedRoleShape({
                    ...boundary,
                    [key]: boundary[key] + 1n,
                }),
            ).toThrow();
        for (const key of ['columns', 'oracles'] as const)
            expect(() =>
                validatePricedRoleShape({ ...boundary, [key]: 0n }),
            ).toThrow();
    });
    it('allocates the whole target once and preserves all explicit sampler terms', () => {
        const budget = addRationals(...ledgerGroups.map(ledgerGroupBudget));
        expect(budget.numerator).toBe(budget.denominator);
        const operands = compileSecurityOperands();
        expect(operands.queries).toBe(704n);
        expect(
            securityProofEnvelope.programmedPrefixBits,
        ).toBeGreaterThanOrEqual(8n * 1048576n);
        expect(operands.maximumSourceFamilies).toBeGreaterThan(1n);
        expect(atMost(operands.sharingRatio, rational(5n, 8n))).toBe(true);
        expect(atMost(operands.releaseRatio, rational(1n, 8n))).toBe(true);
    }, 60000);
    it('satisfies every chronological endpoint and representative interior work', () => {
        const rows = compileSecurityLedger();
        const population = rows.reduce(
            (minimum, row) =>
                row.criterion.binding.limit < minimum
                    ? row.criterion.binding.limit
                    : minimum,
            rows[0].criterion.binding.limit,
        );
        // The owner accepted this suite's limit of 37 original honest
        // registrations; a model change that lowers it returns to the owner.
        expect(population).toBeGreaterThanOrEqual(37n);
        for (const row of rows)
            expect(row.stressTest.binding.limit).toBeLessThanOrEqual(
                row.criterion.binding.limit,
            );
        for (const original of [1n, 20n, population]) {
            const checks = [
                ...compileErrorEnvelope(original),
                ...[1n << 64n, 1n << 96n].map((work) => ({
                    work,
                    ...compileErrorGroups(original, work),
                })),
            ];
            for (const check of checks) {
                const target = rational(check.work, 1n << 128n);
                for (const [group, value] of [
                    ['Purpose authentication', check.authentication],
                    ['Identity collisions', check.identity],
                    ['Statistical terms', check.statistical],
                ] as const) {
                    const allocation = ledgerGroupBudget(group);
                    expect(
                        atMost(
                            value,
                            rational(
                                target.numerator * allocation.numerator,
                                target.denominator * allocation.denominator,
                            ),
                        ),
                    ).toBe(true);
                }
            }
            for (const check of checks.filter(
                (value) => value.work < minimumReductionWork,
            ))
                expect(check.statistical.numerator).toBe(0n);
        }
        expect(() => compileErrorGroups(0n, 1n)).toThrow();
        expect(() =>
            compileErrorGroups(1n, maximumExperimentGates + 1n),
        ).toThrow();
    }, 60000);
    it('keeps every payload class within one caller pass', async () => {
        const fits = (label: string, bits: bigint) =>
            expect(bits, label).toBeLessThanOrEqual(callerPassPayloadBits);
        // A descriptor's serialized input and proof, and every statement and
        // recovery program's input and output.
        fits('descriptor input', reductionDescriptorGeometry.inputBits);
        fits('descriptor proof', reductionDescriptorGeometry.proofBits);
        for (const row of reductionConstructorOperands.statements) {
            fits(`${row.name} statement input`, row.inputBits);
            fits(`${row.name} statement output`, row.outputBits);
        }
        for (const [name, row] of Object.entries(
            reductionConstructorOperands.recovery,
        )) {
            fits(`${name} recovery input`, row.inputBits);
            fits(`${name} recovery output`, row.outputBits);
        }
        // Source ciphertexts, signatures, envelopes and the native and
        // stored chunks.
        fits('source ciphertext', 8n * sourceCiphertextBytes);
        fits('purpose signature', 8n * BigInt(purposeSignatureBytes));
        fits('ballot envelope', 8n * ballotEnvelopeBytes);
        fits('release envelope', 8n * participantReleaseEnvelopeBytes);
        fits('aggregate chunk', 8n * setupAggregateChunkBytes);
        fits('candidate chunk', 8n * candidateTransportParameters.chunkBytes);
        fits(
            'native chunk',
            8n *
                rustIntegerConstant(
                    await readRustSource(
                        'crates/protocol-research/parallel-work/src/lib.rs',
                    ),
                    'CHUNK_LIMIT',
                ),
        );
        // The proofs, signed bodies, offer envelopes and records of every
        // supported profile.
        for (const profile of listSupportedProfiles()) {
            const label = `${profile.participantCount}/${profile.optionCount}`;
            for (const [name, layout] of [
                ['setup proof', compileFullWordProofLayout(profile)],
                ['ballot proof', compileBallotWordProofLayout(profile)],
                ['release proof', compileLinkedReleaseWordProofLayout(profile)],
            ] as const)
                fits(`${name} ${label}`, 8n * layout.maximumProofBytes);
            fits(
                `signed ballot body ${label}`,
                8n * compileBallotBodyCensus(profile).maximumSignedBodyBytes,
            );
            fits(
                `contribution body ${label}`,
                8n * compileContributionBodyCensus(profile).maximumBodyBytes,
            );
            fits(
                `received close bodies ${label}`,
                8n * compileCloseWireCensus(profile).maximumReceivedBodyBytes,
            );
            fits(
                `offer envelope ${label}`,
                8n *
                    compileSetupSelectionWireCensus(profile.participantCount)
                        .offerEnvelopeBytes,
            );
            fits(
                `release record ${label}`,
                8n * compileParticipantReleaseCustody(profile).recordBytes,
            );
            fits(
                `ballot record ${label}`,
                8n * compileParticipantBallotCustody(profile).recordBytes,
            );
            fits(
                `checkpoint record ${label}`,
                8n *
                    compileFirstOracleCheckpointCensus(profile)
                        .maximumCiphertextRecordBytes,
            );
        }
    }, 240000);
});
