import { describe, expect, it } from 'vitest';

import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import {
    compileGcmKeyHistory,
    compileParticipantCustodyCensus,
    compileParticipantVaultKeyClasses,
} from '#tests/participant-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

describe('shared participant custody', () => {
    it('retains every contribution polynomial once and omits fixed statement framing', () => {
        const value = compileParticipantCustodyCensus();
        const body = compileContributionBodyCensus();
        expect(value.maximumRootRecords).toBe(
            compileRegistrationEnrollmentCensus().maximumRecords + 1n,
        );
        expect(value.setupReferenceBytes).toBe(
            4n + 64n + 64n * BigInt(body.polynomials.length),
        );
        expect(value.publicRecords.some((record) => record.object === 0)).toBe(
            false,
        );
        for (const polynomial of body.polynomials) {
            const records = value.publicRecords.filter(
                (record) => record.object === polynomial.expandedIndex + 1,
            );
            expect(
                records.reduce((total, record) => total + record.length, 0n),
            ).toBe(polynomial.bytes);
            expect(
                records.every(
                    (record, index) =>
                        record.offset === BigInt(index) * (1n << 20n),
                ),
            ).toBe(true);
        }
    });

    it('carries the complete existing private checkpoint without exceeding the root or storage bounds', () => {
        const value = compileParticipantCustodyCensus();
        const checkpoint = compileFirstOracleCheckpointCensus();
        expect(BigInt(value.checkpointLengths.length)).toBe(
            checkpoint.recordCount,
        );
        expect(
            value.checkpointLengths.reduce(
                (total, length) => total + length,
                0n,
            ),
        ).toBe(checkpoint.ciphertextBytes);
        expect(value.maximumRootBytes).toBeLessThan(1_572_864n);
        expect(value.maximumRetainedPayloadBytes).toBeLessThan(2_147_483_648n);
    });

    it('counts repeated reads as work without inventing new AES inputs', () => {
        const first = { nonce: 0n, plaintextBytes: 17n, associatedBytes: 1n };
        const second = { nonce: 1n, plaintextBytes: 1n, associatedBytes: 0n };
        const value = compileGcmKeyHistory([first, second], [first, first]);
        // Independently enumerate full AES input blocks, including H and J0.
        const inputs = new Set(['0:0']);
        for (const [nonce, payload] of [
            [0, 2],
            [1, 1],
        ])
            for (let counter = 1; counter <= payload + 1; counter++)
                inputs.add(`${nonce}:${counter}`);
        expect(value.distinctAesInputUpperBound).toBe(BigInt(inputs.size));
        expect(value.algorithmicAesCallUpperBound).toBe(4n + 3n + 4n + 4n);
        expect(value.permutationSwitchNumerator).toBe(15n);
        expect(value.authenticationNumerator).toBe(8n);
        expect(value.statisticalDenominator).toBe(2n ** 128n);
    });

    it('rejects encryption nonce reuse while allowing verification-only and empty histories', () => {
        const empty = {
            nonce: (1n << 96n) - 1n,
            plaintextBytes: 0n,
            associatedBytes: 0n,
        };
        expect(() => compileGcmKeyHistory([empty, empty], [])).toThrow(
            'reused',
        );
        expect(
            compileGcmKeyHistory([], [empty]).distinctAesInputUpperBound,
        ).toBe(2n);
        expect(compileGcmKeyHistory([], []).algorithmicAesCallUpperBound).toBe(
            0n,
        );
        expect(compileGcmKeyHistory([], []).permutationSwitchNumerator).toBe(
            0n,
        );
        for (const changed of [
            { ...empty, nonce: 1n << 96n },
            { ...empty, plaintextBytes: (1n << 36n) - 31n },
            { ...empty, associatedBytes: 1n << 61n },
            { ...empty, plaintextBytes: -1n },
        ])
            expect(() => compileGcmKeyHistory([changed], [])).toThrow('bounds');
        expect(
            compileGcmKeyHistory(
                [{ ...empty, plaintextBytes: (1n << 36n) - 32n }],
                [],
            ).distinctAesInputUpperBound,
        ).toBe(1n << 32n);
    });

    it('leaves lifetime key and read populations unknown across the complete emitted custody graph', () => {
        const classes = compileParticipantVaultKeyClasses();
        expect(classes.map((value) => value.name)).toEqual([
            'Initial root',
            'Later root',
            'Recipient capsule',
            'Signing capsule',
            'Contribution body record',
            'Contribution checkpoint record',
            'Contribution signing record',
            'Ballot journal record',
            'Ballot body record',
        ]);
        expect(
            classes.every(
                (value) =>
                    value.lifetimeKeys === null &&
                    value.lifetimeVerifications === null,
            ),
        ).toBe(true);
        expect(
            classes.find((value) => value.name === 'Later root')!
                .maximumPerCompletedCorpus,
        ).toBeNull();
        expect(classes[0].encryptionWork.invocations).toBe(2n);
        expect(
            classes
                .slice(1)
                .every((value) => value.encryptionWork.invocations === 1n),
        ).toBe(true);
        expect(classes[3].encryptionWork.distinctAesInputUpperBound).toBe(5n);
    });
});
