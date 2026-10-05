import { describe, expect, it } from 'vitest';

import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import {
    compileRegistrationEnrollmentCensus,
    compileRegistrationSourceCustody,
} from '#tests/registration-enrollment-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

describe('signed registration and original-key custody', () => {
    it('accounts for the canonical username and every public or secret record', () => {
        const value = compileRegistrationEnrollmentCensus();
        expect(value.maximumHeaderBytes).toBe(
            2375n + 6n + 2n + 4n + 64n * value.maximumSourceFamilyCount,
        );
        expect(value.proofRoleBytes).toBe(282n);
        expect(value.pollDefinitionOverheadBytes).toBe(2143n);
        // A two-option poll: 694 bytes of runtime, lengths, counts, username
        // and data keys beside the texts, which fill the poll definition but
        // its 2,143 bytes of framing and the manifest's 30 + 2 * 36 + 16.
        expect(value.maximumCreatorInputBytes).toBe(
            694n + 1_048_576n - 2143n - 118n,
        );
        expect(value.maximumJoinInputBytes).toBeLessThan(1_572_864n);
        expect(value.recipientCapsuleBytes).toBe(532n);
        expect(value.signingCapsuleBytes).toBe(52n);
        expect(value.maximumEnrollmentRecords).toBe(18n);
        expect(value.maximumRecords).toBe(22n);
        expect(value.maximumEnrollmentManifestBytes).toBe(1482n);
        expect(value.maximumProposalIntentManifestBytes).toBe(
            4n + 96n + 64n + 4n + 21n * 73n,
        );
        expect(value.maximumManifestBytes).toBe(
            4n + 96n + 64n + 4n + 22n * 73n,
        );
        expect(value.maximumRootBytes).toBe(
            4n + 96n + 64n + 4n + 22n * 73n + 16n,
        );
        expect(value.maximumRestoreInputBytes).toBeLessThan(1_572_864n);
        expect(value.maximumRetainedPayloadBytes).toBeLessThan(
            16n * 1024n ** 2n,
        );
    });

    it('charges all three original secret capsules and retires the source key before ballots', () => {
        const value = compileRegistrationEnrollmentCensus();
        expect(value.manifestPrefixBytes).toBe(168n);
        expect(value.preparedManifestPrefixBytes).toBe(136n);
        expect(value.rootAssociatedBytes).toBe(68n);
        expect(value.recipientAssociatedBytes).toBe(482n);
        expect(value.initialRootDistinctBlockInputs).toBe(101n);
        expect(value.rootDistinctBlockInputs).toBe(113n);
        expect(value.signingDistinctBlockInputs).toBe(5n);
        expect(value.sourceDistinctBlockInputs).toBe(
            2n + (value.maximumSourceCapsuleBytes - 16n + 15n) / 16n,
        );
        const associated = Buffer.concat([
            Buffer.alloc(8),
            Buffer.alloc(6),
            Buffer.alloc(4),
            Buffer.from('sealed-lattice/fhe-source-custody/v1'),
            Buffer.alloc(6),
            Buffer.alloc(64),
        ]);
        expect(value.sourceAssociatedBytes).toBe(BigInt(associated.length));
    });

    it.each([
        [3, 2],
        [10, 10],
        [20, 20],
    ])(
        'frames every distinct source family for a poll up to %i participants and %i options',
        (maximum, options) => {
            const families = new Set<string>();
            for (
                let participants = 3;
                participants <= maximum;
                participants++
            ) {
                const profile = deriveSupportedProfile(participants, options);
                const sampler =
                    compileCommonMatrixSamplingCensus(
                        profile,
                    ).fheBitsPerCoefficient;
                families.add(`${profile.ciphertext.modulus}:${sampler}`);
            }
            const value = compileRegistrationSourceCustody(maximum, options);
            const commitments = Buffer.concat([
                Buffer.from([6, 0]),
                Buffer.alloc(4),
                ...[...families].map(() => Buffer.alloc(64)),
            ]);
            const capsule = Buffer.concat([
                Buffer.from('FSC1'),
                ...[...families].map(() =>
                    Buffer.concat([Buffer.alloc(64), Buffer.alloc(64)]),
                ),
                Buffer.alloc(16),
            ]);
            expect(value.familyCount).toBe(BigInt(families.size));
            expect(value.commitmentListBytes).toBe(BigInt(commitments.length));
            expect(value.capsuleBytes).toBe(BigInt(capsule.length));
            expect(value.capsulePlaintextBytes).toBe(
                BigInt(capsule.length - 16),
            );
            expect(value.capsuleBytes).toBeLessThanOrEqual(
                compileRegistrationEnrollmentCensus().maximumSourceCapsuleBytes,
            );
        },
    );

    it('enumerates the root counter inputs independently of the byte census', () => {
        const inputs = new Set<bigint>([0n]);
        for (const [nonceOrdinal, plaintextBlocks] of [
            [0n, 5],
            [1n, 93],
        ] as const) {
            const initial = (nonceOrdinal << 32n) + 1n;
            for (let counter = 0; counter <= plaintextBlocks; counter++) {
                const input = initial + BigInt(counter);
                expect(inputs.has(input)).toBe(false);
                inputs.add(input);
            }
        }
        expect(BigInt(inputs.size)).toBe(
            compileRegistrationEnrollmentCensus()
                .initialRootDistinctBlockInputs,
        );
        for (const [nonceOrdinal, blocks] of [
            [2n, 107],
            [3n, 111],
        ] as const) {
            const rotatedKeyInputs = new Set<bigint>([0n]);
            for (let counter = 0; counter <= blocks; counter++) {
                const input = (nonceOrdinal << 32n) + 1n + BigInt(counter);
                expect(rotatedKeyInputs.has(input)).toBe(false);
                rotatedKeyInputs.add(input);
            }
            expect(BigInt(rotatedKeyInputs.size)).toBeLessThanOrEqual(
                compileRegistrationEnrollmentCensus().rootDistinctBlockInputs,
            );
        }
    });
});
