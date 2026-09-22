import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { compileArchiveAuthenticationWork } from '#tests/archive-authentication-model.js';

describe('archive authentication call accounting', () => {
    it('matches the pure receipt frame independently of participant purposes', () => {
        const context = Buffer.from('sealed-lattice/archive-retention/v1');
        const frame = Buffer.concat([
            Buffer.from([0, context.length]),
            context,
            Buffer.alloc(64, 7),
        ]);
        const value = compileArchiveAuthenticationWork();
        expect(value.contextBytes).toBe(BigInt(context.length));
        expect(value.messageBytes).toBe(64n);
        expect(value.frameBytes).toBe(BigInt(frame.length));
        expect(value.representativeInputBytes).toBe(BigInt(frame.length + 64));
        expect(value.representativePermutations).toBe(2n);
        const source = readFileSync(
            'crates/sealed-lattice-kernel/src/foundation/public-archive.rs',
            'utf8',
        );
        expect(source).toContain('"sealed-lattice/archive-retention/v1"');
        expect(source).toMatch(/MAXIMUM_ARCHIVE_REPLICAS: usize = 32/u);
    });

    it.each([1n, 2n, 3n, 7n, 31n, 32n])(
        'charges all responses for %s replicas',
        (replicas) => {
            const received: number[] = [];
            let verifications = 0n;
            for (
                let position = Number(replicas) - 1;
                position >= 0;
                position--
            ) {
                received.push(position);
                // Every synchronous acknowledgement check revisits the whole batch.
                for (const author of received) {
                    expect(author).toBeGreaterThanOrEqual(0);
                    verifications++;
                }
            }
            const value = compileArchiveAuthenticationWork(replicas);
            expect(value.maximumSignatureVerificationsPerPublish).toBe(
                verifications,
            );
            expect(value.maximumSdkRetentionRequestsPerPublish).toBe(replicas);
            expect(value.maximumAcknowledgementBatchesPerPublish).toBe(
                replicas,
            );
            // Direct calls may supply duplicate authors up to the independent cap.
            expect(value.maximumSignatureVerificationsPerDirectCall).toBe(32n);
            expect(value.signaturesPerSuccessfulRetentionRequest).toBe(1n);
        },
    );

    it('refuses counts outside the implemented policy bound', () => {
        for (const value of [-1n, 0n, 33n])
            expect(() => compileArchiveAuthenticationWork(value)).toThrow(
                RangeError,
            );
    });
});
