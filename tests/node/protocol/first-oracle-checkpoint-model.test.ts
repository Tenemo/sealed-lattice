import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('complete first-oracle proof checkpoint', () => {
    it('keeps the first response salt after the checkpoint and prices separate field reads', async () => {
        const model = compileFirstOracleCheckpointCensus(completionProfile());
        const read = (file: string) =>
            readFile(new URL('../../../' + file, import.meta.url), 'utf8');
        const [worker, bridge, transcript, checkpoint] = await Promise.all([
            read(
                'packages/sdk/src/participant/worker/stages/contribution/contribution.ts',
            ),
            read('crates/protocol-research/word-proof/src/bridge.rs'),
            read('crates/protocol-research/word-proof/src/transcript.rs'),
            read('crates/protocol-research/word-proof/src/first-checkpoint.rs'),
        ]);
        const position = (source: string, text: string) => {
            const index = source.indexOf(text);
            expect(index).toBeGreaterThanOrEqual(0);
            return index;
        };
        const continuation = worker.slice(
            position(worker, 'export const continueContribution'),
        );
        expect(position(continuation, 'await commitContribution')).toBeLessThan(
            position(continuation, 'const run = proverRun'),
        );
        expect(position(bridge, 'first.finish_commitment();')).toBeLessThan(
            position(bridge, 'transcript.respond(&[&first.tree.root()]);'),
        );
        expect(transcript).toContain('let mut salt = [0; 128];');
        expect(transcript).toContain('crate::random::fill(&mut salt);');
        expect(checkpoint).toContain('tree: Tree::with_seed(');

        // Independent request schedule for the completion profile: one full
        // read for each base mask, the degree mask, then one retained seed.
        const buffer = 65_536n;
        const firstMasks = 356n;
        const degreeMaskWords = 3n * 131_072n;
        const generation = firstMasks * buffer + degreeMaskWords * 16n + 64n;
        expect(model.minimumGenerationProofRandomBytes).toBe(generation);
        // Batching the short mask requests incorrectly preserves bytes that
        // each real random_base call discards.
        const incorrectlyBatched =
            ((firstMasks * 1409n * 16n + buffer - 1n) / buffer) * buffer;
        expect(incorrectlyBatched).toBeLessThan(firstMasks * buffer);
        // The remaining eighteen tree seeds, all twenty response salts,
        // the 376 extension masks (two reads each), and the sum mask.
        expect(model.minimumContinuationProofRandomBytes).toBe(
            18n * 64n + 20n * 128n + (376n * 2n + 50n) * buffer,
        );
    });

    it('accounts for every required private field without deterministic caches', () => {
        const model = compileFirstOracleCheckpointCensus(completionProfile());
        expect(model.fields.map((field) => field.plaintextBytes)).toEqual([
            355n * 65536n * 2n,
            356n * 1409n * 16n,
            131072n * 48n,
            64n,
            262144n * 201n,
        ]);
        let bytes = 0n;
        let records = 0n;
        for (const field of model.fields) {
            let remaining = field.units;
            while (remaining > 0n) {
                const units =
                    remaining < field.unitsPerRecord
                        ? remaining
                        : field.unitsPerRecord;
                const plaintext = units * field.unitBytes;
                expect(plaintext).toBeLessThanOrEqual(1_048_576n);
                expect(plaintext % field.unitBytes).toBe(0n);
                bytes += plaintext + 16n;
                remaining -= units;
                records++;
            }
        }
        expect(bytes).toBe(model.ciphertextBytes);
        expect(records).toBe(model.recordCount);
        expect(model.dataKeyBytes).toBe(32n * records);
        expect(model.recordHashBytes).toBe(64n * records);
        expect(model.maximumHeaderBytes).toBeLessThan(16384n);
        expect(model.maximumHeaderBytes).toBe(
            4n +
                1n +
                1n +
                4n +
                2n +
                1024n +
                64n +
                64n +
                (4n + 4n + 108n + 20n) +
                2n +
                10n * 64n,
        );
        const actualHeader = Buffer.concat([
            Buffer.from('FPC4'),
            Buffer.from([10, 10]),
            Buffer.alloc(4),
            Buffer.from([84, 1]),
            Buffer.alloc(340),
            Buffer.alloc(64),
            Buffer.alloc(64),
            Buffer.concat([
                Buffer.from('SCO2'),
                Buffer.alloc(4),
                Buffer.alloc(108),
                Buffer.alloc(20),
            ]),
            Buffer.from([10, 0]),
            Buffer.alloc(10 * 64),
        ]);
        expect(model.headerBytes).toBe(BigInt(actualHeader.length));
        expect(model.importBytes).toBe(
            BigInt(Buffer.concat([Buffer.alloc(2 * 64), actualHeader]).length),
        );
        expect(model.maximumHeaderBytes - model.headerBytes).toBe(1024n - 340n);
        const input = Buffer.concat([Buffer.alloc(64), actualHeader]);
        expect(model.headerDigestInputBytes).toBe(BigInt(input.length));
        const padded = [...input, 0x1f];
        while (padded.length % 136 !== 0) padded.push(0);
        padded[padded.length - 1] |= 0x80;
        expect(model.headerDigestPermutations).toBe(
            BigInt(padded.length / 136),
        );
        expect(model.headerDigestPermutationsPerPass).toBe(
            model.recordCount * BigInt(padded.length / 136),
        );
        expect(model.publicRecordCount).toBe(1n + 24n * 7n + 20n * 2n);
        expect(model.publicPlaintextBytes).toBe(
            4n + 4n + 108n + 20n + 24n * 65536n * 109n + 20n * 65536n * 21n,
        );
        expect(model.maximumRootPlaintextBytes).toBeLessThan(1_048_576n);
        expect(model.maximumRetainedPayloadBytes).toBeLessThan(402_653_184n);
        expect(
            model.ciphertextBytes + model.dataKeyBytes + model.recordHashBytes,
        ).toBeLessThan(268_435_456n);
    });
});
