import { readFile } from 'node:fs/promises';

import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import {
    shake256RateBytes,
    spongePermutations,
} from '#tests/node/protocol/reference/sponge-permutations.js';
import { readRustSource, rustFunctionBody } from '#tests/node/rust-source.js';
import { completionProfile } from '#tests/supported-profile-model.js';

// The callees of the calls in the named arrow function's body, in source
// order. Comments are not calls, so they cannot satisfy an ordering check.
const callsIn = (source: string, name: string) => {
    const file = ts.createSourceFile(
        'source.ts',
        source,
        ts.ScriptTarget.Latest,
        true,
    );
    const bodies: ts.Node[] = [];
    const findBody = (node: ts.Node) => {
        if (
            ts.isVariableDeclaration(node) &&
            node.name.getText(file) === name &&
            node.initializer !== undefined &&
            ts.isArrowFunction(node.initializer)
        )
            bodies.push(node.initializer.body);
        ts.forEachChild(node, findBody);
    };
    findBody(file);
    expect(bodies).toHaveLength(1);
    const calls: string[] = [];
    const collect = (node: ts.Node) => {
        if (ts.isCallExpression(node))
            calls.push(node.expression.getText(file));
        ts.forEachChild(node, collect);
    };
    collect(bodies[0]);
    return calls;
};

describe('complete first-oracle proof checkpoint', () => {
    it('keeps the first response salt after the checkpoint and prices separate field reads', async () => {
        const model = compileFirstOracleCheckpointCensus(completionProfile());
        const [worker, setupProver, transcript, checkpoint] = await Promise.all(
            [
                readFile(
                    new URL(
                        '../../../packages/sdk/src/participant/worker/stages/contribution/contribution.ts',
                        import.meta.url,
                    ),
                    'utf8',
                ),
                readRustSource(
                    'crates/protocol-research/word-proof/src/setup-prover.rs',
                ),
                readRustSource(
                    'crates/protocol-research/word-proof/src/transcript.rs',
                ),
                readRustSource(
                    'crates/protocol-research/word-proof/src/first-oracle-checkpoint.rs',
                ),
            ],
        );
        // The continuation retains its fresh seed before the prover draws
        // the first response salt from it.
        const continuation = callsIn(worker, 'continueContribution');
        expect(continuation.indexOf('commitContribution')).toBeGreaterThan(-1);
        expect(continuation.indexOf('commitContribution')).toBeLessThan(
            continuation.indexOf('proverRun'),
        );
        const position = (source: string, text: string) => {
            const index = source.indexOf(text);
            expect(index).toBeGreaterThanOrEqual(0);
            return index;
        };
        const step = rustFunctionBody(setupProver, 'step');
        expect(position(step, 'first.finish_commitment();')).toBeLessThan(
            position(step, 'transcript.respond(&[&first.tree.root()]);'),
        );
        const respond = rustFunctionBody(transcript, 'respond');
        expect(position(respond, 'let mut salt = [0; 128];')).toBeLessThan(
            position(respond, 'parallel_work::random::proof(&mut salt);'),
        );
        expect(rustFunctionBody(checkpoint, 'finish')).toContain(
            'tree: Tree::with_seed(',
        );

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
        const digestPermutations = spongePermutations(
            input.length,
            64,
            shake256RateBytes,
        );
        expect(model.headerDigestPermutations).toBe(digestPermutations);
        expect(model.headerDigestPermutationsPerPass).toBe(
            model.recordCount * digestPermutations,
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
