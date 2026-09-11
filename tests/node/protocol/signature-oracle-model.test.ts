import { describe, expect, it } from 'vitest';

import {
    excludedPrefixStreamControl,
    fullXofPrefixControl,
} from '#tests/excluded-prefix-stream-model.js';
import {
    nodeLabel,
    readNodeLabel,
    routeSignatureHashRow,
} from '#tests/signature-oracle-model.js';

const row = (
    layer: number,
    tree: bigint,
    type: number,
    leaf: number,
    first: number,
    second: number,
    bytes: number,
) => {
    const input = Buffer.alloc(bytes);
    if (bytes >= 64) {
        input.fill(9, 0, 32);
        input.writeUInt32BE(layer, 32);
        input.writeBigUInt64BE(tree, 40);
        input.writeUInt32BE(type, 48);
        input.writeUInt32BE(leaf, 52);
        input.writeUInt32BE(first, 56);
        input.writeUInt32BE(second, 60);
    }
    return input;
};
describe('Signature implicit-node and full-XOF correspondence', () => {
    it('fixes each standard row and its exact operands', () => {
        const seed = Buffer.alloc(32, 9);
        for (const layer of [0, 1, 8, 16]) {
            const tree = (1n << BigInt(64 - 4 * layer)) - 1n;
            const chain = routeSignatureHashRow(
                row(layer, tree, 0, 15, 66, 14, 96),
            )!;
            expect(chain.target).toEqual(
                nodeLabel(0, seed, layer, tree, 15, 66, 15),
            );
            expect(chain.dependencies).toEqual([
                nodeLabel(0, seed, layer, tree, 15, 66, 14),
            ]);
            expect(chain.stageMessage).toEqual(
                layer === 0
                    ? nodeLabel(5, seed, 0, tree, 15)
                    : nodeLabel(2, seed, layer - 1, 16n * tree + 15n, 0, 4, 0),
            );
            const compressed = routeSignatureHashRow(
                row(layer, tree, 1, 15, 0, 0, 2208),
            )!;
            expect(compressed.dependencies).toEqual(
                Array.from({ length: 67 }, (_, index) =>
                    nodeLabel(0, seed, layer, tree, 15, index, 15),
                ),
            );
            for (let height = 1; height <= 4; height++) {
                const index = 2 ** (4 - height) - 1,
                    plan = routeSignatureHashRow(
                        row(layer, tree, 2, 0, height, index, 128),
                    )!;
                expect(plan.target).toEqual(
                    nodeLabel(2, seed, layer, tree, 0, height, index),
                );
                expect(plan.dependencies).toEqual(
                    [0, 1].map((side) =>
                        height === 1
                            ? nodeLabel(1, seed, layer, tree, 2 * index + side)
                            : nodeLabel(
                                  2,
                                  seed,
                                  layer,
                                  tree,
                                  0,
                                  height - 1,
                                  2 * index + side,
                              ),
                    ),
                );
            }
        }
        for (let height = 0; height <= 9; height++) {
            const index = 35 * 2 ** (9 - height) - 1,
                plan = routeSignatureHashRow(
                    row(0, 7n, 3, 15, height, index, height === 0 ? 96 : 128),
                )!;
            expect(plan.target).toEqual(
                nodeLabel(4, seed, 0, 7n, 15, height, index),
            );
            expect(plan.dependencies).toEqual(
                height === 0
                    ? [nodeLabel(3, seed, 0, 7n, 15, 0, index)]
                    : [0, 1].map((side) =>
                          nodeLabel(
                              4,
                              seed,
                              0,
                              7n,
                              15,
                              height - 1,
                              2 * index + side,
                          ),
                      ),
            );
        }
        const forest = routeSignatureHashRow(row(0, 7n, 4, 15, 0, 0, 1184))!;
        expect(forest.target).toEqual(nodeLabel(5, seed, 0, 7n, 15));
        expect(forest.dependencies).toEqual(
            Array.from({ length: 35 }, (_, index) =>
                nodeLabel(4, seed, 0, 7n, 15, 9, index),
            ),
        );
        expect(readNodeLabel(forest.target)).toEqual({
            kind: 5,
            seed,
            layer: 0,
            tree: 7n,
            leaf: 15,
            first: 0,
            second: 0,
        });
    });
    it('leaves malformed and unrelated queries in the base-function domain', () => {
        const inputs = [
            row(17, 0n, 0, 0, 0, 0, 96),
            row(16, 1n, 0, 0, 0, 0, 96),
            row(0, 0n, 0, 16, 0, 0, 96),
            row(0, 0n, 0, 0, 67, 0, 96),
            row(0, 0n, 0, 0, 0, 15, 96),
            row(0, 0n, 1, 0, 1, 0, 2208),
            row(0, 0n, 2, 1, 1, 0, 128),
            row(0, 0n, 2, 0, 0, 0, 128),
            row(0, 0n, 2, 0, 4, 1, 128),
            row(1, 0n, 3, 0, 0, 0, 96),
            row(0, 0n, 3, 0, 0, 17920, 96),
            row(0, 0n, 3, 0, 9, 35, 128),
            row(0, 0n, 4, 0, 0, 1, 1184),
            row(0, 0n, 5, 0, 0, 0, 96),
            Buffer.alloc(63),
        ];
        const valid = row(0, 0n, 0, 0, 0, 0, 96),
            high = Buffer.from(valid);
        high.writeUInt32BE(1, 36);
        inputs.push(
            high,
            valid.subarray(0, 95),
            Buffer.concat([valid, Buffer.from([0])]),
            Buffer.concat([valid, Buffer.alloc(4096)]),
        );
        for (const input of inputs)
            expect(routeSignatureHashRow(input)).toBeUndefined();
    });
    it('preserves the excluded-prefix/tail correlation counterexample', () => {
        for (const value of excludedPrefixStreamControl()) {
            expect(value.reusedSuccess * 2 ** value.outputBits).toBe(
                2 * value.samples,
            );
            expect(
                BigInt(value.distinguishing.numerator) * BigInt(value.samples),
            ).toBeGreaterThan(
                BigInt(2 ** value.outputBits - 1) * BigInt(value.denominator),
            );
        }
    });
    it('implements variable-length XOF answers with two Boolean queries and clean scratch', () => {
        const value = fullXofPrefixControl();
        expect(value.basisCases).toBe(16 * 4 * 5 * 16);
        expect(value.booleanQueriesPerXof).toBe(2);
        for (const view of value.views)
            expect(view.counts).toEqual(Array<number>(16).fill(3));
    });
});
