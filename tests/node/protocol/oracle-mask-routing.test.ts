import { describe, expect, it } from 'vitest';

import {
    compileOracleMaskRouting,
    oracleMaskRoutingWork,
    oracleSliceRoutingWork,
    runOracleSliceRouting,
    type OracleInputMask,
} from '#tests/compressed-oracle-model.js';

describe('exact raw-input oracle slice masks', () => {
    it('routes non-adjacent fields with exact lengths and clean reversible work', () => {
        const masks: OracleInputMask[] = [
            { inputLength: 4, positions: [0, 3], values: Uint8Array.of(0, 1) },
            {
                inputLength: 4,
                positions: [3, 0, 2],
                values: Uint8Array.of(0, 0, 1),
            },
            { inputLength: 2, positions: [0], values: Uint8Array.of(1) },
        ];
        for (const capacity of [0, 1, 2, 4, 5])
            for (const outputCapacity of [0, 1, 3]) {
                const compiled = compileOracleMaskRouting(
                    capacity,
                    outputCapacity,
                    masks,
                );
                for (let raw = 0; raw < 2 ** capacity; raw++)
                    for (
                        let length = 0;
                        length < 2 ** Number(compiled.work.inputLengthBits);
                        length++
                    )
                        for (
                            let requested = 0;
                            requested <
                            2 ** Number(compiled.work.outputLengthBits);
                            requested++
                        ) {
                            const data = Uint8Array.from(
                                { length: capacity },
                                (_, bit) => (raw >> bit) & 1,
                            );
                            const expected = [0, 0, 0, 0];
                            if (
                                length <= capacity &&
                                requested <= outputCapacity
                            ) {
                                const selected = masks.findIndex(
                                    (mask) =>
                                        length === mask.inputLength &&
                                        mask.positions.every(
                                            (position, bit) =>
                                                data[position] ===
                                                mask.values[bit],
                                        ),
                                );
                                expected[selected + 1] = requested;
                            }
                            expect(
                                runOracleSliceRouting(
                                    compiled,
                                    data,
                                    length,
                                    requested,
                                ),
                            ).toEqual(expected);
                        }
                const work = oracleMaskRoutingWork(
                    BigInt(capacity),
                    BigInt(outputCapacity),
                    masks.map((mask) => ({
                        inputLength: BigInt(mask.inputLength),
                        comparedBits: BigInt(mask.positions.length),
                    })),
                );
                expect(work.computeAndUncomputeGates).toBe(
                    BigInt(
                        4 * compiled.circuit.gates.length +
                            2 * compiled.circuit.output.length,
                    ),
                );
                // The prefix-dispatch envelope conservatively contains exact
                // masks with as many compared positions as the entire input.
                expect(work.computeAndUncomputeGates).toBeLessThanOrEqual(
                    oracleSliceRoutingWork(
                        BigInt(capacity),
                        BigInt(outputCapacity),
                        masks.map((mask) => BigInt(mask.inputLength)),
                    ).computeAndUncomputeGates,
                );
            }
    });

    it('rejects overlapping masks and ambiguous wire selections', () => {
        const mask = {
            inputLength: 3,
            positions: [0],
            values: Uint8Array.of(1),
        };
        expect(() =>
            compileOracleMaskRouting(3, 1, [
                mask,
                { inputLength: 3, positions: [2], values: Uint8Array.of(0) },
            ]),
        ).toThrow('overlap');
        expect(() => compileOracleMaskRouting(3, 1, [mask, mask])).toThrow(
            'overlap',
        );
        expect(() =>
            compileOracleMaskRouting(3, 1, [
                { ...mask, positions: [0, 0], values: Uint8Array.of(0, 1) },
            ]),
        ).toThrow();
        expect(() =>
            compileOracleMaskRouting(3, 1, [{ ...mask, positions: [3] }]),
        ).toThrow();
        expect(() =>
            compileOracleMaskRouting(3, 1, [
                { ...mask, values: Uint8Array.of(2) },
            ]),
        ).toThrow();
        // An equal mask at another exact length is a disjoint raw language.
        expect(() =>
            compileOracleMaskRouting(4, 1, [mask, { ...mask, inputLength: 4 }]),
        ).not.toThrow();
    });
});
