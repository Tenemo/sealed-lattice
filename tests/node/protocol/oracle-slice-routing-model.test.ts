import { describe, expect, it } from 'vitest';

import {
    compileOracleSliceRouting,
    oracleSliceRoutingWork,
    runOracleSliceRouting,
    compileOraclePrefixReplacement,
    runOraclePrefixReplacement,
} from '#tests/compressed-oracle-model.js';
import {
    oracleDomainWork,
    shadowOracleDomainWork,
} from '#tests/oracle-domain-model.js';

describe('Hidden-slice oracle routing', () => {
    it('restores the entire background slice and only replaces the disclosed point', () => {
        const prefixes = [Uint8Array.of(0), Uint8Array.of(1)],
            before = compileOracleSliceRouting(2, 1, prefixes),
            after = compileOracleSliceRouting(2, 1, [prefixes[1]]);
        for (let background = 0; background < 16; background++)
            for (let first = 0; first < 4; first++)
                for (let second = 0; second < 4; second++)
                    for (const announced of [0, 1]) {
                        const copy = compileOraclePrefixReplacement(2, 1, [
                            {
                                input: Uint8Array.of(0, 0),
                                prefix: Uint8Array.of(announced),
                            },
                        ]);
                        for (let input = 0; input < 4; input++) {
                            const data = Uint8Array.of(
                                    input % 2,
                                    Math.floor(input / 2),
                                ),
                                prior = runOracleSliceRouting(
                                    before,
                                    data,
                                    2,
                                    1,
                                ),
                                later = runOracleSliceRouting(
                                    after,
                                    data,
                                    2,
                                    1,
                                ),
                                base = (background >> input) & 1,
                                firstValue = (first >> data[1]) & 1,
                                secondValue = (second >> data[1]) & 1;
                            expect(
                                (prior[0] * base) ^
                                    (prior[1] * firstValue) ^
                                    (prior[2] * secondValue),
                            ).toBe(data[0] === 0 ? firstValue : secondValue);
                            const patched = runOraclePrefixReplacement(
                                copy,
                                data,
                                2,
                                later[0],
                                Uint8Array.of(base),
                                Uint8Array.of(0),
                            )[0];
                            expect(patched ^ (later[1] * secondValue)).toBe(
                                data[0] === 1
                                    ? secondValue
                                    : input === 0
                                      ? announced
                                      : base,
                            );
                        }
                    }
    });
    it('retains each oracle across opening stages and counts the nested background separately', () => {
        const runs = [
                {
                    count: 2n,
                    inputCapacity: 4n,
                    outputCapacity: 3n,
                    activeShadows: [0, 1],
                    replacements: [],
                },
                {
                    count: 3n,
                    inputCapacity: 4n,
                    outputCapacity: 3n,
                    activeShadows: [1],
                    replacements: [{ inputBits: 4n, prefixBits: 2n }],
                },
            ],
            work = shadowOracleDomainWork(runs, 2n, [2n, 3n]);
        expect(work.base).toEqual(
            oracleDomainWork(
                [{ count: 10n, inputCapacity: 4n, outputCapacity: 3n }],
                2n,
            ),
        );
        expect(work.shadows[0]).toEqual(oracleDomainWork([runs[0]], 2n));
        expect(work.shadows[1]).toEqual(oracleDomainWork(runs, 2n));
        expect(work.queryGates).toBe(
            work.base.queryGates +
                work.copyGates +
                work.routingGates +
                work.shadows[0].queryGates +
                work.shadows[1].queryGates,
        );
        expect(() =>
            shadowOracleDomainWork(
                [{ ...runs[0], activeShadows: [0, 0] }],
                2n,
                [2n],
            ),
        ).toThrow();
        expect(() =>
            shadowOracleDomainWork([{ ...runs[0], activeShadows: [1] }], 2n, [
                2n,
            ]),
        ).toThrow();
    });
    it('routes complete prefixes across every suffix and clears all selection work', () => {
        const prefixes = [Uint8Array.of(0, 1), Uint8Array.of(1, 0, 1)];
        for (const m of [0, 1, 2, 3, 4])
            for (const r of [0, 1, 2, 3]) {
                const compiled = compileOracleSliceRouting(m, r, prefixes);
                for (let value = 0; value < 2 ** m; value++)
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
                                    { length: m },
                                    (_, bit) =>
                                        Math.floor(value / 2 ** bit) % 2,
                                ),
                                actual = runOracleSliceRouting(
                                    compiled,
                                    data,
                                    length,
                                    requested,
                                ),
                                expected = [0, 0, 0];
                            if (length <= m && requested <= r) {
                                const selected = prefixes.findIndex(
                                    (prefix) =>
                                        prefix.length <= length &&
                                        prefix.every(
                                            (bit, index) => bit === data[index],
                                        ),
                                );
                                expected[selected + 1] = requested;
                            }
                            expect(actual).toEqual(expected);
                        }
                const work = oracleSliceRoutingWork(
                    BigInt(m),
                    BigInt(r),
                    prefixes.map((value) => BigInt(value.length)),
                );
                expect(work.computeAndUncomputeGates).toBe(
                    BigInt(
                        4 * compiled.circuit.gates.length +
                            2 * compiled.circuit.output.length,
                    ),
                );
                expect(work.routingQubits).toBe(
                    BigInt(
                        compiled.circuit.wires + compiled.circuit.output.length,
                    ),
                );
            }
    });
    it('rejects overlapping scopes, including an empty prefix beside another scope', () => {
        expect(() =>
            compileOracleSliceRouting(4, 2, [
                Uint8Array.of(0),
                Uint8Array.of(0, 1),
            ]),
        ).toThrow('overlap');
        expect(() =>
            compileOracleSliceRouting(4, 2, [
                Uint8Array.of(0, 1),
                Uint8Array.of(0),
            ]),
        ).toThrow('overlap');
        expect(() =>
            compileOracleSliceRouting(4, 2, [
                new Uint8Array(),
                Uint8Array.of(1),
            ]),
        ).toThrow('overlap');
        expect(() =>
            compileOracleSliceRouting(4, 2, [Uint8Array.of(2)]),
        ).toThrow();
        expect(() => oracleSliceRoutingWork(0n, 0n, [-1n])).toThrow();
    });
    it('returns the background after a shadow closes and keeps other shadows active', () => {
        const all = [Uint8Array.of(0, 1), Uint8Array.of(1, 0, 1)],
            before = compileOracleSliceRouting(4, 3, all),
            after = compileOracleSliceRouting(4, 3, [all[1]]);
        expect(
            runOracleSliceRouting(before, Uint8Array.of(0, 1, 1, 1), 4, 3),
        ).toEqual([0, 3, 0]);
        expect(
            runOracleSliceRouting(after, Uint8Array.of(0, 1, 1, 1), 4, 3),
        ).toEqual([3, 0]);
        expect(
            runOracleSliceRouting(after, Uint8Array.of(1, 0, 1, 0), 4, 3),
        ).toEqual([0, 3]);
    });
});
