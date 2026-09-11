import { describe, expect, it } from 'vitest';

import {
    compileOraclePrefixReplacement,
    oraclePrefixReplacementWork,
    runOraclePrefixReplacement,
    verifyProgrammedLocalOracle,
} from '#tests/compressed-oracle-model.js';
import {
    oracleDomainWork,
    programmedOracleDomainWork,
} from '#tests/oracle-domain-model.js';

const bits = (value: number, width: number) =>
    Uint8Array.from(
        { length: width },
        (_, bit) => Math.floor(value / 2 ** bit) % 2,
    );

describe('Programmed oracle prefixes', () => {
    it('matches the modified compressed-oracle operator on every supported bounded database state', () => {
        for (const width of [1, 2]) {
            const result = verifyProgrammedLocalOracle(width);
            expect(result.cases).toBeGreaterThan(0);
            expect(result.maximumError).toBeLessThan(1e-12);
        }
    });
    it('preserves tails, distinct message lengths, repeated writes and clean quantum controls', () => {
        const replacements = [
            { input: bits(0, 0), prefix: bits(1, 1) },
            { input: bits(0, 1), prefix: bits(2, 2) },
            { input: bits(0, 2), prefix: bits(1, 3) },
            { input: bits(0, 1), prefix: bits(1, 1) },
        ];
        for (const m of [0, 1, 2, 3])
            for (const r of [0, 1, 2, 3]) {
                const compiled = compileOraclePrefixReplacement(
                    m,
                    r,
                    replacements,
                );
                for (let data = 0; data < 2 ** m; data++)
                    for (
                        let inputLength = 0;
                        inputLength <
                        2 ** Number(compiled.work.inputLengthBits);
                        inputLength++
                    )
                        for (
                            let outputLength = 0;
                            outputLength <
                            2 ** Number(compiled.work.outputLengthBits);
                            outputLength++
                        )
                            for (let base = 0; base < 2 ** r; base++) {
                                const raw = bits(data, m),
                                    expected = bits(base, r);
                                for (const replacement of replacements)
                                    if (
                                        replacement.input.length ===
                                            inputLength &&
                                        replacement.input.every(
                                            (bit, index) => bit === raw[index],
                                        )
                                    )
                                        expected.set(
                                            replacement.prefix.subarray(0, r),
                                        );
                                for (let bit = 0; bit < r; bit++)
                                    if (
                                        inputLength > m ||
                                        outputLength > r ||
                                        bit >= outputLength
                                    )
                                        expected[bit] = 0;
                                const response = bits(base ^ (2 ** r - 1), r),
                                    actual = runOraclePrefixReplacement(
                                        compiled,
                                        raw,
                                        inputLength,
                                        outputLength,
                                        bits(base, r),
                                        response,
                                    );
                                expect(actual).toEqual(
                                    expected.map(
                                        (bit, index) => bit ^ response[index],
                                    ),
                                );
                            }
            }
    });

    it('matches each emitted copy gate and charges both nested oracle wrappers', () => {
        const replacement = { input: bits(2, 3), prefix: bits(7, 4) },
            compiled = compileOraclePrefixReplacement(4, 5, [replacement]),
            shapes = [{ inputBits: 3n, prefixBits: 4n }],
            copy = oraclePrefixReplacementWork(4n, 5n, shapes),
            runs = [{ count: 3n, inputCapacity: 4n, outputCapacity: 5n }],
            work = programmedOracleDomainWork(runs, 2n, shapes);
        expect(copy.cleanCopyGates).toBe(
            BigInt(2 * compiled.circuit.gates.length + 5),
        );
        expect(copy.copyQubits).toBe(BigInt(compiled.circuit.wires + 5));
        expect(work.base).toEqual(
            oracleDomainWork([{ ...runs[0], count: 6n }], 2n),
        );
        expect(work.copyGates).toBe(3n * copy.cleanCopyGates);
        expect(work.queryGates).toBe(work.base.queryGates + work.copyGates);
        expect(work.classicalRecordPayloadBits).toBe(7n);
    });
});
