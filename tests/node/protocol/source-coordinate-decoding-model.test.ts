import { describe, expect, it } from 'vitest';

import {
    compileSourceCoordinateDecoding,
    runCleanCircuit,
    sourceCoordinateDecodingWork,
} from '#tests/compressed-oracle-model.js';
import { listSupportedProfiles } from '#tests/supported-profile-model.js';

const bits = (value: bigint, width: number) =>
    Array.from({ length: width }, (_, index) =>
        Number((value >> BigInt(index)) & 1n),
    );
const input = (
    found: number,
    expected: bigint,
    actual: bigint,
    salt: bigint,
    coefficients: readonly (readonly [number, bigint])[],
    magnitudeBits: number,
    contextBits: number,
    saltBits: number,
) =>
    Uint8Array.from([
        found,
        ...bits(expected, contextBits),
        ...bits(actual, contextBits),
        ...bits(salt, saltBits),
        ...coefficients.flatMap(([sign, magnitude]) => [
            ...bits(BigInt(sign), 8),
            ...bits(magnitude, magnitudeBits),
        ]),
    ]);
const cleanGates = (
    circuit: ReturnType<typeof compileSourceCoordinateDecoding>,
) => BigInt(2 * circuit.gates.length + circuit.output.length);

describe('extracted source coordinate decoding circuit', () => {
    it('exhausts sign bytes, centered bounds and negative zero on a small coefficient', () => {
        for (const limit of [1n, 3n, 7n]) {
            const circuit = compileSourceCoordinateDecoding(1, 3, limit, 2, 2);
            for (let sign = 0; sign < 256; sign++)
                for (let magnitude = 0n; magnitude < 8n; magnitude++) {
                    const source = input(
                        1,
                        2n,
                        2n,
                        3n,
                        [[sign, magnitude]],
                        3,
                        2,
                        2,
                    );
                    const valid =
                        sign <= 1 &&
                        magnitude <= limit &&
                        (sign === 0 || magnitude !== 0n);
                    const payload = source.subarray(5);
                    expect(runCleanCircuit(circuit, source)).toEqual(
                        Uint8Array.from([
                            ...payload.map((bit) => (valid ? bit : 0)),
                            Number(valid),
                        ]),
                    );
                }
        }
    });

    it('keeps missing extraction, wrong contexts and later invalid coefficients total', () => {
        const circuit = compileSourceCoordinateDecoding(2, 4, 5n, 2, 3);
        for (const found of [0, 1])
            for (let expected = 0n; expected < 4n; expected++)
                for (let actual = 0n; actual < 4n; actual++)
                    for (const second of [
                        [0, 0n],
                        [1, 5n],
                        [1, 0n],
                        [0, 6n],
                        [2, 1n],
                    ] as const) {
                        const source = input(
                            found,
                            expected,
                            actual,
                            7n,
                            [[1, 3n], second],
                            4,
                            2,
                            3,
                        );
                        const valid =
                            found === 1 &&
                            expected === actual &&
                            second[0] <= 1 &&
                            second[1] <= 5n &&
                            (second[0] === 0 || second[1] !== 0n);
                        const output = Uint8Array.from(
                            { length: circuit.output.length },
                            (_, index) => index % 2,
                        );
                        const original = output.slice();
                        const result = runCleanCircuit(circuit, source, output);
                        expect(result).toEqual(
                            Uint8Array.from([
                                ...source
                                    .subarray(5)
                                    .map((bit, index) =>
                                        valid
                                            ? bit ^ original[index]
                                            : original[index],
                                    ),
                                Number(valid) ^ original[original.length - 1],
                            ]),
                        );
                        expect(
                            runCleanCircuit(circuit, source, result),
                        ).toEqual(original);
                    }
    });

    it('matches emitted clean gates and actual modulus boundaries without materializing a full source', () => {
        const moduli = new Set(
            listSupportedProfiles().map(
                (profile) => profile.ciphertext.modulus,
            ),
        );
        for (const modulus of moduli) {
            const magnitudeBits = 8 * Math.ceil(modulus.toString(2).length / 8);
            const limit = modulus / 2n;
            const one = compileSourceCoordinateDecoding(
                1,
                magnitudeBits,
                limit,
            );
            const two = compileSourceCoordinateDecoding(
                2,
                magnitudeBits,
                limit,
            );
            const perCoefficient = cleanGates(two) - cleanGates(one);
            const fixed = cleanGates(one) - perCoefficient;
            expect(
                sourceCoordinateDecodingWork(1n, BigInt(magnitudeBits))
                    .decodingGates,
            ).toBe(cleanGates(one));
            expect(
                sourceCoordinateDecodingWork(65536n, BigInt(magnitudeBits))
                    .decodingGates,
            ).toBe(fixed + 65536n * perCoefficient);
            for (const sign of [0, 1])
                for (const magnitude of [0n, limit - 1n, limit, limit + 1n]) {
                    const source = input(
                        1,
                        1n << 1023n,
                        1n << 1023n,
                        1n << 511n,
                        [[sign, magnitude]],
                        magnitudeBits,
                        1024,
                        512,
                    );
                    const result = runCleanCircuit(one, source);
                    const valid =
                        magnitude <= limit && (sign === 0 || magnitude !== 0n);
                    expect(result[result.length - 1]).toBe(Number(valid));
                    expect(result.subarray(0, -1)).toEqual(
                        valid
                            ? source.subarray(2049)
                            : new Uint8Array(result.length - 1),
                    );
                }
        }
    });

    it('refuses invalid circuit dimensions and a modulus outside its magnitude width', () => {
        expect(() => compileSourceCoordinateDecoding(0, 8, 3n)).toThrow();
        expect(() => compileSourceCoordinateDecoding(1, 0, 3n)).toThrow();
        expect(() => compileSourceCoordinateDecoding(1, 8, 256n)).toThrow();
        expect(() => sourceCoordinateDecodingWork(-1n, 8n)).toThrow();
    });
});
