import { describe, expect, it } from 'vitest';

import {
    sourceCiphertextBytes,
    sourceGoodKeyPhaseError,
    sourceMaximumPhase,
    sourceMessageMaximum,
    sourceMessageScale,
    sourceStatementPolynomialCount,
} from '#tests/encrypted-registration-source-model.js';
import { reductionConstructorOperands } from '#tests/security-margin/constructor-operands.js';
import { sourceRecoveryAllowance } from '#tests/security-margin/constructor-price.js';
import {
    buildPackedSourceRecoveryProgram,
    packedSourceRecoveryBounds,
} from '#tests/security-margin/packed-source-recovery.js';
import {
    auditWordProgram,
    runWordProgram,
} from '#tests/security-margin/word-program.js';

// Independently pinned auxiliary instance and source ranges. The source
// plaintext modulus is separate from the ballot's plaintext modulus.
const modulus = 257n * 101n * (1n << 20n) + 1n;
const scale = (modulus - 1n) / 769n;
const phaseError = (256n + 1n + 256n) * 64n;
const center = (value: bigint) => {
    const residue = ((value % modulus) + modulus) % modulus;
    return residue > modulus / 2n ? residue - modulus : residue;
};
const rounded = (value: bigint) =>
    value < 0n
        ? -((-value + scale / 2n) / scale)
        : (value + scale / 2n) / scale;
const product = (left: readonly bigint[], right: readonly bigint[]) =>
    left.map((_value, output) =>
        right.reduce((sum, coefficient, shift) => {
            const index = (output - shift + left.length) % left.length;
            return (
                sum + left[index] * coefficient * (shift > output ? -1n : 1n)
            );
        }, 0n),
    );
const sparse = (length: number, stride: number, offset: number) => {
    const values = Array<bigint>(length).fill(0n);
    for (let index = 0; index < 4; index++)
        values[(offset + stride * index) % length] = index < 2 ? 1n : -1n;
    return values;
};

const program = buildPackedSourceRecoveryProgram();
const programShape = auditWordProgram(program);
const runRecovery = (
    constant: bigint[],
    linear: bigint[],
    key: bigint[],
    secret: bigint[],
    errors: bigint[],
) => {
    const degree = constant.length,
        auxiliaryDegree = 8,
        stride = degree / auxiliaryDegree;
    const keyOffset = 96 * degree,
        outputOffset = keyOffset + 2 * auxiliaryDegree,
        scratchOffset = outputOffset + 32 * degree;
    const memory = new Uint8Array(scratchOffset + 32 * 4 + 128 * degree);
    const put = (offset: number, width: number, value: bigint) => {
        for (let bit = 0; bit < width; bit++)
            memory[offset + bit] = Number((value >> BigInt(bit)) & 1n);
    };
    const get = (offset: number, width: number) => {
        let value = 0n;
        for (let bit = 0; bit < width; bit++)
            value |= BigInt(memory[offset + bit]) << BigInt(bit);
        return value;
    };
    [...constant, ...linear].forEach((value, index) =>
        put(48 * index, 48, value < 0n ? (-value << 8n) + 1n : value << 8n),
    );
    for (let index = 0; index < auxiliaryDegree; index++)
        put(
            keyOffset + 2 * index,
            2,
            key[stride * index] === -1n ? 2n : key[stride * index],
        );
    const recoveryInputs = {
        input: 0n,
        key: BigInt(keyOffset),
        output: BigInt(outputOffset),
        scratch: BigInt(scratchOffset),
        degree: BigInt(degree),
        'auxiliary-degree': BigInt(auxiliaryDegree),
        stride: BigInt(stride),
        'key-half-support': 2n,
        'source-half-support': 2n,
    };
    const result = runWordProgram(program, recoveryInputs, memory, 384);
    expect(result.results.count).toBe(2n * BigInt(degree));
    for (let index = 0; index < degree; index++) {
        expect(get(outputOffset + 16 * index, 16) - 1n).toBe(secret[index]);
        expect(get(outputOffset + 16 * (degree + index), 16) - 64n).toBe(
            errors[index],
        );
    }
    const bounds = packedSourceRecoveryBounds(
        BigInt(degree),
        BigInt(auxiliaryDegree),
        4n,
    );
    expect(BigInt(memory.length)).toBe(bounds.spanBits);
    expect(result.events).toBeLessThanOrEqual(bounds.events);
    expect(result.steps).toBeLessThanOrEqual(
        programShape.maximumEventGap * (result.events + 1n),
    );
    return { memory, recoveryInputs, keyOffset, put };
};

describe('packed encrypted registration source', () => {
    it('recovers every allowed secret/error pair at both complete noise bounds', () => {
        expect(sourceMessageScale).toBe(scale);
        expect(sourceGoodKeyPhaseError).toBe(phaseError);
        expect(sourceMessageMaximum).toBe(383n);
        expect(sourceMaximumPhase).toBe(383n * scale + phaseError);
        expect(2n * phaseError).toBeLessThan(scale);
        expect(2n * sourceMaximumPhase).toBeLessThan(modulus);
        const messages = new Set<bigint>();
        for (let secret = -1n; secret <= 1n; secret++) {
            for (let error = -64n; error < 64n; error++) {
                const message = 3n * (error + 64n) + secret + 1n;
                messages.add(message);
                for (const noise of [-phaseError, -1n, 0n, 1n, phaseError]) {
                    const decoded = rounded(center(scale * message + noise));
                    expect((decoded % 3n) - 1n).toBe(secret);
                    expect(decoded / 3n - 64n).toBe(error);
                }
            }
        }
        expect(messages.size).toBe(384);
        expect(messages.has(0n)).toBe(true);
        expect(messages.has(383n)).toBe(true);
    });

    it('decodes the same source with strided and full-ring accepted ephemerals', () => {
        const recoveries: ReturnType<typeof runRecovery>[] = [];
        for (const degree of [16, 32, 64]) {
            for (const seed of [1, 7, 19]) {
                const key = sparse(degree, degree / 8, 0);
                const common = Array.from({ length: degree }, (_, index) =>
                    center(BigInt(index * 7919 + seed * 104729) ** 3n),
                );
                const keyError = common.map(
                    (_value, index) => BigInt((index + seed) % 128) - 64n,
                );
                const publicKey = product(common, key).map((value, index) =>
                    center(-value + keyError[index]),
                );
                for (const strided of [true, false]) {
                    const ephemeral = sparse(
                        degree,
                        strided ? degree / 8 : 1,
                        strided ? 0 : 1,
                    );
                    const sourceSecret = sparse(degree, 1, seed);
                    const sourceError = common.map(
                        (_value, index) =>
                            BigInt((17 * index + seed) % 128) - 64n,
                    );
                    const message = sourceSecret.map(
                        (value, index) =>
                            3n * (sourceError[index] + 64n) + value + 1n,
                    );
                    const errors = [0, 1].map((component) =>
                        common.map(
                            (_value, index) =>
                                BigInt((31 * index + component + seed) % 128) -
                                64n,
                        ),
                    );
                    const constant = product(publicKey, ephemeral).map(
                        (value, index) =>
                            center(
                                value +
                                    errors[0][index] +
                                    scale * message[index],
                            ),
                    );
                    const linear = product(common, ephemeral).map(
                        (value, index) => center(value + errors[1][index]),
                    );
                    const decodedProduct = product(linear, key);
                    for (let index = 0; index < degree; index++) {
                        const phase = center(
                            constant[index] + decodedProduct[index],
                        );
                        const decoded = rounded(phase);
                        expect((decoded % 3n) - 1n).toBe(sourceSecret[index]);
                        expect(decoded / 3n - 64n).toBe(sourceError[index]);
                        expect(
                            phase - scale * message[index],
                        ).toBeGreaterThanOrEqual(-phaseError);
                        expect(
                            phase - scale * message[index],
                        ).toBeLessThanOrEqual(phaseError);
                    }
                    recoveries.push(
                        runRecovery(
                            constant,
                            linear,
                            key,
                            sourceSecret,
                            sourceError,
                        ),
                    );
                }
            }
        }
        for (const recovery of recoveries) {
            const original = recovery.memory.slice();
            for (const record of [2n, 1n, (modulus / 2n + 1n) << 8n]) {
                recovery.memory.set(original);
                recovery.put(0, 48, record);
                expect(() =>
                    runWordProgram(
                        program,
                        recovery.recoveryInputs,
                        recovery.memory,
                        384,
                    ),
                ).toThrow();
            }
            recovery.memory.set(original);
            recovery.put(recovery.keyOffset, 2, 3n);
            expect(() =>
                runWordProgram(
                    program,
                    recovery.recoveryInputs,
                    recovery.memory,
                    384,
                ),
            ).toThrow();
            recovery.memory.set(original);
            expect(() =>
                runWordProgram(
                    program,
                    { ...recovery.recoveryInputs, 'source-half-support': 1n },
                    recovery.memory,
                    384,
                ),
            ).toThrow();
        }
    });

    it('publishes one pair and retains only its paired common operands', () => {
        expect(sourceCiphertextBytes).toBe(2n * 65536n * 6n);
        expect(sourceStatementPolynomialCount).toBe(4n);
    });

    it('fits the new literal decoder and every loop beneath the existing reduction price', () => {
        const allowance = reductionConstructorOperands.banks.sourceRecovery;
        expect(programShape.instructions).toBeLessThanOrEqual(
            allowance.instructions,
        );
        expect(programShape.registers).toBeLessThanOrEqual(allowance.registers);
        expect(programShape.maximumEventGap).toBeLessThanOrEqual(
            allowance.maximumEventGap,
        );
        for (const degree of [32768n, 65536n]) {
            const bounds = packedSourceRecoveryBounds(degree, 4096n, 256n);
            const priced = sourceRecoveryAllowance(degree);
            expect(bounds.events).toBeLessThanOrEqual(priced.events);
            expect(bounds.spanBits).toBeLessThanOrEqual(priced.spanBits);
        }
        for (let message = 0n; message < 384n; message++)
            expect((message * 171n) >> 9n).toBe(message / 3n);
    });

    it('audits both branch arms and refuses a cycle with no charged event', () => {
        expect(
            auditWordProgram({
                registers: 1,
                inputs: {},
                results: {},
                instructions: [
                    { operation: 'copy', destination: 0, left: 0n },
                    { operation: 'jump-if-zero', left: 0, branch: 3 },
                    { operation: 'add', destination: 0, left: 0, right: 1n },
                    { operation: 'halt' },
                ],
            }),
        ).toEqual({ instructions: 4n, registers: 1n, maximumEventGap: 3n });
        expect(() =>
            auditWordProgram({
                registers: 0,
                inputs: {},
                results: {},
                instructions: [{ operation: 'jump', branch: 0 }],
            }),
        ).toThrow('event-free cycle');
    });
});
