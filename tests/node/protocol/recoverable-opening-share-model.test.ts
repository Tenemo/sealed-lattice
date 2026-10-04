import { describe, expect, it } from 'vitest';

import {
    compileOpeningShareResources,
    createOpeningShareExample,
    decodeOpeningShare,
    deriveOpeningShareWitness,
    encodeOpeningShare,
    openingDifference,
    openingProduct,
    openingShareParameters,
    openingShareSeparation,
} from '#tests/recoverable-opening-share-model.js';
import { registrationIntegerRows } from '#tests/registration-key-relation-model.js';

const abs = (value: bigint) => (value < 0n ? -value : value);
const center = (value: bigint, modulus: bigint) => {
    const reduced = ((value % modulus) + modulus) % modulus;
    return reduced > modulus / 2n ? reduced - modulus : reduced;
};
// An independent coefficient-by-coefficient matrix view, including the sign
// of terms crossing X^degree = -1, checks the sparse product implementation.
const matrixProduct = (left: readonly bigint[], right: readonly bigint[]) =>
    left.map((_value, output) =>
        right.reduce(
            (total, coefficient, input) =>
                total +
                coefficient *
                    left[(output + left.length - input) % left.length] *
                    (output < input ? -1n : 1n),
            0n,
        ),
    );

describe('public opening-share relation model', () => {
    it('uses the exact negacyclic product including negative wrap', () => {
        expect(openingProduct([0n, 0n, 0n, 1n], [0n, 1n, 0n, 0n])).toEqual([
            -1n,
            0n,
            0n,
            0n,
        ]);
        for (const [left, right] of [
            [
                [2n, -7n, 0n, 13n],
                [-1n, 0n, 1n, 2n],
            ],
            [
                [0n, 3n, -5n, -11n],
                [1n, -1n, 0n, 1n],
            ],
        ])
            expect(openingProduct(left, right)).toEqual(
                matrixProduct(left, right),
            );
    });

    it('derives unique decoding and exact integer lifting for every roster size', () => {
        for (let participants = 3; participants <= 20; participants++) {
            const parameters = openingShareParameters(participants);
            expect(parameters.honestError).toBe((2n * 256n + 1n) * 64n);
            expect(parameters.recoveryErrorBits).toBe(17);
            expect(parameters.recoveryErrorRadius).toBe(1n << 16n);
            expect(parameters.modulus).toBe(
                parameters.scale * parameters.proofPrime,
            );
            expect(2n * parameters.maximumShare).toBeLessThan(
                parameters.proofPrime,
            );
            expect(
                parameters.honestError + parameters.recoveryErrorRadius,
            ).toBeLessThan(parameters.scale);
            expect(parameters.honestQuotient).toBeLessThan(129n);
            expect(parameters.honestCarry).toBeLessThan(387n);
            expect(parameters.maximumLimbResidual).toBeLessThan(
                parameters.proofPrime,
            );
            expect(
                parameters.proofPrime / parameters.radix,
            ).toBeGreaterThanOrEqual(parameters.signedWordRadius);
        }
    });

    it.each([
        [4, 0, 0, 0],
        [4, 1, 1, 1],
        [4, 2, 0, 2],
        [4, 3, 1, 3],
        [10, 9, 0, 1],
        [20, 19, 1, 2],
    ] as const)(
        'decrypts original keys at profile %i recipient %i and seed %i using tape %i',
        (participants, recipient, seedBit, sequence) => {
            const example = createOpeningShareExample(
                participants,
                recipient,
                seedBit,
                sequence,
            );
            const { parameters } = example;
            const messages = example.packages.map((source) =>
                decodeOpeningShare(
                    participants,
                    encodeOpeningShare(
                        participants,
                        source.message,
                        example.degree,
                    ),
                    example.degree,
                ),
            );
            const witness = deriveOpeningShareWitness(example, messages);
            expect(witness[0].errors).toEqual(example.keyErrors);
            const keyRows = registrationIntegerRows(
                example.common,
                example.publicKey,
                example.secret,
                witness[0].errors,
                witness[0].quotients,
                witness[0].carries,
                parameters.modulus,
                parameters.radix,
            );
            expect(keyRows.every((value) => value === 0n)).toBe(true);
            expect(example.secret.filter((value) => value === 0n)).toHaveLength(
                example.degree - 256,
            );
            for (const [index, source] of example.packages.entries()) {
                const product = openingProduct(source.linear, example.secret);
                const phase = product.map((value, position) =>
                    center(
                        value + source.constant[position],
                        parameters.modulus,
                    ),
                );
                const plaintext = phase.map(
                    (value) =>
                        (value < 0n ? -1n : 1n) *
                        ((abs(value) + parameters.scale / 2n) /
                            parameters.scale),
                );
                expect(plaintext).toEqual(source.message);
                const keyNoise = openingProduct(
                    example.keyErrors,
                    source.ephemeral,
                );
                const receiverNoise = openingProduct(
                    source.errors[1],
                    example.secret,
                );
                expect(witness[index + 1].errors).toEqual(
                    keyNoise.map(
                        (value, position) =>
                            value +
                            receiverNoise[position] +
                            source.errors[0][position],
                    ),
                );
                expect(
                    witness[index + 1].errors.every(
                        (value) => abs(value) <= parameters.honestError,
                    ),
                ).toBe(true);
                const difference = openingDifference(
                    source.constant,
                    messages[index],
                    parameters,
                );
                const rows = registrationIntegerRows(
                    source.linear,
                    difference,
                    example.secret,
                    witness[index + 1].errors,
                    witness[index + 1].quotients,
                    witness[index + 1].carries,
                    parameters.modulus,
                    parameters.radix,
                );
                expect(rows.every((value) => value === 0n)).toBe(true);
            }
        },
    );

    it('keeps the later-public seed independent of sharing and encryption fixture tapes', () => {
        const first = createOpeningShareExample(4, 2, 0, 3);
        const second = createOpeningShareExample(4, 2, 1, 3);
        expect(first.common).toEqual(second.common);
        expect(first.publicKey).toEqual(second.publicKey);
        for (const [index, source] of first.packages.entries()) {
            expect(source.coefficients).toEqual(
                second.packages[index].coefficients,
            );
            expect(source.ephemeral).toEqual(second.packages[index].ephemeral);
            expect(source.errors).toEqual(second.packages[index].errors);
            expect(source.linear).toEqual(second.packages[index].linear);
            expect(source.constant).not.toEqual(
                second.packages[index].constant,
            );
        }
    });

    it('makes a changed public share impossible for any valid bounded recipient-key witness', () => {
        const example = createOpeningShareExample(4, 0, 1, 0);
        const messages = example.packages.map((source) => [...source.message]);
        deriveOpeningShareWitness(example, messages);
        const original = messages[0][0];
        messages[0][0] += 1n;
        // The false claim is still canonical, under the same real public
        // key and original ciphertext. It is not a parser/context negative.
        expect(
            decodeOpeningShare(
                4,
                encodeOpeningShare(4, messages[0], example.degree),
                example.degree,
            ),
        ).toEqual(messages[0]);
        expect(() => deriveOpeningShareWitness(example, messages)).toThrow(
            'noise',
        );
        const gap = openingShareSeparation(
            example.parameters,
            messages[0][0] - original,
        );
        expect(gap.distance).toBe(example.parameters.scale);
        expect(gap.distance).toBeGreaterThan(gap.maximumNoiseDifference);
        // For every other nonzero difference allowed by both public ranges,
        // the multiple-of-scale distance is at least one scale as well.
        for (const difference of [
            -2n * example.parameters.maximumShare,
            -1n,
            1n,
            2n * example.parameters.maximumShare,
        ]) {
            const separation = openingShareSeparation(
                example.parameters,
                difference,
            );
            expect(separation.distance).toBeGreaterThan(
                separation.maximumNoiseDifference,
            );
        }
    });

    it('needs the public range to exclude real modular share aliases', () => {
        const example = createOpeningShareExample(4, 0, 0, 0);
        const original = example.packages[0].message;
        for (const sign of [-1n, 1n]) {
            const alias = [...original];
            alias[0] += sign * example.parameters.proofPrime;
            expect(
                openingDifference(
                    example.packages[0].constant,
                    alias,
                    example.parameters,
                ),
            ).toEqual(
                openingDifference(
                    example.packages[0].constant,
                    original,
                    example.parameters,
                ),
            );
            expect(() => encodeOpeningShare(4, alias, example.degree)).toThrow(
                'range',
            );
            expect(
                openingShareSeparation(
                    example.parameters,
                    sign * example.parameters.proofPrime,
                ).distance,
            ).toBe(0n);
        }
    });

    it('reaches the honest negative noise endpoint that needs seventeen signed bits', () => {
        const original = createOpeningShareExample(4, 0, 0, 0);
        const degree = 256;
        const secret = Array.from({ length: degree }, (_unused, position) =>
            position < 128 ? 1n : -1n,
        );
        const common = Array.from({ length: degree }, (_unused, position) =>
            BigInt(position),
        );
        const keyErrors = Array<bigint>(degree).fill(-64n);
        const publicKey = matrixProduct(common, secret).map((value) =>
            center(-value - 64n, original.parameters.modulus),
        );
        const zero = Array<bigint>(degree).fill(0n);
        const source = {
            seed: zero,
            coefficients: [zero],
            message: zero,
            ephemeral: secret,
            errors: [keyErrors, keyErrors],
            constant: matrixProduct(publicKey, secret).map((value) =>
                center(value - 64n, original.parameters.modulus),
            ),
            linear: matrixProduct(common, secret).map((value) =>
                center(value - 64n, original.parameters.modulus),
            ),
        };
        const example = {
            ...original,
            degree,
            common,
            publicKey,
            secret,
            keyErrors,
            packages: [source, source],
        };
        const witness = deriveOpeningShareWitness(example, [zero, zero]);
        expect(witness[1].errors[127]).toBe(-32832n);
        expect(witness[1].errors[127]).toBeLessThan(-(1n << 15n));
        expect(witness[1].errors[127]).toBeGreaterThanOrEqual(-(1n << 16n));
    });

    it('does not require uniqueness of the registered secret to fix the plaintext', () => {
        const original = createOpeningShareExample(4, 0, 1, 1);
        // A synthetic zero common/key has many bounded valid secrets. This
        // checks the conditional plaintext lemma, not the production sampler.
        const example = {
            ...original,
            common: Array<bigint>(original.degree).fill(0n),
            publicKey: Array<bigint>(original.degree).fill(0n),
            keyErrors: Array<bigint>(original.degree).fill(0n),
            packages: original.packages.map((source) => ({
                ...source,
                constant: source.message.map((value, index) =>
                    center(
                        original.parameters.scale * value +
                            source.errors[0][index],
                        original.parameters.modulus,
                    ),
                ),
                linear: [...source.errors[1]],
            })),
        };
        const other = [...example.secret];
        const positive = other.indexOf(1n);
        const negative = other.indexOf(-1n);
        [other[positive], other[negative]] = [other[negative], other[positive]];
        const messages = example.packages.map((source) => source.message);
        expect(deriveOpeningShareWitness(example, messages)).toHaveLength(3);
        expect(
            deriveOpeningShareWitness(example, messages, other),
        ).toHaveLength(3);
        const wrong = messages.map((message) => [...message]);
        wrong[0][0] += 1n;
        expect(() => deriveOpeningShareWitness(example, wrong, other)).toThrow(
            'noise',
        );
    });

    it('parses exact signed shares at the permitted endpoints and refuses aliases and malformed encodings', () => {
        const parameters = openingShareParameters(4);
        const degree = 512;
        const values = Array<bigint>(degree).fill(0n);
        values[1] = parameters.maximumShare;
        values[degree - 1] = -parameters.maximumShare;
        const bytes = encodeOpeningShare(4, values, degree);
        expect(decodeOpeningShare(4, bytes, degree)).toEqual(values);
        for (const sign of [1, 2]) {
            const changed = bytes.slice();
            changed[0] = sign;
            expect(() => decodeOpeningShare(4, changed, degree)).toThrow(
                'Noncanonical',
            );
        }
        for (const value of [
            parameters.maximumShare + 1n,
            -parameters.maximumShare - 1n,
        ]) {
            const changed = [...values];
            changed[0] = value;
            expect(() => encodeOpeningShare(4, changed, degree)).toThrow(
                'range',
            );
        }
        const tooLarge = bytes.slice();
        tooLarge.fill(255, 1, parameters.shareCoefficientBytes);
        expect(() => decodeOpeningShare(4, tooLarge, degree)).toThrow('range');
        expect(() => decodeOpeningShare(4, bytes.subarray(1), degree)).toThrow(
            'length',
        );
        expect(() =>
            decodeOpeningShare(4, new Uint8Array([...bytes, 0]), degree),
        ).toThrow('length');
    });

    it('counts one registration equation and all selected recovery equations without private plaintext columns', () => {
        const bounded = compileOpeningShareResources(4, 256n);
        expect(bounded.wordColumns).toBe(9);
        expect(bounded.booleanColumns).toBe(4);
        expect(bounded.lookupEntries).toBe(10);
        expect(bounded.affineRows).toBe(1538n);
        expect(bounded.publicShareBytes).toBe(2n * 256n * 15n);
        const complete = compileOpeningShareResources(10, 65536n);
        expect(complete.wordColumns).toBe(15);
        expect(complete.booleanColumns).toBe(6);
        expect(complete.lookupEntries).toBe(16);
        expect(complete.affineRows).toBe(10n * 65536n + 2n);
        expect(() => compileOpeningShareResources(4, 128n)).toThrow('degree');
    });
});
