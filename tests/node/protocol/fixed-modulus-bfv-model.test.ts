import { describe, expect, it } from 'vitest';

import {
    compileFixedModulusBfvCensus,
    createFixedModulusBfvNoiseModel,
    verifyProthCertificate,
} from '#tests/fixed-modulus-bfv-model.js';

type Polynomial = readonly bigint[];
const degree = 8;
const modulo = (value: bigint, modulus: bigint): bigint =>
    ((value % modulus) + modulus) % modulus;
const centered = (value: bigint, modulus: bigint): bigint => {
    const residue = modulo(value, modulus);
    return residue > modulus / 2n ? residue - modulus : residue;
};
const zero = (): bigint[] => Array.from({ length: degree }, () => 0n);
const add = (left: Polynomial, right: Polynomial): bigint[] =>
    left.map((value, index) => value + right[index]);
const scale = (value: Polynomial, factor: bigint): bigint[] =>
    value.map((coefficient) => coefficient * factor);
const product = (left: Polynomial, right: Polynomial): bigint[] => {
    const result = zero();
    // Form the unreduced ordinary product first, then divide by X^8+1.
    const ordinary = Array.from({ length: 2 * degree - 1 }, () => 0n);
    left.forEach((value, index) =>
        right.forEach((other, offset) => {
            ordinary[index + offset] += value * other;
        }),
    );
    ordinary.forEach((value, index) => {
        result[index % degree] += index < degree ? value : -value;
    });
    return result;
};
const normalize = (value: Polynomial, modulus: bigint): bigint[] =>
    value.map((coefficient) => centered(coefficient, modulus));
const absolute = (value: bigint): bigint => (value < 0n ? -value : value);
const maximumNorm = (value: Polynomial): bigint =>
    value.reduce(
        (maximum, coefficient) =>
            absolute(coefficient) > maximum ? absolute(coefficient) : maximum,
        0n,
    );
const round = (numerator: bigint, denominator: bigint): bigint =>
    numerator < 0n
        ? -((-numerator + denominator / 2n) / denominator)
        : (numerator + denominator / 2n) / denominator;

describe('fixed-modulus BFV noise', () => {
    it('certifies the candidate primes and preserves the full ranking decoding margin', () => {
        const census = compileFixedModulusBfvCensus();
        expect(census.ciphertextModulus.toString(2)).toHaveLength(864);
        expect(census.releaseModulus.toString(2)).toHaveLength(192);
        expect(census.gadgetLength).toBe(6n);
        expect(census.comparisonDepth).toBe(8);
        expect(census.rankingDepth).toBe(12);
        expect(census.releaseCorrect).toBe(true);
        expect(census.jointStatisticalBoundHolds).toBe(true);
        expect(census.publicKeyCorpusBytes).toBe(10n * 4n * 6n * 65536n * 108n);
        expect(() => verifyProthCertificate(9n, 4, 2n)).toThrow(); // 145 is composite.
        expect(() =>
            verifyProthCertificate(65537n * 65319n, 832, 1n),
        ).toThrow();
    });

    it('bounds independently evaluated products with dense correlated extreme errors', () => {
        const plaintextModulus = 17n;
        const ciphertextModulus = plaintextModulus * (1n << 112n) + 1n;
        const delta = (ciphertextModulus - 1n) / plaintextModulus;
        const gadgetBase = 16n;
        const model = createFixedModulusBfvNoiseModel({
            participantCount: 3n,
            polynomialDegree: BigInt(degree),
            plaintextSubringDegree: BigInt(degree / 2),
            plaintextModulus,
            ciphertextModulus,
            secretSupportWeight: 2n,
            errorBound: 64n,
            gadgetBase,
        });
        let randomState = 0x6a09e667f3bcc909n;
        const random = (): bigint =>
            (randomState =
                (randomState * 6364136223846793005n + 1442695040888963407n) &
                ((1n << 64n) - 1n));
        const sparse = (): bigint[] => {
            const value = zero();
            const first = Number(random() % BigInt(degree));
            const second =
                (first + 1 + Number(random() % BigInt(degree - 1))) % degree;
            value[first] = 1n;
            value[second] = -1n;
            return value;
        };
        const gadget: bigint[] = [];
        for (let power = 1n; power < ciphertextModulus; power *= gadgetBase)
            gadget.push(power);
        const external = (
            value: Polynomial,
            key: readonly Polynomial[],
        ): bigint[] =>
            gadget.reduce(
                (sum, power, index) =>
                    add(
                        sum,
                        product(
                            value.map(
                                (coefficient) =>
                                    (modulo(coefficient, ciphertextModulus) /
                                        power) %
                                    gadgetBase,
                            ),
                            key[index],
                        ),
                    ),
                zero(),
            );
        let observedNonzeroError = false;
        for (let trial = 0; trial < 32; trial++) {
            const secret = add(add(sparse(), sparse()), sparse());
            const auxiliary = add(add(sparse(), sparse()), sparse());
            const common = (): bigint[][] =>
                gadget.map(() =>
                    zero().map(() =>
                        centered(
                            (random() * ciphertextModulus) / (1n << 64n),
                            ciphertextModulus,
                        ),
                    ),
                );
            const firstCommon = common();
            const secondCommon = common();
            const errors = Array.from({ length: 3 }, () =>
                gadget.map(() =>
                    zero().map(
                        () =>
                            3n *
                            (trial === 0
                                ? 63n
                                : trial === 1
                                  ? -64n
                                  : (random() % 128n) - 64n),
                    ),
                ),
            );
            const publicKey = firstCommon.map((value, index) =>
                normalize(
                    add(scale(product(secret, value), -1n), errors[0][index]),
                    ciphertextModulus,
                ),
            );
            const transition = firstCommon.map((value, index) =>
                normalize(
                    add(
                        add(
                            scale(product(auxiliary, value), -1n),
                            scale(secret, gadget[index]),
                        ),
                        errors[1][index],
                    ),
                    ciphertextModulus,
                ),
            );
            const relinearization = secondCommon.map((value, index) =>
                normalize(
                    add(
                        add(
                            scale(product(secret, value), -1n),
                            scale(auxiliary, -gadget[index]),
                        ),
                        errors[2][index],
                    ),
                    ciphertextModulus,
                ),
            );
            const encrypt = () => {
                const message = zero().map((_unused, index) =>
                    index % 2 === 0
                        ? (random() % plaintextModulus) - plaintextModulus / 2n
                        : 0n,
                );
                const ephemeral = sparse();
                const error = (): bigint[] =>
                    zero().map(() =>
                        trial === 0
                            ? 63n
                            : trial === 1
                              ? -64n
                              : (random() % 128n) - 64n,
                    );
                const constant = normalize(
                    add(
                        add(
                            product(publicKey[0], ephemeral),
                            scale(message, delta),
                        ),
                        error(),
                    ),
                    ciphertextModulus,
                );
                const linear = normalize(
                    add(product(firstCommon[0], ephemeral), error()),
                    ciphertextModulus,
                );
                return { message, constant, linear };
            };
            const left = encrypt();
            const right = encrypt();
            const tensor = [
                product(left.constant, right.constant),
                product(left.constant, right.linear),
                product(left.linear, right.constant),
                product(left.linear, right.linear),
            ].map((value) =>
                normalize(
                    value.map((coefficient) =>
                        round(
                            plaintextModulus * coefficient,
                            ciphertextModulus,
                        ),
                    ),
                    ciphertextModulus,
                ),
            );
            const mixed = normalize(
                external(tensor[3], publicKey),
                ciphertextModulus,
            );
            const constant = normalize(
                add(tensor[0], external(mixed, relinearization)),
                ciphertextModulus,
            );
            const linear = normalize(
                add(
                    add(
                        add(tensor[1], tensor[2]),
                        external(tensor[3], transition),
                    ),
                    external(mixed, secondCommon),
                ),
                ciphertextModulus,
            );
            const phase = normalize(
                add(constant, product(linear, secret)),
                ciphertextModulus,
            );
            const expectedMessage = normalize(
                product(left.message, right.message),
                plaintextModulus,
            );
            const observedError = maximumNorm(
                normalize(
                    add(phase, scale(expectedMessage, -delta)),
                    ciphertextModulus,
                ),
            );
            const bound = model.multiply(model.fresh, model.fresh);
            expect(observedError).toBeLessThanOrEqual(bound.error);
            observedNonzeroError ||= observedError > 0n;
            expect(
                phase.map((coefficient) =>
                    modulo(
                        round(
                            plaintextModulus * coefficient,
                            ciphertextModulus,
                        ),
                        plaintextModulus,
                    ),
                ),
            ).toEqual(
                expectedMessage.map((coefficient) =>
                    modulo(coefficient, plaintextModulus),
                ),
            );
        }
        expect(observedNonzeroError).toBe(true);
    });
});
