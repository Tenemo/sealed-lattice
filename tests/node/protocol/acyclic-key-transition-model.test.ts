import { describe, expect, it } from 'vitest';

import {
    compileAcyclicKeyTransitionModel,
    type AcyclicKeyTransitionKey,
    type IntegerRingElement,
} from '#tests/acyclic-key-transition-model.js';

// Independent polynomial oracle: form an ordinary product, then divide by
// X^N+1. The model instead accumulates a negacyclic convolution directly.
const polynomialProduct = (
    left: IntegerRingElement,
    right: IntegerRingElement,
): bigint[] => {
    const product = Array.from({ length: 2 * left.length - 1 }, () => 0n);
    left.forEach((coefficient, index) => {
        right.forEach((other, offset) => {
            product[index + offset] =
                product[index + offset] + coefficient * other;
        });
    });
    for (let index = product.length - 1; index >= left.length; index -= 1)
        product[index - left.length] =
            product[index - left.length] - product[index];
    return product.slice(0, left.length);
};
const maximumNorm = (value: IntegerRingElement): bigint =>
    value.reduce((maximum, coefficient) => {
        const absolute = coefficient < 0n ? -coefficient : coefficient;
        return absolute > maximum ? absolute : maximum;
    }, 0n);

describe('acyclic linear key transition algebra', () => {
    it('preserves arbitrary quadratic phases with the exact integer rounding residual', () => {
        let randomState = 0x6a09e667;
        const next = (): bigint => {
            randomState ^= randomState << 13;
            randomState ^= randomState >>> 17;
            randomState ^= randomState << 5;
            return BigInt(randomState >>> 0);
        };
        for (const parameters of [
            {
                polynomialModulusDegree: 2,
                ciphertextModulus: 17n,
                specialModulus: 3n,
                decompositionBase: 2n,
                participantCount: 3,
            },
            {
                polynomialModulusDegree: 8,
                ciphertextModulus: 12_289n,
                specialModulus: 65_537n,
                decompositionBase: 16n,
                participantCount: 10,
            },
            {
                polynomialModulusDegree: 8,
                ciphertextModulus: 257n,
                specialModulus: 17n,
                decompositionBase: 257n,
                participantCount: 20,
            },
        ]) {
            const model = compileAcyclicKeyTransitionModel(parameters);
            const { add, normalize, scale, subtract, zero } = model;
            const ring = (bound: bigint): bigint[] =>
                Array.from(
                    { length: parameters.polynomialModulusDegree },
                    () => next() % bound,
                );
            const ternary = (): bigint[] => ring(3n).map((value) => value - 1n);
            const vector = (): bigint[][] => model.gadget.map(zero);
            const bounds = model.errorBound(
                BigInt(
                    parameters.participantCount *
                        parameters.polynomialModulusDegree,
                ),
                BigInt(
                    parameters.participantCount *
                        parameters.polynomialModulusDegree,
                ),
                BigInt(parameters.participantCount),
            );
            for (let trial = 0; trial < 64; trial += 1) {
                const commonVector = model.gadget.map(() =>
                    ring(model.extendedModulus),
                );
                let sourceSecret = zero();
                let destinationSecret = zero();
                const sourceVector = vector();
                const transitionVector = vector();
                const sourceErrors = vector();
                const transitionErrors = vector();
                for (
                    let participant = 0;
                    participant < parameters.participantCount;
                    participant += 1
                ) {
                    // Include maximally correlated accepted secret/error support,
                    // as well as ordinary independent ternary model samples.
                    const small = (): bigint[] =>
                        trial < 2
                            ? zero().map(() => (trial === 0 ? 1n : -1n))
                            : ternary();
                    const source = small();
                    const destination = small();
                    const sourceError = model.gadget.map(small);
                    const transitionError = model.gadget.map(small);
                    const contribution = model.contribution(
                        commonVector,
                        source,
                        destination,
                        sourceError,
                        transitionError,
                    );
                    sourceSecret = add(sourceSecret, source);
                    destinationSecret = add(destinationSecret, destination);
                    model.gadget.forEach((_power, index) => {
                        sourceVector[index] = add(
                            sourceVector[index],
                            contribution.sourceVector[index],
                        );
                        transitionVector[index] = add(
                            transitionVector[index],
                            contribution.transitionVector[index],
                        );
                        sourceErrors[index] = add(
                            sourceErrors[index],
                            sourceError[index],
                        );
                        transitionErrors[index] = add(
                            transitionErrors[index],
                            transitionError[index],
                        );
                    });
                }
                const key: AcyclicKeyTransitionKey = {
                    commonVector,
                    sourceVector,
                    transitionVector,
                };
                // These congruences use the independently reduced products.
                model.gadget.forEach((power, index) => {
                    expect(
                        normalize(
                            add(
                                sourceVector[index],
                                polynomialProduct(
                                    sourceSecret,
                                    commonVector[index],
                                ),
                            ),
                            model.extendedModulus,
                        ),
                    ).toEqual(
                        normalize(sourceErrors[index], model.extendedModulus),
                    );
                    expect(
                        normalize(
                            subtract(
                                add(
                                    transitionVector[index],
                                    polynomialProduct(
                                        destinationSecret,
                                        commonVector[index],
                                    ),
                                ),
                                scale(
                                    sourceSecret,
                                    parameters.specialModulus * power,
                                ),
                            ),
                            model.extendedModulus,
                        ),
                    ).toEqual(
                        normalize(
                            transitionErrors[index],
                            model.extendedModulus,
                        ),
                    );
                });
                const ciphertext = [
                    ring(parameters.ciphertextModulus),
                    ring(parameters.ciphertextModulus),
                    ring(parameters.ciphertextModulus),
                ] as const;
                const output = model.apply(key, ciphertext);
                const inputPhase = add(
                    add(
                        ciphertext[0],
                        polynomialProduct(ciphertext[1], sourceSecret),
                    ),
                    polynomialProduct(
                        ciphertext[2],
                        polynomialProduct(sourceSecret, sourceSecret),
                    ),
                );
                const outputPhase = add(
                    output.constant,
                    polynomialProduct(output.linear, destinationSecret),
                );
                const actualError = subtract(outputPhase, inputPhase).map(
                    (coefficient) =>
                        model.centered(
                            coefficient,
                            parameters.ciphertextModulus,
                        ),
                );
                const predictedScaledError = add(
                    add(
                        add(
                            subtract(
                                polynomialProduct(
                                    sourceSecret,
                                    model.externalProduct(
                                        ciphertext[2],
                                        transitionErrors,
                                    ),
                                ),
                                polynomialProduct(
                                    destinationSecret,
                                    model.externalProduct(
                                        ciphertext[2],
                                        sourceErrors,
                                    ),
                                ),
                            ),
                            model.externalProduct(
                                output.transitionProduct.value,
                                transitionErrors,
                            ),
                        ),
                        subtract(
                            polynomialProduct(
                                sourceSecret,
                                output.transitionProduct.remainder,
                            ),
                            polynomialProduct(
                                destinationSecret,
                                output.sourceProduct.remainder,
                            ),
                        ),
                    ),
                    add(
                        output.constantProduct.remainder,
                        polynomialProduct(
                            destinationSecret,
                            output.linearProduct.remainder,
                        ),
                    ),
                );
                expect(
                    predictedScaledError.every(
                        (coefficient) =>
                            coefficient % parameters.specialModulus === 0n,
                    ),
                ).toBe(true);
                expect(actualError).toEqual(
                    predictedScaledError.map((coefficient) =>
                        model.centered(
                            coefficient / parameters.specialModulus,
                            parameters.ciphertextModulus,
                        ),
                    ),
                );
                expect(maximumNorm(predictedScaledError)).toBeLessThanOrEqual(
                    bounds.scaledBound,
                );
                expect(maximumNorm(actualError)).toBeLessThanOrEqual(
                    bounds.transitionErrorMaximumNormBound,
                );
                for (const product of [
                    output.sourceProduct,
                    output.transitionProduct,
                    output.constantProduct,
                    output.linearProduct,
                ])
                    expect(maximumNorm(product.remainder)).toBeLessThanOrEqual(
                        (parameters.specialModulus - 1n) / 2n,
                    );
            }
        }
    });

    it('preserves every scalar plaintext under a nontrivial two-secret transition', () => {
        const model = compileAcyclicKeyTransitionModel({
            polynomialModulusDegree: 2,
            ciphertextModulus: 12_289n,
            specialModulus: 65_537n,
            decompositionBase: 16n,
        });
        const source = [3n, -2n];
        const destination = [-1n, 4n];
        const common = model.gadget.map((_power, index) => [
            9_127n * BigInt(index + 1),
            715_831n,
        ]);
        const sourceErrors = model.gadget.map(() => [1n, -1n]);
        const transitionErrors = model.gadget.map(() => [-1n, 1n]);
        const key = model.contribution(
            common,
            source,
            destination,
            sourceErrors,
            transitionErrors,
        );
        const linear = [12_288n, 6_145n];
        const quadratic = [6_144n, 12_288n];
        const decode = (value: IntegerRingElement): bigint[] =>
            model
                .normalize(value, 12_289n)
                .map(
                    (coefficient) =>
                        ((coefficient * 17n + 6_144n) / 12_289n) % 17n,
                );
        for (let first = 0n; first < 17n; first += 1n)
            for (let second = 0n; second < 17n; second += 1n) {
                const plaintext = [first, second];
                const constant = model.subtract(
                    model.subtract(
                        model.scale(plaintext, 723n),
                        polynomialProduct(linear, source),
                    ),
                    polynomialProduct(
                        quadratic,
                        polynomialProduct(source, source),
                    ),
                );
                const output = model.apply(key, [constant, linear, quadratic]);
                expect(
                    decode(
                        model.add(
                            output.constant,
                            polynomialProduct(output.linear, destination),
                        ),
                    ),
                ).toEqual(plaintext);
            }
        const constantOnly = [12_288n, 6_145n];
        const output = model.apply(key, [
            constantOnly,
            model.zero(),
            model.zero(),
        ]);
        expect(output.constant).toEqual(constantOnly);
        expect(output.linear).toEqual(model.zero());
    });

    it('exposes a source relation if two messages to one destination reuse the common vector', () => {
        const model = compileAcyclicKeyTransitionModel({
            polynomialModulusDegree: 2,
            ciphertextModulus: 257n,
            specialModulus: 17n,
            decompositionBase: 16n,
        });
        const common = model.gadget.map(() => [19n, 31n]);
        const destination = [1n, -1n];
        const source = [1n, 1n];
        const rotatedSource = [1n, -1n];
        const errors = model.gadget.map(model.zero);
        const plainKey = model.contribution(
            common,
            source,
            destination,
            errors,
            errors,
        );
        const rotationKey = model.contribution(
            common,
            rotatedSource,
            destination,
            errors,
            errors,
        );
        const publicDifference = model.subtract(
            rotationKey.transitionVector[0],
            plainKey.transitionVector[0],
        );
        expect(
            model.normalize(publicDifference, model.extendedModulus),
        ).toEqual(model.normalize([0n, -34n], model.extendedModulus));
        // The destination secret cancels from public bytes. Distinct incoming
        // plaintext relations therefore require independent common vectors.
        expect(
            publicDifference.map(
                (value) => model.centered(value, model.extendedModulus) / 17n,
            ),
        ).toEqual(model.subtract(rotatedSource, source));
    });
});
