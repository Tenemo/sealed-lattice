import assert from 'node:assert/strict';

import { evaluateOddPolynomialBlocks } from '#tests/odd-polynomial-block-model.js';

export type BfvPlaintextPurpose =
    'comparison-input-offset' | 'comparison-constant' | 'ranking-constant';

export const evaluateFixedModulusBfvRanking = <Value>(
    inputs: readonly Value[],
    optionCount: number,
    comparisonBlockWidth: number,
    operations: Readonly<{
        add: (left: Value, right: Value) => Value;
        multiply: (left: Value, right: Value) => Value;
        multiplyScalar: (value: Value, exponent: number) => Value;
        multiplyPlaintext: (value: Value, exponent: number) => Value;
        addPlaintext: (value: Value, purpose: BfvPlaintextPurpose) => Value;
        rotate: (value: Value) => Value;
    }>,
) => {
    assert.ok(inputs.length >= 3 && inputs.length <= 20);
    assert.ok(
        Number.isSafeInteger(optionCount) &&
            optionCount >= 2 &&
            optionCount <= 20,
    );
    const sum = (values: readonly Value[]): Value => {
        assert.ok(values.length > 0);
        return values.slice(1).reduce(operations.add, values[0]);
    };
    const input = operations.addPlaintext(
        sum(inputs),
        'comparison-input-offset',
    );
    const comparison = operations.addPlaintext(
        evaluateOddPolynomialBlocks(
            input,
            2 * (10 - 1) * inputs.length + 1,
            comparisonBlockWidth,
            {
                add: operations.add,
                multiply: operations.multiply,
                weight: operations.multiplyScalar,
            },
        ),
        'comparison-constant',
    );
    let shifted = comparison;
    let rank = comparison;
    const windowWidth = 2 ** Math.ceil(Math.log2(optionCount));
    for (let offset = 1; offset < windowWidth; offset++) {
        shifted = operations.rotate(shifted);
        rank = operations.add(rank, shifted);
    }
    const cache = new Map<number, Value>([[1, rank]]);
    const power = (exponent: number): Value => {
        const existing = cache.get(exponent);
        if (existing !== undefined) return existing;
        const value = operations.multiply(
            power(Math.floor(exponent / 2)),
            power(Math.ceil(exponent / 2)),
        );
        cache.set(exponent, value);
        return value;
    };
    const result = operations.addPlaintext(
        sum(
            Array.from({ length: optionCount - 1 }, (_, index) =>
                operations.multiplyPlaintext(power(index + 1), index + 1),
            ),
        ),
        'ranking-constant',
    );
    return { comparison, result };
};
