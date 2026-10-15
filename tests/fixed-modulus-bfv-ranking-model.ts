import assert from 'node:assert/strict';

import { evaluateOddPolynomialBlocks } from '#tests/odd-polynomial-block-model.js';

export type PlaintextPurpose =
    | 'comparison-input-offset'
    | 'comparison-constant'
    | 'ranking-constant'
    | 'padding-correction';
export const evaluateFixedModulusBfvRanking = <Value>(
    inputs: readonly Value[],
    options: number,
    comparisonBlockWidth: number,
    operations: Readonly<{
        add: (left: Value, right: Value) => Value;
        multiply: (left: Value, right: Value) => Value;
        multiplyScalar: (value: Value, exponent: number) => Value;
        multiplyPlaintext: (value: Value, exponent: number) => Value;
        addPlaintext: (value: Value, purpose: PlaintextPurpose) => Value;
        rotate: (value: Value) => Value;
    }>,
    topCount = options,
) => {
    assert(
        inputs.length >= 3 &&
            inputs.length <= 20 &&
            options >= 2 &&
            options <= 20,
    );
    assert(Number.isInteger(topCount) && topCount >= 1 && topCount <= options);
    const sum = (values: readonly Value[]) =>
        values.slice(1).reduce(operations.add, values[0]);
    const input = operations.addPlaintext(
        sum(inputs),
        'comparison-input-offset',
    );
    const comparison = operations.addPlaintext(
        evaluateOddPolynomialBlocks(
            input,
            18 * inputs.length + 1,
            comparisonBlockWidth,
            {
                add: operations.add,
                multiply: operations.multiply,
                weight: operations.multiplyScalar,
            },
        ),
        'comparison-constant',
    );
    const window = 2 ** Math.ceil(Math.log2(options));
    const sweep = (value: Value, length = window) => {
        let result = value,
            shifted = value;
        for (let offset = 1; offset < length; offset++) {
            shifted = operations.rotate(shifted);
            result = operations.add(result, shifted);
        }
        return result;
    };
    const rank = sweep(
        operations.multiplyPlaintext(sweep(comparison), -1),
        topCount,
    );
    const cache = new Map<number, Value>([[1, rank]]);
    const power = (exponent: number): Value => {
        if (cache.has(exponent)) return cache.get(exponent)!;
        const value = operations.multiply(
            power(Math.floor(exponent / 2)),
            power(Math.ceil(exponent / 2)),
        );
        cache.set(exponent, value);
        return value;
    };
    const result = operations.addPlaintext(
        operations.addPlaintext(
            sum(
                Array.from({ length: options - 1 }, (_, index) =>
                    operations.multiplyPlaintext(power(index + 1), index + 1),
                ),
            ),
            'ranking-constant',
        ),
        'padding-correction',
    );
    return { comparison, result };
};
