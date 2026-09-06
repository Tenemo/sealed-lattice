import assert from 'node:assert/strict';

export const evaluateOddPolynomialBlocks = <Value>(
    variable: Value,
    maximumDegree: number,
    blockWidth: number,
    operations: Readonly<{
        add: (left: Value, right: Value) => Value;
        multiply: (left: Value, right: Value) => Value;
        weight: (power: Value, exponent: number) => Value;
    }>,
): Value => {
    assert.ok(
        Number.isSafeInteger(maximumDegree) &&
            maximumDegree > 0 &&
            maximumDegree % 2 === 1,
    );
    assert.ok(
        Number.isSafeInteger(blockWidth) &&
            blockWidth >= 2 &&
            Number.isInteger(Math.log2(blockWidth)),
    );
    const cache = new Map<number, Value>([[1, variable]]);
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
    const blockCount = Math.ceil((maximumDegree + 1) / blockWidth);
    const blocks = Array.from({ length: blockCount }, (_, block) => {
        const last = Math.min(
            blockWidth - 1,
            maximumDegree - block * blockWidth,
        );
        const terms = Array.from({ length: (last + 1) / 2 }, (_unused, index) =>
            operations.weight(
                power(2 * index + 1),
                block * blockWidth + 2 * index + 1,
            ),
        );
        return terms
            .slice(1)
            .reduce((left, right) => operations.add(left, right), terms[0]);
    });
    const combine = (offset: number, length: number): Value | undefined => {
        if (offset >= blockCount) return undefined;
        if (length === 1) return blocks[offset];
        const lower = combine(offset, length / 2);
        const upper = combine(offset + length / 2, length / 2);
        assert.ok(lower !== undefined);
        return upper === undefined
            ? lower
            : operations.add(
                  lower,
                  operations.multiply(power((blockWidth * length) / 2), upper),
              );
    };
    const result = combine(0, 2 ** Math.ceil(Math.log2(blockCount)));
    assert.ok(result !== undefined);
    return result;
};
