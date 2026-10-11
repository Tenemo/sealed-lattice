import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';

const reduce = (value: bigint) => ((value % 17n) + 17n) % 17n;
const power = (value: bigint, exponent: number) => {
    let result = 1n;
    for (let index = 0; index < exponent; index++)
        result = reduce(result * value);
    return result;
};

export const evaluateSelectedOpeningModel = (
    coefficients: readonly bigint[],
    indices: readonly number[],
): readonly bigint[] => {
    const length = coefficients.length;
    if (
        ![2, 4, 8, 16].includes(length) ||
        coefficients.some((value) => value < 0n || value >= 17n) ||
        indices.some(
            (index) =>
                !Number.isSafeInteger(index) || index < 0 || index >= length,
        )
    )
        throw new RangeError('Invalid transform inputs.');
    const recurse = (
        values: readonly bigint[],
        wanted: readonly number[],
        root: bigint,
    ): bigint[] => {
        if (wanted.length === 0) return [];
        if (values.length === 1) return wanted.map(() => values[0]);
        const half = values.length / 2;
        const even = wanted
            .filter((index) => index % 2 === 0)
            .map((index) => index / 2);
        const odd = wanted
            .filter((index) => index % 2 === 1)
            .map((index) => (index - 1) / 2);
        const evenValues =
            even.length === 0
                ? []
                : recurse(
                      Array.from({ length: half }, (_, index) =>
                          reduce(values[index] + values[index + half]),
                      ),
                      even,
                      reduce(root * root),
                  );
        const oddValues =
            odd.length === 0
                ? []
                : recurse(
                      Array.from({ length: half }, (_, index) =>
                          reduce(
                              (values[index] - values[index + half]) *
                                  power(root, index),
                          ),
                      ),
                      odd,
                      reduce(root * root),
                  );
        let evenPosition = 0,
            oddPosition = 0;
        return wanted.map((index) =>
            index % 2 === 0
                ? evenValues[evenPosition++]
                : oddValues[oddPosition++],
        );
    };
    return recurse(coefficients, indices, power(3n, 16 / length));
};

export const directlyEvaluateOpeningModel = (
    coefficients: readonly bigint[],
    index: number,
) => {
    const point = power(3n, (16 / coefficients.length) * index);
    return coefficients.reduceRight(
        (value, coefficient) => reduce(value * point + coefficient),
        0n,
    );
};

export const compileSelectedOpeningTransformCensus = () => {
    const proof = compileCommonAgreementDegreeCensus();
    const length = BigInt(proof.systematicSize);
    const maximumSelected = 2n * BigInt(proof.queries);
    const levels = BigInt(proof.systematicSize.toString(2).length - 1);
    let maximumBranches = 0n;
    for (let depth = 0n; depth < levels; depth++) {
        const nodes = 1n << depth;
        maximumBranches +=
            (nodes < maximumSelected ? nodes : maximumSelected) *
            (length >> (depth + 1n));
    }
    return {
        transformLength: length,
        maximumSelected,
        levels,
        fullButterflies: (length / 2n) * levels,
        maximumSelectedBranches: maximumBranches,
        maximumSelectionPairBytes:
            (1n + 2n * levels) * maximumSelected * 2n * 4n,
        maximumSelectionIndexBytes: maximumSelected * 4n,
        maximumSelectedBaseOutputBytes: maximumSelected * 16n,
        maximumSelectedExtensionOutputBytes: maximumSelected * 48n,
    };
};
