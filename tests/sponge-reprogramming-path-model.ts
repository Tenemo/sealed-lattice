const absorb = (permutation: readonly number[], blocks: readonly number[]) => {
    let state = 0;
    const inputs: number[] = [];
    for (const block of blocks) {
        const input = state ^ block;
        inputs.push(input);
        state = permutation[input];
    }
    return { inputs, state };
};

export const swapFinalSpongeOutput = (
    permutation: readonly number[],
    rateBits: number,
    blocks: readonly number[],
    targetOutput: number,
) => {
    const size = permutation.length;
    if (
        size < 4 ||
        size > 32 ||
        (size & (size - 1)) !== 0 ||
        new Set(permutation).size !== size ||
        permutation.some(
            (value) => !Number.isInteger(value) || value < 0 || value >= size,
        ) ||
        !Number.isInteger(rateBits) ||
        rateBits < 1 ||
        2 ** rateBits >= size ||
        blocks.length === 0 ||
        blocks.length > 8 ||
        blocks.some(
            (value) =>
                !Number.isInteger(value) || value < 0 || value >= 2 ** rateBits,
        ) ||
        !Number.isInteger(targetOutput) ||
        targetOutput < 0 ||
        targetOutput >= size
    )
        throw new RangeError('Invalid bounded sponge-path case.');
    const original = absorb(permutation, blocks);
    const finalInput = original.inputs[original.inputs.length - 1];
    const otherInput = permutation.indexOf(targetOutput);
    const changed = [...permutation];
    [changed[finalInput], changed[otherInput]] = [
        changed[otherInput],
        changed[finalInput],
    ];
    const prefix = original.inputs.slice(0, -1);
    return {
        originalInputs: original.inputs,
        changedPermutation: changed,
        changedOutput: absorb(changed, blocks).state,
        finalInputOccursInPrefix: prefix.includes(finalInput),
        otherInputOccursInPrefix: prefix.includes(otherInput),
    };
};

export const splitSaltCollision = () => {
    // Two salt fragments occupy disjoint positions of successive rate blocks.
    // The permutation swaps those rate bits and is a bijection on full states.
    const permutation = [0, 2, 1, 3, 4, 6, 5, 7];
    return {
        permutation,
        outputs: [0, 1].flatMap((first) =>
            [0, 1].map(
                (second) => absorb(permutation, [2 * first, second]).state,
            ),
        ),
    };
};
