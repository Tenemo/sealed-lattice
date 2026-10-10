// Independently maintained tree::RECOMPUTED_LEVELS operand.
const maximumRecomputedMerkleLevels = 4;

const shape = (length: number) => {
    if (
        !Number.isSafeInteger(length) ||
        length < 2 ||
        length > 2 ** 30 ||
        !Number.isInteger(Math.log2(length))
    )
        throw new RangeError('Invalid Merkle tree length.');
    const omittedLevels = Math.min(
        maximumRecomputedMerkleLevels,
        Math.log2(length) - 1,
    );
    return { omittedLevels, blockLeaves: 2 ** (omittedLevels + 1) };
};

const work = (
    openedLeaves: number,
    blocks: number,
    omittedLevels: number,
    blockLeaves: number,
    leavesForgotten: boolean,
) => {
    const restoredLeaves = leavesForgotten ? blocks * blockLeaves : 0;
    const restoredNodes = leavesForgotten ? blocks * (blockLeaves - 1) : 0;
    const reconstructedNodes = blocks * (blockLeaves - 2);
    return {
        openedLeaves,
        blocks,
        omittedLevels,
        blockLeaves,
        restoredLeaves,
        restoredNodes,
        reconstructedNodes,
        nodeHashes: restoredNodes + reconstructedNodes,
        // Restoring a forgotten block hashes every leaf again. Writing each
        // requested record independently re-expands its original leaf salt.
        saltExpansions: restoredLeaves + openedLeaves,
        leafPrefixInitializations: leavesForgotten ? blocks : 0,
        nodePrefixInitializations:
            blocks * omittedLevels +
            (leavesForgotten ? blocks * (omittedLevels + 1) : 0),
    };
};

// Sorted openings visit each aligned block once. The node cache rebuilds
// every internal node below its kept root, even when only one is transmitted.
export const merkleOpeningWork = (
    length: number,
    indices: readonly number[],
    leavesForgotten: boolean,
) => {
    const { omittedLevels, blockLeaves } = shape(length);
    if (
        indices.some(
            (index, position) =>
                !Number.isSafeInteger(index) ||
                index < 0 ||
                index >= length ||
                (position > 0 && index <= indices[position - 1]),
        )
    )
        throw new RangeError('Invalid canonical opening indices.');
    const blocks = new Set(
        indices.map((index) => Math.floor(index / blockLeaves)),
    ).size;
    return work(
        indices.length,
        blocks,
        omittedLevels,
        blockLeaves,
        leavesForgotten,
    );
};

export const maximumMerkleOpeningWork = (
    length: number,
    maximumOpenedLeaves: number,
    leavesForgotten: boolean,
) => {
    const { omittedLevels, blockLeaves } = shape(length);
    if (
        !Number.isSafeInteger(maximumOpenedLeaves) ||
        maximumOpenedLeaves < 0 ||
        maximumOpenedLeaves > length
    )
        throw new RangeError('Invalid opening count.');
    return work(
        maximumOpenedLeaves,
        Math.min(maximumOpenedLeaves, length / blockLeaves),
        omittedLevels,
        blockLeaves,
        leavesForgotten,
    );
};
