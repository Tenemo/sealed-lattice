import assert from 'node:assert/strict';

// Keccak-f[1600]: 24 rounds, with one chi product at each state bit.
export const shakePermutationGateCharge = 24n * 1600n;

// FIPS 202 sections 5.2 and 6.2: SHAKE appends four domain bits and
// pad10*1, then reads the initial squeeze block before another permutation.
// Zero-output XOR queries are identities and are omitted from this schedule.
export const shakeQueryPermutations = (
    inputBits: bigint,
    outputBits: bigint,
    rateBits: 1088n | 1344n,
) => {
    assert.ok(inputBits >= 0n && outputBits >= 1n);
    const ceiling = (bits: bigint) => (bits + rateBits - 1n) / rateBits;
    return ceiling(inputBits + 6n) + ceiling(outputBits) - 1n;
};

// A full coherent circuit has this many permutation slots even when a slot
// is controlled by a low-probability branch. Input and output maxima may be
// on different branches. Their rectangular envelope costs 2*p-1, not p.
export const fullCircuitQueryEnvelope = (
    permutationSlots: bigint,
    rateBits: 1088n | 1344n,
) => {
    assert.ok(permutationSlots >= 1n);
    return {
        inputCapacity: rateBits * permutationSlots - 6n,
        outputCapacity: rateBits * permutationSlots,
        maximumLengthPermutations: 2n * permutationSlots - 1n,
    };
};

// One classical fixed-input XOF reader and its cursor clones, sharing one
// prefix cache. Input absorption is charged once at this root; sharing an
// unfinished input hash between DIFFERENT inputs is outside this model.
// The effective stream stays unchanged, and hidden prefetch must commute
// with intervening oracle operations. This is a reduction adapter, not a
// change to the participant's memory plan or random stream.
export const compileClassicalXofReaderBudget = (
    inputBits: bigint,
    consumedOutputBits: bigint,
    rateBits: 1088n | 1344n,
) => {
    assert.ok(inputBits >= 0n && consumedOutputBits >= 0n);
    const absorptionPermutations = (inputBits + 6n + rateBits - 1n) / rateBits;
    const consumedBlocks = (consumedOutputBits + rateBits - 1n) / rateBits;
    const minimumReferencePermutations =
        absorptionPermutations +
        (consumedBlocks > 0n ? consumedBlocks - 1n : 0n);
    if (consumedBlocks === 0n)
        return {
            absorptionPermutations,
            consumedBlocks,
            minimumReferencePermutations,
            maximumPrefixQueries: 0n,
            prefixQueryPermutationsUpperBound: 0n,
            maximumCachedBits: 0n,
            maximumOverlappingCacheBits: 0n,
        };
    // Starting with a blocks amortizes repeated input absorption as well as
    // squeezing. Starting with one block can instead cost log(length)*a.
    let capacityBlocks = absorptionPermutations;
    let maximumPrefixQueries = 1n;
    while (capacityBlocks < consumedBlocks) {
        capacityBlocks *= 2n;
        maximumPrefixQueries++;
    }
    // Every growth level may be visited; jumps only omit terms of this sum.
    const queriedBlocks = 2n * capacityBlocks - absorptionPermutations;
    return {
        absorptionPermutations,
        consumedBlocks,
        minimumReferencePermutations,
        maximumPrefixQueries,
        prefixQueryPermutationsUpperBound:
            maximumPrefixQueries * (absorptionPermutations - 1n) +
            queriedBlocks,
        maximumCachedBits: capacityBlocks * rateBits,
        maximumOverlappingCacheBits:
            (maximumPrefixQueries === 1n
                ? capacityBlocks
                : (3n * capacityBlocks) / 2n) * rateBits,
    };
};

// Mixed complete-input coherent queries and covered classical readers.
// Doubling from an absorption-sized initial prefix costs at most five times
// the readers' reference permutations. Complete-input rectangles cost at most
// twice their own slots, so five covers every mixture. The input budget must
// include additional conceptual producer calls made by a reduction, before
// expanding their oracle implementation; it is not automatically original T.
// A larger completeInputFactor may cover authenticated resumed hashes only
// after their full-input/resumed-work ratio and original-input availability
// are established separately. Five alone does not cover deep checkpoints.
// Cache lookup, cursor/handle control, copying returned bits, circuit
// construction, input-state sharing and other reduction work remain separate.
export const compileClassicalReaderOracleBudget = (
    callerReferenceGates: bigint,
    completeInputFactor = 5n,
) => {
    assert.ok(callerReferenceGates >= 0n && completeInputFactor >= 5n);
    const permutations = callerReferenceGates / shakePermutationGateCharge;
    const maximumLengthPermutations = completeInputFactor * permutations;
    return {
        maximumLogicalQueries: permutations,
        maximumLengthPermutations,
        // Covered reader-cache payload only. Resumed hash inputs, handles,
        // indices and oracle-circuit memory remain separate.
        cacheInputBitsUpperBound: 1344n * permutations,
        cacheOutputBitsUpperBound: 2n * 1344n * permutations,
        cacheGrowthOverlapBitsUpperBound: 3n * 1344n * permutations,
    };
};
