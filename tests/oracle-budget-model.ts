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

const bitWidth = (value: bigint) => {
    let bits = 0n;
    while (value > 0n) {
        bits++;
        value >>= 1n;
    }
    return bits;
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

// An upper bound on the maintained query circuits, conditional on charging
// EACH call at its declared maximum input and output capacities. It is not
// a normalization theorem for arbitrary coherent-length or expected-work
// algorithms, and excludes extraction, programming-record creation, classical
// circuit construction/dispatch and the rest of a cryptographic reduction.
//
// P bounds the sum of reference permutations for those maximum capacities.
// A nonempty call costs at least one permutation and m+n <= 2*r*p for that
// call. The widest SHAKE rate conservatively covers both FIPS 202 functions.
export const compileOraclePermutationBudget = (
    permutations: bigint,
    firstChunkBits: bigint,
    programmedRecords = 0n,
    shadowStreams = 0n,
) => {
    assert.ok(
        permutations >= 0n &&
            firstChunkBits >= 1n &&
            programmedRecords >= 0n &&
            shadowStreams >= 0n,
    );
    const rateBits = 1344n;
    const lengthBits = bitWidth(
        4n * rateBits * permutations + 2n * firstChunkBits + 3n,
    );
    const componentVisits = lengthBits ** 2n * permutations;
    // For each call, sum the cell widths w=u+s+2 over all input classes u
    // and output chunks s. The dyadic sums are <4*max(m,1) and
    // <=2*max(n,K). Summing over calls uses sum(m+n)<=2*r*P, not Q times
    // the largest query's dimensions.
    const componentBitVisits =
        (8n * rateBits * lengthBits +
            4n * lengthBits +
            2n * lengthBits ** 2n +
            2n * lengthBits * firstChunkBits) *
        permutations;

    const queryCircuit = (baseAccesses: bigint) => {
        const fullValueAccesses = 2n * baseAccesses;
        // A component with t full-value calls has an entry term at most
        // (59*w+34)*t*(t-1) and a local/per-call term at most 80*w*t.
        // Both the new query AND its persistent prior capacity acquire the
        // wrapper multiplier. This is where a merely linear multiplier fails.
        const routing =
            fullValueAccesses ** 2n *
            permutations *
            (59n * componentBitVisits + 34n * componentVisits);
        const local = 80n * fullValueAccesses * componentBitVisits;
        // The clean length/sentinel controller is <=(98+306*L)*w;
        // prefix copy is <=(7+14*L)*w, for each base access to each cell.
        const controllersAndCopies =
            baseAccesses * (105n + 320n * lengthBits) * componentBitVisits;
        return routing + local + controllersAndCopies;
    };

    // The outer replacement copy runs once per logical query. A fitting
    // record compares at most m input bits and substitutes at most n bits;
    // records longer than the caller's input cannot match.
    const replacementCopies =
        permutations *
        (6n +
            28n * lengthBits +
            programmedRecords * (10n + 10n * lengthBits) +
            2n * rateBits * (14n * lengthBits + 5n) +
            20n * rateBits * programmedRecords);
    const baseQueryGates = queryCircuit(1n);
    const programmedQueryGates = queryCircuit(2n) + replacementCopies;
    // Each shadow keeps its own database across all openings. Prefix routing
    // compares only fitting input positions, and cannot exceed this sum even
    // when all potential shadows are active for the entire schedule.
    const shadowRoutingGates =
        permutations *
        (24n +
            62n * lengthBits +
            shadowStreams * (44n + 34n * lengthBits + 40n * rateBits));
    return {
        lengthBitsUpperBound: lengthBits,
        componentVisitsUpperBound: componentVisits,
        componentBitVisitsUpperBound: componentBitVisits,
        baseQueryGatesUpperBound: baseQueryGates,
        programmedQueryGatesUpperBound: programmedQueryGates,
        shadowQueryGatesUpperBound:
            programmedQueryGates +
            shadowStreams * baseQueryGates +
            shadowRoutingGates,
    };
};

// Applies the owner-selected full-circuit convention to the query circuits.
// This operand must include every caller's charged oracle work. Extra calls
// introduced by a reduction must be included before using this conversion.
// Other simulation work, extraction and record construction remain separate.
export const compileFullCircuitOracleBudget = (
    experimentGates: bigint,
    firstChunkBits: bigint,
    programmedRecords = 0n,
    shadowStreams = 0n,
) => {
    assert.ok(experimentGates >= 0n);
    const permutationSlots = experimentGates / shakePermutationGateCharge;
    // Sum_i(2*p_i-1) <= 2*sum_i p_i; no quantum branch is inspected.
    const maximumLengthPermutations = 2n * permutationSlots;
    return {
        maximumLogicalQueries: permutationSlots,
        maximumLengthPermutations,
        ...compileOraclePermutationBudget(
            maximumLengthPermutations,
            firstChunkBits,
            programmedRecords,
            shadowStreams,
        ),
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
    firstChunkBits: bigint,
    programmedRecords = 0n,
    shadowStreams = 0n,
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
        ...compileOraclePermutationBudget(
            maximumLengthPermutations,
            firstChunkBits,
            programmedRecords,
            shadowStreams,
        ),
    };
};
