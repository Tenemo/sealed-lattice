import assert from 'node:assert/strict';

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
) => {
    assert.ok(
        permutations >= 0n && firstChunkBits >= 1n && programmedRecords >= 0n,
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
    return {
        lengthBitsUpperBound: lengthBits,
        componentVisitsUpperBound: componentVisits,
        componentBitVisitsUpperBound: componentBitVisits,
        baseQueryGatesUpperBound: queryCircuit(1n),
        programmedQueryGatesUpperBound: queryCircuit(2n) + replacementCopies,
    };
};
