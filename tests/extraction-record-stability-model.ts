// Finite rational quantum control: database, retained record, and query bits.
// This checks a projector-stability lemma, not a permutation-oracle simulator.
const permute = (
    state: readonly bigint[],
    target: (index: number) => number,
) => {
    const output = Array<bigint>(state.length).fill(0n);
    for (let index = 0; index < state.length; index++)
        output[target(index)] += state[index];
    return output;
};

const rotate = (
    state: readonly bigint[],
    bit: number,
    cosine: bigint,
    sine: bigint,
    sign: (index: number) => bigint,
) => {
    const output = [...state];
    for (let lower = 0; lower < state.length; lower++) {
        if ((lower & bit) !== 0) continue;
        const upper = lower | bit;
        const signedSine = sign(lower) * sine;
        output[lower] = cosine * state[lower] - signedSine * state[upper];
        output[upper] = signedSine * state[lower] + cosine * state[upper];
    }
    return output;
};

export const simulateReadOnlyExtractionRecord = (
    queries: number,
    feedbackPattern: number,
    recordedBit: number,
) => {
    if (
        !Number.isSafeInteger(queries) ||
        queries < 0 ||
        queries > 8 ||
        !Number.isSafeInteger(feedbackPattern) ||
        feedbackPattern < 0 ||
        feedbackPattern >= 2 ** queries ||
        ![0, 1].includes(recordedBit)
    )
        throw new RangeError('Invalid bounded record-stability case.');
    let state = Array<bigint>(8).fill(0n);
    state[6 * recordedBit] = 3n;
    state[6 * recordedBit + 1] = 4n;
    let denominator = 5n;
    // The Pythagorean triple gives an exactly unitary small rotation.
    const cosine = 9999n,
        sine = 200n,
        queryDenominator = 10001n;
    for (let query = 0; query < queries; query++) {
        if ((feedbackPattern & (1 << query)) !== 0)
            state = permute(state, (index) =>
                (index & 2) !== 0 ? index ^ 1 : index,
            );
        state = rotate(state, 1, 3n, 4n, () => 1n);
        denominator *= 5n;
        state = rotate(state, 4, cosine, sine, (index) =>
            (index & 1) === 0 ? 1n : -1n,
        );
        denominator *= queryDenominator;
    }
    const probabilityDenominator = denominator ** 2n;
    const totalWeight = state.reduce((total, value) => total + value ** 2n, 0n);
    if (totalWeight !== probabilityDenominator)
        throw new Error('The rational control lost normalization.');
    const mismatchNumerator = state.reduce(
        (total, value, index) =>
            ((index >> 2) & 1) !== ((index >> 1) & 1)
                ? total + value ** 2n
                : total,
        0n,
    );
    return {
        mismatchNumerator,
        probabilityDenominator,
        perQueryLeakageSquaredNumerator: sine ** 2n,
        perQueryLeakageSquaredDenominator: queryDenominator ** 2n,
    };
};

export const compareCopyAndReadOnlyFeedback = () => {
    const copy = (index: number) => ((index & 4) !== 0 ? index ^ 2 : index);
    const feedback = (index: number) => ((index & 2) !== 0 ? index ^ 1 : index);
    const equality = (index: number) =>
        ((index >> 2) & 1) === ((index >> 1) & 1);
    return {
        copyThenFeedback: feedback(copy(4)),
        feedbackThenCopy: copy(feedback(4)),
        feedbackPreservesEquality: Array.from(
            { length: 8 },
            (_, index) => equality(index) === equality(feedback(index)),
        ),
        overwrittenRecordPreservesEquality: equality(0 ^ 2),
    };
};

export const discardedQuantumTagRecord = () => {
    // The vector has squared norm two; retain that common density denominator.
    const initial = [1n, 0n, 1n, 0n];
    const copied = permute(initial, (index) =>
        (index & 2) !== 0 ? index ^ 1 : index,
    );
    const reducedTag = (state: readonly bigint[]) =>
        Array.from({ length: 4 }, (_, entry) => {
            const row = Math.floor(entry / 2),
                column = entry % 2;
            return (
                state[2 * row] * state[2 * column] +
                state[2 * row + 1] * state[2 * column + 1]
            );
        });
    return {
        initialDensityNumerators: reducedTag(initial),
        copiedDensityNumerators: reducedTag(copied),
        densityDenominator: 2n,
    };
};
