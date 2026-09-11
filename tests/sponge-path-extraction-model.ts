type Pair = readonly [input: number, output: number];

// A shortest path is sufficient for the extractor candidate. Parsing its
// reconstructed message and comparing a later opening are separate obligations.
const pathForTag = (
    database: readonly Pair[],
    rateBits: number,
    tag: number,
    tagBits = rateBits,
) => {
    const rateMask = (1 << rateBits) - 1;
    const queued: { pair: Pair; path: readonly number[] }[] = [];
    const visited = new Set<number>();
    const sorted = [...database].sort(([first], [second]) => first - second);
    for (const pair of sorted)
        if (pair[0] >> rateBits === 0) {
            queued.push({ pair, path: [pair[0] & rateMask] });
            visited.add(pair[0]);
        }
    for (let index = 0; index < queued.length; index++) {
        const current = queued[index];
        if ((current.pair[1] & ((1 << tagBits) - 1)) === tag)
            return current.path.join(',');
        for (const pair of sorted)
            if (
                !visited.has(pair[0]) &&
                pair[0] >> rateBits === current.pair[1] >> rateBits
            ) {
                visited.add(pair[0]);
                queued.push({
                    pair,
                    path: [
                        ...current.path,
                        (pair[0] ^ current.pair[1]) & rateMask,
                    ],
                });
            }
    }
    return undefined;
};

const partialPermutations = function* (
    size: number,
    maximumEntries: number,
): Generator<readonly Pair[]> {
    function* visit(
        database: Pair[],
        nextInput: number,
    ): Generator<readonly Pair[]> {
        yield database;
        if (database.length === maximumEntries) return;
        for (let input = nextInput; input < size; input++)
            for (let output = 0; output < size; output++)
                if (!database.some((pair) => pair[1] === output))
                    yield* visit([...database, [input, output]], input + 1);
    }
    yield* visit([], 0);
};

export const compileSpongePathExtractionCensus = () => {
    let checkedForwardStars = 0,
        checkedInverseStars = 0,
        changedPaths = 0;
    for (const [size, rateBits, tagBits, maximumEntries] of [
        [4, 1, 1, 2],
        [8, 1, 1, 2],
        [16, 2, 2, 1],
        [16, 2, 1, 1],
    ]) {
        const rateSize = 1 << rateBits;
        for (const database of partialPermutations(size, maximumEntries))
            for (let tag = 0; tag < 1 << tagBits; tag++) {
                const original = pathForTag(database, rateBits, tag, tagBits);
                for (let input = 0; input < size; input++) {
                    if (database.some((pair) => pair[0] === input)) continue;
                    let changed = 0;
                    for (let output = 0; output < size; output++)
                        if (!database.some((pair) => pair[1] === output))
                            changed += Number(
                                pathForTag(
                                    [...database, [input, output]],
                                    rateBits,
                                    tag,
                                    tagBits,
                                ) !== original,
                            );
                    if (
                        changed >
                        size / (1 << tagBits) + database.length * rateSize
                    )
                        throw new Error(
                            'The forward path-change bound failed.',
                        );
                    checkedForwardStars++;
                    changedPaths += changed;
                }
                for (let output = 0; output < size; output++) {
                    if (database.some((pair) => pair[1] === output)) continue;
                    let changed = 0;
                    for (let input = 0; input < size; input++)
                        if (!database.some((pair) => pair[0] === input))
                            changed += Number(
                                pathForTag(
                                    [...database, [input, output]],
                                    rateBits,
                                    tag,
                                    tagBits,
                                ) !== original,
                            );
                    if (changed > (database.length + 1) * rateSize)
                        throw new Error(
                            'The inverse path-change bound failed.',
                        );
                    checkedInverseStars++;
                    changedPaths += changed;
                }
            }
    }
    return { checkedForwardStars, checkedInverseStars, changedPaths };
};

export const compareInverseExtractionPredicates = (
    size: number,
    rateBits: number,
) => {
    const output = 0;
    return {
        terminalEdgeChanges: size,
        completePathChanges: Array.from({ length: size }, (_, input) =>
            pathForTag([[input, output]], rateBits, 0),
        ).filter((value) => value !== undefined).length,
    };
};

// Squaring the compression-reflection comparison reduces its only
// nontrivial case to this exact rational inequality; no floating roots occur.
export const compressionComparisonSlack = (
    available: bigint,
    changing: bigint,
) => {
    if (available < 1n || changing < 0n || changing > available)
        throw new RangeError('Invalid compression star.');
    if (2n * available <= 3n * changing) return undefined;
    return (
        4n * available * (available - changing) -
        (2n * available - 3n * changing) ** 2n
    );
};
