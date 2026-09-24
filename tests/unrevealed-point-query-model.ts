type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const rational = (numerator: bigint, denominator: bigint): Fraction => {
    if (denominator === 0n) throw new RangeError('Zero denominator.');
    if (denominator < 0n) {
        numerator = -numerator;
        denominator = -denominator;
    }
    let a = numerator < 0n ? -numerator : numerator,
        b = denominator;
    while (b) [a, b] = [b, a % b];
    return { numerator: numerator / a, denominator: denominator / a };
};

// A q-query Boolean-oracle algorithm has an acceptance polynomial of degree
// at most 2q after symmetrization by Hamming weight. Initial information and
// fixed gate descriptions must be independent of the hidden function.
export const unrevealedPointQueryBound = (
    queries: bigint,
    domainSize: bigint,
) => {
    if (queries < 0n || domainSize < 1n)
        throw new RangeError('Invalid query bound.');
    const degree = 2n * queries;
    if (degree === 0n)
        return {
            queries,
            domainSize,
            degree,
            spacing: 0n,
            bound: rational(0n, 1n),
        };
    const spacing = domainSize / (degree * degree);
    const bound = spacing < 3n ? rational(1n, 1n) : rational(5n, 2n * spacing);
    return { queries, domainSize, degree, spacing, bound };
};

// In the length-preserving restricted ideal collection game, preimage finding can be
// compared with independent targets by an undetectability distinguisher that
// runs the finder once and spends one additional public query checking it.
// This does not simulate opening other challenge preimages.
export const idealCollectionPreimageBound = (
    publicQueries: bigint,
    domainSize: bigint,
) => {
    if (publicQueries < 0n || domainSize < 1n)
        throw new RangeError('Invalid preimage-bound operands.');
    const undetectability = unrevealedPointQueryBound(
        2n * (publicQueries + 1n),
        domainSize,
    );
    const independentTargetSearch = rational(
        8n * (2n * publicQueries + 1n) ** 2n,
        domainSize,
    );
    const total = rational(
        undetectability.bound.numerator * independentTargetSearch.denominator +
            independentTargetSearch.numerator *
                undetectability.bound.denominator,
        undetectability.bound.denominator * independentTargetSearch.denominator,
    );
    return {
        publicQueries,
        undetectability,
        independentTargetSearch,
        bound: total.numerator < total.denominator ? total : rational(1n, 1n),
    };
};

// Exact Lagrange weights at x=1 for nodes 0, A, 4A, ..., d^2 A.
// Only a small control grid is materialized; the cryptographic bound above
// uses the analytic sum and never constructs a 2q-sized polynomial.
export const squareGridWeights = (domainSize: bigint, degree: number) => {
    if (
        !Number.isSafeInteger(degree) ||
        degree < 1 ||
        degree > 16 ||
        domainSize < BigInt(degree * degree)
    )
        throw new RangeError('Invalid interpolation control.');
    const spacing = domainSize / BigInt(degree * degree);
    const nodes = Array.from(
        { length: degree + 1 },
        (_, index) => spacing * BigInt(index * index),
    );
    return nodes.map((node, index) => {
        let numerator = 1n,
            denominator = 1n;
        for (let other = 0; other < nodes.length; other++) {
            if (other === index) continue;
            numerator *= 1n - nodes[other];
            denominator *= node - nodes[other];
        }
        return { node, weight: rational(numerator, denominator) };
    });
};

// Independent quantum control: phase oracle, then diffusion about the
// uniform state. Track the two per-item amplitudes as integers. Accept the
// subspace orthogonal to the initial uniform state after the final query.
export const groverDecisionProbability = (
    size: number,
    marked: number,
    queries: number,
): Fraction => {
    if (
        !Number.isSafeInteger(size) ||
        size < 2 ||
        size > 4096 ||
        !Number.isSafeInteger(marked) ||
        marked < 0 ||
        marked > size ||
        !Number.isSafeInteger(queries) ||
        queries < 0 ||
        queries > 8
    )
        throw new RangeError('Invalid exact search control.');
    const domain = BigInt(size),
        count = BigInt(marked);
    let selected = 1n,
        other = 1n,
        denominator = 1n;
    for (let query = 0; query < queries; query++) {
        const nextSelected =
            (domain - 2n * count) * selected + 2n * (domain - count) * other;
        const nextOther =
            -2n * count * selected + (domain - 2n * count) * other;
        selected = nextSelected;
        other = nextOther;
        denominator *= domain;
        if (
            count * selected ** 2n + (domain - count) * other ** 2n !==
            domain * denominator ** 2n
        )
            throw new Error('Search control lost normalization.');
    }
    const overlap = count * selected + (domain - count) * other;
    const square = domain ** 2n * denominator ** 2n;
    return rational(square - overlap ** 2n, square);
};

// One public-parameter slice, three tweaks, two inputs and one output bit.
// The second target and the non-target collection query depend on earlier
// replies. Compare the complete final function as well as the transcript.
export const undetectabilityCollectionViews = () => {
    type World = 'uniform' | 'image' | 'zeroPointOracle' | 'onePointOracle';
    const views = new Map<string, Record<World, bigint>>();
    const record = (
        table: number,
        first: number,
        second: number,
        collection: number,
        world: World,
    ) => {
        const view = JSON.stringify([
            first,
            1 + first,
            second,
            2 - first,
            collection,
            table,
        ]);
        const counts = views.get(view) ?? {
            uniform: 0n,
            image: 0n,
            zeroPointOracle: 0n,
            onePointOracle: 0n,
        };
        counts[world]++;
        views.set(view, counts);
    };
    const bit = (table: number, tweak: number, input: number) =>
        (table >> (2 * tweak + input)) & 1;
    const replace = (
        table: number,
        tweak: number,
        input: number,
        value: number,
    ) => {
        const position = 2 * tweak + input;
        return (table & ~(1 << position)) | (value << position);
    };
    for (let table = 0; table < 64; table++) {
        for (let x = 0; x < 2; x++)
            for (let y = 0; y < 2; y++) {
                const first = bit(table, 0, x),
                    second = bit(table, 1 + first, y);
                record(
                    table,
                    first,
                    second,
                    bit(table, 2 - first, second),
                    'image',
                );
            }
        for (let first = 0; first < 2; first++)
            for (let second = 0; second < 2; second++) {
                const collection = bit(table, 2 - first, second);
                record(table, first, second, collection, 'uniform');
                for (let mark = 0; mark < 2; mark++)
                    for (let shift0 = 0; shift0 < 2; shift0++)
                        for (let shift1 = 0; shift1 < 2; shift1++) {
                            // Preprocessing uses the original non-target row and replies
                            // fixed independently of the hidden point. Only later public
                            // oracle evaluation consults the point-oracle construction.
                            record(
                                table,
                                first,
                                second,
                                collection,
                                'zeroPointOracle',
                            );
                            const replaced = replace(
                                replace(table, 0, mark ^ shift0, first),
                                1 + first,
                                mark ^ shift1,
                                second,
                            );
                            record(
                                replaced,
                                first,
                                second,
                                collection,
                                'onePointOracle',
                            );
                        }
            }
    }
    return {
        originalSamples: 256n,
        simulatedSamples: 2048n,
        views: [...views].map(([view, counts]) => ({ view, ...counts })),
    };
};
