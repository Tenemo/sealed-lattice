// Two hidden-key positions and two public inputs. Each public XOF value has
// a prefix bit and an additional bit; the classical keyed oracle returns only
// the prefix. Full functions are enumerated to compare joint distributions,
// not supplied free to the query-bounded adversary.
export const keyedXofViews = () => {
    type World = 'keyed' | 'random' | 'onePointOracle' | 'zeroPointOracle';
    const views = new Map<string, Record<World, bigint>>();
    const cell = (table: number, key: number, input: number) =>
        (table >> (2 * (2 * key + input))) & 3;
    const replace = (
        table: number,
        key: number,
        input: number,
        value: number,
    ) => {
        const position = 2 * (2 * key + input);
        return (table & ~(3 << position)) | (value << position);
    };
    const record = (
        table: number,
        oracle: (input: number) => number,
        world: World,
    ) => {
        const first = oracle(0),
            extended = cell(table, 0, first),
            next = (extended >> 1) ^ first;
        const view = JSON.stringify([
            table,
            oracle(0) | (oracle(1) << 1),
            first,
            extended,
            next,
            oracle(next),
            oracle(0),
        ]);
        const counts = views.get(view) ?? {
            keyed: 0n,
            random: 0n,
            onePointOracle: 0n,
            zeroPointOracle: 0n,
        };
        counts[world]++;
        views.set(view, counts);
    };
    let disclosedRandomMatches = 0n,
        disclosedKeyedMatches = 0n;
    for (let table = 0; table < 256; table++) {
        for (let key = 0; key < 2; key++) {
            const oracle = (input: number) => cell(table, key, input) & 1;
            record(table, oracle, 'keyed');
            if (oracle(0) === (cell(table, key, 0) & 1))
                disclosedKeyedMatches++;
        }
        for (let responses = 0; responses < 4; responses++) {
            record(table, (input) => (responses >> input) & 1, 'random');
            for (let key = 0; key < 2; key++)
                if ((responses & 1) === (cell(table, key, 0) & 1))
                    disclosedRandomMatches++;
        }
        for (let streams = 0; streams < 16; streams++)
            for (let key = 0; key < 2; key++) {
                const oracle = (input: number) => (streams >> (2 * input)) & 1;
                record(table, oracle, 'zeroPointOracle');
                const programmed = replace(
                    replace(table, key, 0, streams & 3),
                    key,
                    1,
                    streams >> 2,
                );
                record(programmed, oracle, 'onePointOracle');
            }
    }
    return {
        keyedSamples: 512n,
        randomSamples: 1024n,
        simulatedSamples: 8192n,
        disclosedKeyedSamples: 512n,
        disclosedRandomSamples: 2048n,
        disclosedKeyedMatches,
        disclosedRandomMatches,
        views: [...views].map(([view, counts]) => ({ view, ...counts })),
    };
};
