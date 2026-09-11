import assert from 'node:assert/strict';

import {
    compileOracleCellController,
    oracleCellControllerWork,
    oraclePrefixReplacementWork,
    oracleSliceRoutingWork,
    prefixOracleWork,
    runOracleCellController,
} from '#tests/compressed-oracle-model.js';

export function oracleDomainCells(
    inputCapacity: bigint,
    outputCapacity: bigint,
    firstChunkBits: bigint,
) {
    assert.ok(
        inputCapacity >= 0n && outputCapacity >= 0n && firstChunkBits >= 1n,
    );
    const cells = [];
    for (let upper = 1n; ; upper *= 2n) {
        let start = 0n,
            size = firstChunkBits;
        while (start < outputCapacity) {
            cells.push({
                inputClassUpper: upper,
                outputStart: start,
                outputSize: size,
            });
            start += size;
            if (start > firstChunkBits) size *= 2n;
        }
        if (upper >= inputCapacity) break;
    }
    return cells;
}

type QueryRun = {
    readonly count: bigint;
    readonly inputCapacity: bigint;
    readonly outputCapacity: bigint;
};

export const prefixReplacementBaseQueriesPerAccess = 2n;

type ShadowQueryRun = QueryRun & {
    readonly activeShadows: readonly number[];
    readonly replacements: readonly {
        readonly inputBits: bigint;
        readonly prefixBits: bigint;
    }[];
};

export function shadowOracleDomainWork(
    runs: readonly ShadowQueryRun[],
    firstChunkBits: bigint,
    prefixLengths: readonly bigint[],
) {
    assert.ok(prefixLengths.every((value) => value >= 0n));
    const base = oracleDomainWork(
        runs.map((run) => ({
            ...run,
            count: prefixReplacementBaseQueriesPerAccess * run.count,
        })),
        firstChunkBits,
    );
    let maximumProgrammingRecordPayloadBits = 0n;
    let routingGates = 0n,
        copyGates = 0n,
        maximumRoutingQubits = 0n,
        maximumCopyQubits = 0n;
    for (const run of runs) {
        assert.equal(new Set(run.activeShadows).size, run.activeShadows.length);
        assert.ok(
            run.activeShadows.every(
                (index) =>
                    Number.isSafeInteger(index) &&
                    index >= 0 &&
                    index < prefixLengths.length,
            ),
        );
        const routing = oracleSliceRoutingWork(
                run.inputCapacity,
                run.outputCapacity,
                run.activeShadows.map((index) => prefixLengths[index]),
            ),
            copy = oraclePrefixReplacementWork(
                run.inputCapacity,
                run.outputCapacity,
                run.replacements,
            );
        const recordPayload = run.replacements.reduce(
            (sum, value) => sum + value.inputBits + value.prefixBits,
            0n,
        );
        if (recordPayload > maximumProgrammingRecordPayloadBits)
            maximumProgrammingRecordPayloadBits = recordPayload;
        routingGates += run.count * routing.computeAndUncomputeGates;
        copyGates += run.count * copy.cleanCopyGates;
        if (run.count > 0n) {
            if (routing.routingQubits > maximumRoutingQubits)
                maximumRoutingQubits = routing.routingQubits;
            if (copy.copyQubits > maximumCopyQubits)
                maximumCopyQubits = copy.copyQubits;
        }
    }
    const shadows = prefixLengths.map((_prefix, index) =>
        oracleDomainWork(
            runs.filter((run) => run.activeShadows.includes(index)),
            firstChunkBits,
        ),
    );
    return {
        base,
        shadows,
        routingGates,
        copyGates,
        queryGates:
            base.queryGates +
            routingGates +
            copyGates +
            shadows.reduce((sum, value) => sum + value.queryGates, 0n),
        maximumQubits:
            base.maximumQubits +
            maximumRoutingQubits +
            maximumCopyQubits +
            shadows.reduce((sum, value) => sum + value.maximumQubits, 0n),
        classicalSlicePrefixBits: prefixLengths.reduce(
            (sum, value) => sum + value,
            0n,
        ),
        maximumProgrammingRecordPayloadBits,
    };
}

export function oracleDomainWork(
    runs: readonly QueryRun[],
    firstChunkBits: bigint,
) {
    assert.ok(firstChunkBits >= 1n);
    const cells = new Map<
        string,
        {
            inputClassUpper: bigint;
            outputStart: bigint;
            outputSize: bigint;
            queries: bigint;
        }
    >();
    let controllerGates = 0n,
        maximumControllerQubits = 0n,
        maximumCallerQubits = 0n;
    for (const run of runs) {
        assert.ok(
            run.count >= 0n &&
                run.inputCapacity >= 0n &&
                run.outputCapacity >= 0n,
        );
        if (run.count === 0n) continue;
        for (const cell of oracleDomainCells(
            run.inputCapacity,
            run.outputCapacity,
            firstChunkBits,
        )) {
            const key = `${cell.inputClassUpper}:${cell.outputStart}`,
                prior = cells.get(key);
            if (prior) prior.queries += run.count;
            else cells.set(key, { ...cell, queries: run.count });
            const work = oracleCellControllerWork(
                run.inputCapacity,
                run.outputCapacity,
                cell.inputClassUpper,
                cell.outputStart,
                cell.outputSize,
            );
            controllerGates += run.count * work.computeAndUncomputeGates;
            maximumControllerQubits =
                maximumControllerQubits > work.controllerQubits
                    ? maximumControllerQubits
                    : work.controllerQubits;
            const caller = work.inputBits + run.outputCapacity;
            maximumCallerQubits =
                maximumCallerQubits > caller ? maximumCallerQubits : caller;
        }
    }
    let prefixGates = 0n,
        databaseQubits = 0n,
        maximumPrefixScratchQubits = 0n,
        fullValueQueries = 0n;
    const cellWork = [...cells.values()].map((cell) => {
        const work = prefixOracleWork(
                cell.queries,
                cell.inputClassUpper + 1n,
                cell.outputSize,
            ),
            database =
                work.fullValueQueries *
                (cell.inputClassUpper + cell.outputSize + 2n);
        prefixGates += work.queryGates;
        databaseQubits += database;
        fullValueQueries += work.fullValueQueries;
        const scratch = work.maximumQubits - database;
        maximumPrefixScratchQubits =
            maximumPrefixScratchQubits > scratch
                ? maximumPrefixScratchQubits
                : scratch;
        return { ...cell, ...work, databaseQubits: database };
    });
    return {
        firstChunkBits,
        cells: cellWork,
        controllerGates,
        prefixGates,
        fullValueQueries,
        queryGates: controllerGates + prefixGates,
        databaseQubits,
        // A conservative allocation permits the largest controller and prefix
        // scratch together, plus all databases and the original caller registers.
        maximumQubits:
            databaseQubits +
            maximumControllerQubits +
            maximumPrefixScratchQubits +
            maximumCallerQubits,
    };
}

export function programmedOracleDomainWork(
    runs: readonly QueryRun[],
    firstChunkBits: bigint,
    replacements: readonly {
        readonly inputBits: bigint;
        readonly prefixBits: bigint;
    }[],
) {
    assert.ok(
        replacements.every(
            (value) => value.inputBits >= 0n && value.prefixBits >= 0n,
        ),
    );
    // Read the base prefix into private workspace and erase it with the same
    // base query after the clean replacement copy. The inner domain adapter
    // independently retains its own compute/copy/uncompute multiplier.
    const base = oracleDomainWork(
        runs.map((run) => ({
            ...run,
            count: prefixReplacementBaseQueriesPerAccess * run.count,
        })),
        firstChunkBits,
    );
    let copyGates = 0n,
        maximumCopyQubits = 0n;
    for (const run of runs) {
        const work = oraclePrefixReplacementWork(
            run.inputCapacity,
            run.outputCapacity,
            replacements,
        );
        copyGates += run.count * work.cleanCopyGates;
        if (run.count > 0n && work.copyQubits > maximumCopyQubits)
            maximumCopyQubits = work.copyQubits;
    }
    return {
        base,
        copyGates,
        queryGates: base.queryGates + copyGates,
        maximumQubits: base.maximumQubits + maximumCopyQubits,
        classicalRecordPayloadBits: replacements.reduce(
            (sum, value) => sum + value.inputBits + value.prefixBits,
            0n,
        ),
    };
}

export function verifyOracleDomainAdapter() {
    let controllerCases = 0,
        streamCases = 0;
    const configurations = [
        [0, 0, 1, 0, 1],
        [0, 1, 1, 0, 1],
        [1, 1, 1, 0, 1],
        [2, 3, 1, 0, 2],
        [2, 3, 2, 2, 2],
        [3, 4, 4, 0, 2],
        [3, 4, 2, 2, 2],
        [4, 4, 4, 4, 4],
        [4, 3, 2, 0, 4],
    ];
    for (const [
        inputCapacity,
        outputCapacity,
        upper,
        start,
        size,
    ] of configurations) {
        const compiled = compileOracleCellController(
            inputCapacity,
            outputCapacity,
            upper,
            start,
            size,
        );
        for (let data = 0; data < 2 ** inputCapacity; data++)
            for (
                let inputLength = 0;
                inputLength < 2 ** Number(compiled.work.inputLengthBits);
                inputLength++
            )
                for (
                    let outputLength = 0;
                    outputLength < 2 ** Number(compiled.work.outputLengthBits);
                    outputLength++
                ) {
                    const raw = Uint8Array.from(
                            { length: inputCapacity },
                            (_, bit) => Math.floor(data / 2 ** bit) % 2,
                        ),
                        actual = runOracleCellController(
                            compiled,
                            raw,
                            inputLength,
                            outputLength,
                        );
                    const inside =
                        inputLength <= inputCapacity &&
                        inputLength <= upper &&
                        inputLength >= (upper === 1 ? 0 : upper / 2 + 1);
                    const key = new Uint8Array(upper + 1);
                    if (inside) {
                        key.set(raw.subarray(0, inputLength));
                        key[inputLength] = 1;
                    }
                    assert.deepEqual(actual.encodedInput, key);
                    assert.equal(
                        actual.prefixLength,
                        inside && outputLength <= outputCapacity
                            ? Math.min(size, Math.max(0, outputLength - start))
                            : 0,
                    );
                    controllerCases++;
                }
    }
    // Every complete two-bit stream assignment to empty/one-bit messages is
    // enumerated. These disjoint raw message coordinates are independent;
    // the adapter must reproduce each assignment, including padded buffers.
    for (let table = 0; table < 64; table++) {
        const streams = [
            table % 4,
            Math.floor(table / 4) % 4,
            Math.floor(table / 16) % 4,
        ];
        for (const capacity of [1, 2, 3]) {
            const cells = oracleDomainCells(BigInt(capacity), 2n, 1n).map(
                (cell) => ({
                    ...cell,
                    controller: compileOracleCellController(
                        capacity,
                        2,
                        Number(cell.inputClassUpper),
                        Number(cell.outputStart),
                        Number(cell.outputSize),
                    ),
                }),
            );
            for (let data = 0; data < 2 ** capacity; data++)
                for (const length of [0, 1])
                    for (const outputLength of [0, 1, 2]) {
                        const raw = Uint8Array.from(
                            { length: capacity },
                            (_, bit) => Math.floor(data / 2 ** bit) % 2,
                        );
                        let answer = 0;
                        for (const cell of cells) {
                            const controlled = runOracleCellController(
                                cell.controller,
                                raw,
                                length,
                                outputLength,
                            );
                            if (!controlled.prefixLength) continue;
                            let marker = controlled.encodedInput.length - 1;
                            while (controlled.encodedInput[marker] === 0)
                                marker--;
                            assert.ok(marker >= 0);
                            const index =
                                marker === 0
                                    ? 0
                                    : 1 + controlled.encodedInput[0];
                            const chunk =
                                Math.floor(
                                    streams[index] /
                                        2 ** Number(cell.outputStart),
                                ) %
                                2 ** controlled.prefixLength;
                            answer ^= chunk * 2 ** Number(cell.outputStart);
                        }
                        const expected =
                            streams[length === 0 ? 0 : 1 + (data % 2)] %
                            2 ** outputLength;
                        for (let response = 0; response < 4; response++)
                            assert.equal(
                                response ^ answer,
                                response ^ expected,
                            );
                        streamCases++;
                    }
        }
    }
    return { controllerCases, streamCases, completeStreamTables: 64 };
}
