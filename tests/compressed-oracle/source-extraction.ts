import assert from 'node:assert/strict';

import {
    Builder,
    applyClean,
    integerBits,
    fromBits,
} from '#tests/compressed-oracle/reversible-circuit.js';
import {
    type Entry,
    encodeDatabase,
    firstMatchingEntry,
} from '#tests/compressed-oracle/sparse-routing.js';

// After source-labelled extraction, framing, owner and family have already
// matched the extraction predicate. This separate total circuit checks the
// expected poll and canonical sign-magnitude coefficients. It copies
// the salt and coordinate only on success, with a distinct validity bit.
// It neither checks a key witness nor creates participant authority.
export function compileSourceCoordinateDecoding(
    coefficients: number,
    magnitudeBits: number,
    halfModulus: bigint,
    contextBits = 512,
    saltBits = 512,
) {
    assert.ok(
        [coefficients, magnitudeBits, contextBits, saltBits].every(
            (value) => Number.isSafeInteger(value) && value > 0,
        ),
    );
    assert.ok(halfModulus > 0n && halfModulus < 1n << BigInt(magnitudeBits));
    const payloadBits = saltBits + coefficients * (8 + magnitudeBits);
    const builder = new Builder(1 + 2 * contextBits + payloadBits);
    const wires = (start: number, length: number) =>
        Array.from({ length }, (_, bit) => start + bit);
    const one = builder.not(builder.zero);
    const limit = Array.from({ length: magnitudeBits }, (_, bit) =>
        (halfModulus >> BigInt(bit)) & 1n ? one : builder.zero,
    );
    let valid = builder.and(
        0,
        builder.equal(
            wires(1, contextBits),
            wires(1 + contextBits, contextBits),
        ),
    );
    const payload = 1 + 2 * contextBits;
    for (let index = 0; index < coefficients; index++) {
        const start = payload + saltBits + index * (8 + magnitudeBits);
        const sign = wires(start, 8);
        const magnitude = wires(start + 8, magnitudeBits);
        const zero = builder.equal(
            magnitude,
            Array<number>(magnitudeBits).fill(builder.zero),
        );
        const canonicalSign = builder.equal(
            sign.slice(1),
            Array<number>(7).fill(builder.zero),
        );
        const noNegativeZero = builder.not(builder.and(sign[0], zero));
        const bounded = builder.not(builder.less(limit, magnitude));
        valid = builder.and(
            valid,
            builder.and(canonicalSign, builder.and(noNegativeZero, bounded)),
        );
    }
    return builder.finish([
        ...wires(payload, payloadBits).map((wire) => builder.and(valid, wire)),
        valid,
    ]);
}

export function sourceCoordinateDecodingWork(
    coefficients: bigint,
    magnitudeBits: bigint,
    contextBits = 512n,
    saltBits = 512n,
) {
    assert.ok(
        coefficients > 0n &&
            magnitudeBits > 0n &&
            contextBits > 0n &&
            saltBits > 0n,
    );
    const payloadBits = saltBits + coefficients * (8n + magnitudeBits);
    // Compute, copy the payload plus its validity bit, then uncompute.
    // Public modulus bits share one prepared constant-one wire. Context
    // equality, every coefficient and all output bits are charged even on
    // missing extraction or a failed early coefficient.
    return {
        payloadBits,
        decodingGates:
            11n +
            10n * contextBits +
            coefficients * (24n * magnitudeBits + 94n) +
            3n * payloadBits,
    };
}

// A classical simulator cache, separate from the compressed oracle database.
// Rows hold value, key, occupied. The value includes the decoder's own valid
// bit, so a cached unsuccessful extraction is still a cache hit.
export function compileSourceCacheLookup(
    capacity: number,
    keyBits: number,
    valueBits: number,
) {
    assert.ok([capacity, keyBits, valueBits].every(Number.isSafeInteger));
    assert.ok(capacity >= 0 && keyBits > 0 && valueBits > 0);
    const rowBits = keyBits + valueBits + 1;
    const builder = new Builder(keyBits + capacity * rowBits);
    const query = Array.from({ length: keyBits }, (_, bit) => bit);
    const rows = Array.from({ length: capacity }, (_, index) =>
        Array.from(
            { length: rowBits },
            (_value, bit) => keyBits + index * rowBits + bit,
        ),
    );
    const matches = rows.map((row) =>
        builder.equal(query, row.slice(valueBits, valueBits + keyBits)),
    );
    return builder.finish(
        firstMatchingEntry(builder, rows, matches, valueBits),
    );
}

// Each request has a new predetermined zero row, even on a hit. Only misses
// occupy their row. This avoids an unpriced dynamically addressed insertion.
export function compileSourceCacheInsert(keyBits: number, valueBits: number) {
    assert.ok([keyBits, valueBits].every(Number.isSafeInteger));
    assert.ok(keyBits > 0 && valueBits > 0);
    const builder = new Builder(1 + valueBits + keyBits);
    const missed = builder.not(0);
    return builder.finish([
        ...Array.from({ length: valueBits + keyBits }, (_, bit) =>
            builder.and(missed, bit + 1),
        ),
        missed,
    ]);
}

export function sourceCacheWork(
    requests: bigint,
    keyBits: bigint,
    valueBits: bigint,
) {
    assert.ok(requests >= 0n && keyBits > 0n && valueBits > 0n);
    const rowBits = keyBits + valueBits + 1n;
    // Lookups scan 0, 1, ..., requests-1 reserved rows. All slots, including
    // unoccupied hit slots, are charged. Copying and uncomputation are included.
    const lookupGates =
        requests * (requests - 1n) * (11n + 5n * keyBits + 3n * valueBits) +
        requests * (valueBits + 1n);
    const insertionGates = requests * (5n + 3n * (keyBits + valueBits));
    // Conservatively charge preparation of every fresh zero cache bit too.
    const initializationGates = requests * rowBits;
    return {
        requests,
        keyBits,
        valueBits,
        maximumRetainedBits: requests * rowBits,
        lookupGates,
        insertionGates,
        initializationGates,
        totalGates: lookupGates + insertionGates + initializationGates,
    };
}

// Complete predicate computation for f(x,y)=(low_label_bits(x),y), followed
// by the exact first-match output. Its relation bits are part of clean work.
export function compileLabelledHashExtraction(
    capacity: number,
    inputBits: number,
    outputBits: number,
    labelBits: number,
    hashPrefixBits = outputBits,
) {
    assert.ok(
        [capacity, inputBits, outputBits, labelBits, hashPrefixBits].every(
            Number.isSafeInteger,
        ),
    );
    assert.ok(
        capacity >= 0 &&
            inputBits >= 1 &&
            outputBits >= 1 &&
            labelBits >= 0 &&
            labelBits <= inputBits &&
            hashPrefixBits >= 1 &&
            hashPrefixBits <= outputBits,
    );
    const targetBits = labelBits + hashPrefixBits,
        width = inputBits + outputBits + 1,
        builder = new Builder(targetBits + capacity * width),
        target = Array.from({ length: targetBits }, (_, index) => index),
        rows = Array.from({ length: capacity }, (_, index) =>
            Array.from(
                { length: width },
                (_item, bit) => targetBits + index * width + bit,
            ),
        );
    const matches = rows.map((row) =>
        builder.and(
            builder.equal(row.slice(0, labelBits), target.slice(0, labelBits)),
            builder.equal(
                row.slice(inputBits, inputBits + hashPrefixBits),
                target.slice(labelBits),
            ),
        ),
    );
    const circuit = builder.finish(
        firstMatchingEntry(builder, rows, matches, inputBits),
    );
    assert.equal(
        circuit.gates.length,
        capacity * (14 + 5 * (labelBits + hashPrefixBits) + 3 * inputBits),
    );
    return circuit;
}

export function labelledHashExtractionWork(
    capacity: bigint,
    inputBits: bigint,
    outputBits: bigint,
    labelBits: bigint,
    hashPrefixBits = outputBits,
) {
    assert.ok(
        capacity >= 0n &&
            inputBits >= 1n &&
            outputBits >= 1n &&
            labelBits >= 0n &&
            labelBits <= inputBits &&
            hashPrefixBits >= 1n &&
            hashPrefixBits <= outputBits,
    );
    return {
        capacity,
        inputBits,
        outputBits,
        labelBits,
        hashPrefixBits,
        extractionGates:
            2n *
                capacity *
                (14n + 5n * (labelBits + hashPrefixBits) + 3n * inputBits) +
            inputBits +
            1n,
        measuredQubits: inputBits + 1n,
        extractionQubits:
            labelBits +
            hashPrefixBits +
            inputBits +
            2n +
            capacity *
                (10n +
                    3n * labelBits +
                    3n * hashPrefixBits +
                    outputBits +
                    3n * inputBits),
    };
}

export function verifyLabelledHashExtraction(
    capacity: number,
    inputBits: number,
    outputBits: number,
    labelBits: number,
    hashPrefixBits = outputBits,
) {
    const circuit = compileLabelledHashExtraction(
        capacity,
        inputBits,
        outputBits,
        labelBits,
        hashPrefixBits,
    );
    let cases = 0;
    const enumerate = (entries: Entry[], next: number) => {
        const database = encodeDatabase(
            entries,
            capacity,
            inputBits,
            outputBits,
        );
        for (let label = 0; label < 2 ** labelBits; label++)
            for (let hash = 0; hash < 2 ** hashPrefixBits; hash++) {
                const target = Uint8Array.from([
                        ...integerBits(label, labelBits),
                        ...integerBits(hash, hashPrefixBits),
                    ]),
                    out = new Uint8Array(inputBits + 1);
                applyClean(circuit, target, database, out);
                const expected = entries.find(
                    (entry) =>
                        entry.input % 2 ** labelBits === label &&
                        entry.output % 2 ** hashPrefixBits === hash,
                );
                assert.equal(out[inputBits], expected ? 1 : 0);
                assert.equal(
                    fromBits(out.subarray(0, inputBits)),
                    expected?.input ?? 0,
                );
                cases++;
            }
        if (entries.length === capacity) return;
        for (let input = next; input < 2 ** inputBits; input++)
            for (let output = 0; output < 2 ** outputBits; output++)
                enumerate([...entries, { input, output }], input + 1);
    };
    enumerate([], 0);
    return {
        capacity,
        inputBits,
        outputBits,
        labelBits,
        cases,
        extractionGates: 2 * circuit.gates.length + inputBits + 1,
    };
}

export function sparseExtractionWork(
    capacity: bigint,
    inputBits: bigint,
    relationCleanQueryGates: bigint,
) {
    assert.ok(
        capacity >= 0n && inputBits >= 1n && relationCleanQueryGates >= 0n,
    );
    const selectionGates =
        2n * capacity * (9n + 3n * inputBits) + inputBits + 1n;
    return {
        capacity,
        inputBits,
        relationCleanQueryGates,
        selectionGates,
        extractionGates:
            2n * capacity * relationCleanQueryGates + selectionGates,
    };
}
