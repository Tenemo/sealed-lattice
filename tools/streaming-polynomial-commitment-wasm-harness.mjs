// Runs the complete streaming polynomial-commitment parity probe in raw
// WebAssembly. This is a Node-hosted Wasm run, not supported-phone evidence.
//
// Usage:
// node tools/streaming-polynomial-commitment-wasm-harness.mjs <wasmPath> <rowVariableCount> <rowCount>

import { readFileSync } from 'node:fs';

const wasmPath = process.argv[2];
const rowVariableCount = Number.parseInt(process.argv[3] ?? '16', 10);
const rowCount = Number.parseInt(process.argv[4] ?? '1024', 10);

if (
    wasmPath === undefined ||
    !Number.isSafeInteger(rowVariableCount) ||
    !Number.isSafeInteger(rowCount)
) {
    throw new Error(
        'Expected a WebAssembly path, integer row variable count, and integer row count.',
    );
}

const bytes = readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, {});
const exports = instance.exports;
const memory = exports.memory;
const runExport = exports.backend_research_streaming_protocol_wasm_run;
const digestAddressExport =
    exports.backend_research_streaming_protocol_wasm_digest_address;
const metricsAddressExport =
    exports.backend_research_streaming_protocol_wasm_metrics_address;
if (!(memory instanceof WebAssembly.Memory)) {
    throw new Error('The WebAssembly module does not export linear memory.');
}
if (
    typeof runExport !== 'function' ||
    typeof digestAddressExport !== 'function' ||
    typeof metricsAddressExport !== 'function'
) {
    throw new Error(
        'The WebAssembly module does not export the streaming protocol probe functions.',
    );
}

const run = /** @type {(rowCount: number, variableCount: number) => number} */ (
    runExport
);
const digestAddressAfterRun = /** @type {() => number} */ (
    digestAddressExport
);
const metricsAddressAfterRun = /** @type {() => number} */ (metricsAddressExport);
const pagesBefore = memory.buffer.byteLength / 65_536;
const started = process.hrtime.bigint();
const pagesAfter = run(rowCount, rowVariableCount);
const elapsedMilliseconds = Number(process.hrtime.bigint() - started) / 1e6;
const digestAddress = digestAddressAfterRun();
const digest = new Uint8Array(memory.buffer, digestAddress, 64);
const metricsAddress = metricsAddressAfterRun();
const metrics = new Uint32Array(memory.buffer, metricsAddress, 15);
const [
    proofByteLength,
    aggregateProofByteLength,
    aggregateQueryValueByteLength,
    aggregateRoundQueryValueByteLength,
    aggregateSourceQueryValueByteLength,
    aggregateFreshMainQueryValueByteLength,
    aggregateMaskQueryValueByteLength,
    aggregateMerkleDictionaryByteLength,
    aggregateMerkleReferenceByteLength,
    aggregateMerkleUniqueNodeCount,
    aggregateMerkleReferenceCount,
    aggregateQueryCount,
    outerColumnValueByteLength,
    outerMerkleFrontierByteLength,
    outerMerkleFrontierNodeCount,
] = metrics;

console.log(
    JSON.stringify(
        {
            rowCount,
            rowVariableCount,
            witnessValueCount: rowCount * 2 ** rowVariableCount,
            classification:
                'complete canonical proof in Node-hosted Wasm, not supported-phone evidence',
            linearMemoryPagesBefore: pagesBefore,
            linearMemoryPagesAfter: pagesAfter,
            linearMemoryMebibytesAfter: (
                (pagesAfter * 65_536) /
                1_048_576
            ).toFixed(2),
            elapsedMilliseconds: elapsedMilliseconds.toFixed(1),
            canonicalProofByteLength: proofByteLength,
            canonicalProofMebibytes: (
                proofByteLength / 1_048_576
            ).toFixed(3),
            aggregateProofByteLength,
            aggregateQueryValueByteLength,
            aggregateRoundQueryValueByteLength,
            aggregateSourceQueryValueByteLength,
            aggregateFreshMainQueryValueByteLength,
            aggregateMaskQueryValueByteLength,
            aggregateMerkleDictionaryByteLength,
            aggregateMerkleReferenceByteLength,
            aggregateMerkleUniqueNodeCount,
            aggregateMerkleReferenceCount,
            aggregateQueryCount,
            outerColumnValueByteLength,
            outerMerkleFrontierByteLength,
            outerMerkleFrontierNodeCount,
            proofDigestHex: Buffer.from(digest).toString('hex'),
        },
        null,
        2,
    ),
);
