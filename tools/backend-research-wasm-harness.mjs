// Runs the bounded affine arithmetic diagnostic in raw WebAssembly. This is
// not a browser test and not a polynomial-commitment proof benchmark.
//
// Usage:
// node tools/backend-research-wasm-harness.mjs <wasmPath> <instanceVariableCount>

import { readFileSync } from 'node:fs';

const wasmPath = process.argv[2];
const relationInstanceVariableCount = Number.parseInt(
    process.argv[3] ?? '6',
    10,
);

if (
    wasmPath === undefined ||
    !Number.isSafeInteger(relationInstanceVariableCount)
) {
    throw new Error(
        'Expected a WebAssembly path and an integer relation-instance variable count.',
    );
}

const bytes = readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, {});
const exports = instance.exports;
const memory = exports.memory;
const runDiagnosticExport = exports.backend_research_wasm_run;
const digestAddressExport = exports.backend_research_wasm_digest_address;
if (!(memory instanceof WebAssembly.Memory)) {
    throw new Error('The WebAssembly module does not export linear memory.');
}
if (
    typeof runDiagnosticExport !== 'function' ||
    typeof digestAddressExport !== 'function'
) {
    throw new Error(
        'The WebAssembly module does not export the diagnostic functions.',
    );
}
const runDiagnostic = /** @type {(variableCount: number) => number} */ (
    runDiagnosticExport
);
const digestAddressAfterRun = /** @type {() => number} */ (digestAddressExport);
const pagesBefore = memory.buffer.byteLength / 65_536;

const started = process.hrtime.bigint();
const pagesAfter = runDiagnostic(relationInstanceVariableCount);
const elapsedMilliseconds = Number(process.hrtime.bigint() - started) / 1e6;
const digestAddress = digestAddressAfterRun();
const digest = new Uint8Array(memory.buffer, digestAddress, 64);

console.log(
    JSON.stringify(
        {
            relationInstanceVariableCount,
            witnessColumnCount: 4 * 2 ** relationInstanceVariableCount,
            witnessVariableCount: relationInstanceVariableCount + 16,
            classification: 'arithmetic diagnostic, not a PCS proof',
            linearMemoryPagesBefore: pagesBefore,
            linearMemoryPagesAfter: pagesAfter,
            linearMemoryMebibytesAfter: (
                (pagesAfter * 65_536) /
                1_048_576
            ).toFixed(2),
            elapsedMilliseconds: elapsedMilliseconds.toFixed(1),
            diagnosticDigestHex: Buffer.from(digest).toString('hex'),
        },
        null,
        2,
    ),
);
