import { rewriteWorkerCheckpoint } from './worker-instrumentation.js';

export const invalidBallotModulePath = 'invalid-ballot-participant.wasm';

// Only the corrupt participant's operation path changes. Its honest-module
// delivery and identity checks still run first, and standalone verification
// keeps compiling the authentic module. This hook is never shipped in the SDK.
export const invalidBallotWorker = (worker: Buffer): Buffer =>
    rewriteWorkerCheckpoint(
        worker,
        'operation-module',
        () =>
            'await WebAssembly.compile(await (await fetch(location.origin + ' +
            JSON.stringify('/' + invalidBallotModulePath) +
            ')).arrayBuffer())',
    );
