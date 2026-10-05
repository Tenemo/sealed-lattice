import assert from 'node:assert/strict';

export const invalidBallotModulePath = 'invalid-ballot-participant.wasm';

// Only the corrupt participant's operation path changes. Its honest-module
// delivery and identity checks still run first, and standalone verification
// keeps compiling the authentic module. This hook is never shipped in the SDK.
export const invalidBallotWorker = (worker: Buffer): Buffer => {
    const source = worker.toString('utf8');
    const boundary =
        /await WebAssembly\.compile\(delivered\.bytes\)(?=;\s*const evaluation = evaluatingOperations\.has\(command\.operation\);)/gu;
    assert.equal(
        [...source.matchAll(boundary)].length,
        1,
        'The worker must contain one participant-operation module compilation.',
    );
    return Buffer.from(
        source.replace(
            boundary,
            'await WebAssembly.compile(await (await fetch(location.origin + ' +
                JSON.stringify('/' + invalidBallotModulePath) +
                ')).arrayBuffer())',
        ),
    );
};
