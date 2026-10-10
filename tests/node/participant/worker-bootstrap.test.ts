import { createHash } from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { participantRuntimeLabel } from '#packages/sdk/src/participant/worker/module/custody-identity.js';
import type { WorkerResult } from '#packages/sdk/src/participant/worker/runtime/worker-messages.js';

const downstream = vi.hoisted(() => ({
    helpers: vi.fn(),
    database: vi.fn(),
}));
vi.mock(
    '#packages/sdk/src/participant/worker/module/parallel-helpers.js',
    async (original) => ({
        ...(await original<
            typeof import('#packages/sdk/src/participant/worker/module/parallel-helpers.js')
        >()),
        startParallelHelpers: downstream.helpers,
    }),
);
vi.mock(
    '#packages/sdk/src/participant/worker/storage/database.js',
    async (original) => ({
        ...(await original<
            typeof import('#packages/sdk/src/participant/worker/storage/database.js')
        >()),
        openParticipantDatabase: downstream.database,
    }),
);

// A valid empty Wasm module exercises real delivery hashing and compilation.
// The first downstream call deliberately stops before participant execution.
const moduleBytes = Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0);
const moduleDigest = createHash('sha512').update(moduleBytes).digest('hex');
const identity = {
    source: '12'.repeat(64),
    module: moduleDigest,
    worker: '34'.repeat(64),
};
const stopped = 'Stopped after authenticated compilation.';

beforeEach(() => {
    vi.resetModules();
    downstream.helpers.mockReset().mockImplementation(() => {
        throw new Error(stopped);
    });
    downstream.database.mockReset();
    vi.stubGlobal('isSecureContext', true);
    vi.stubGlobal('navigator', { locks: { request: vi.fn() } });
    vi.stubGlobal('indexedDB', {});
});
afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
});

const runWorker = async (
    operation: 'status' | 'verify-outcome',
    bytes: Uint8Array,
    identities = identity,
) => {
    vi.stubGlobal(
        'fetch',
        vi.fn(() =>
            Promise.resolve(
                new Response(
                    new ReadableStream<Uint8Array>({
                        start(controller) {
                            controller.enqueue(bytes.subarray(0, 3));
                            controller.enqueue(bytes.subarray(3));
                            controller.close();
                        },
                    }),
                ),
            ),
        ),
    );
    let complete: (result: WorkerResult) => void;
    const result = new Promise<WorkerResult>((resolve) => {
        complete = resolve;
    });
    const scope: {
        onmessage: ((event: MessageEvent) => void) | null;
        postMessage: (value: WorkerResult) => void;
    } = { onmessage: null, postMessage: (value) => complete(value) };
    vi.stubGlobal('self', scope);
    await import('#packages/sdk/src/participant/worker/worker.js');
    expect(scope.onmessage).not.toBeNull();
    scope.onmessage?.(
        new MessageEvent('message', {
            data: {
                operation,
                namespace: 'bootstrap',
                poll: '56'.repeat(64),
                relay: 'https://relay.invalid/',
                module: 'https://application.invalid/participant.wasm',
                identity: identities,
                parameters: {},
            },
        }),
    );
    return result;
};

describe.each(['status', 'verify-outcome'] as const)(
    '%s worker bootstrap',
    (operation) => {
        it('hashes the module once and compiles the same owned bytes after both identities', async () => {
            const calls: string[] = [];
            const digest = crypto.subtle.digest.bind(crypto.subtle);
            const hashing = vi
                .spyOn(crypto.subtle, 'digest')
                .mockImplementation((algorithm, bytes) => {
                    calls.push('digest');
                    return digest(algorithm, bytes);
                });
            const compile = WebAssembly.compile.bind(WebAssembly);
            const compiling = vi
                .spyOn(WebAssembly, 'compile')
                .mockImplementation((bytes) => {
                    calls.push('compile');
                    return compile(bytes);
                });
            downstream.helpers.mockImplementation(() => {
                calls.push('helpers');
                throw new Error(stopped);
            });
            const result = await runWorker(operation, moduleBytes);
            expect(result).toMatchObject({
                status: 'pending',
                detail: stopped,
            });
            expect(calls).toEqual(['digest', 'digest', 'compile', 'helpers']);
            expect(hashing).toHaveBeenCalledTimes(2);
            expect(compiling).toHaveBeenCalledOnce();
            const delivered = hashing.mock.calls[0][1];
            expect(delivered).toBe(compiling.mock.calls[0][0]);
            expect(delivered).toBeInstanceOf(Uint8Array);
            expect((delivered as Uint8Array).buffer).toBeInstanceOf(
                ArrayBuffer,
            );
            expect(delivered).not.toBe(moduleBytes);
            const preimage = Buffer.concat([
                Buffer.from(participantRuntimeLabel),
                Buffer.from(identity.source, 'hex'),
                createHash('sha512').update(moduleBytes).digest(),
                Buffer.from(identity.worker, 'hex'),
            ]);
            expect(Buffer.from(hashing.mock.calls[1][1] as Uint8Array)).toEqual(
                preimage,
            );
            expect(Buffer.from(await hashing.mock.results[1].value)).toEqual(
                createHash('sha512').update(preimage).digest(),
            );
            expect(downstream.database).not.toHaveBeenCalled();
        });

        it('rejects a module digest mismatch before runtime derivation or execution', async () => {
            const hashing = vi.spyOn(crypto.subtle, 'digest');
            const compiling = vi.spyOn(WebAssembly, 'compile');
            expect(
                await runWorker(operation, moduleBytes, {
                    ...identity,
                    module: 'ff'.repeat(64),
                }),
            ).toMatchObject({
                status: 'pending',
                cause: 'public input',
                detail: 'The participant module changed.',
            });
            expect(hashing).toHaveBeenCalledOnce();
            expect(compiling).not.toHaveBeenCalled();
            expect(downstream.helpers).not.toHaveBeenCalled();
            expect(downstream.database).not.toHaveBeenCalled();
        });

        it('rejects oversized delivery before hashing or compilation', async () => {
            const hashing = vi.spyOn(crypto.subtle, 'digest');
            const compiling = vi.spyOn(WebAssembly, 'compile');
            expect(
                await runWorker(operation, new Uint8Array(8_388_609)),
            ).toMatchObject({
                status: 'pending',
                cause: 'public input',
                detail: 'A public record exceeds its bound.',
            });
            expect(hashing).not.toHaveBeenCalled();
            expect(compiling).not.toHaveBeenCalled();
            expect(downstream.helpers).not.toHaveBeenCalled();
            expect(downstream.database).not.toHaveBeenCalled();
        });

        it('rejects malformed pinned identity bytes before compilation', async () => {
            const compiling = vi.spyOn(WebAssembly, 'compile');
            expect(
                await runWorker(operation, moduleBytes, {
                    ...identity,
                    source: 'not-hexadecimal',
                }),
            ).toMatchObject({
                status: 'pending',
                detail: 'Malformed hexadecimal bytes.',
            });
            expect(compiling).not.toHaveBeenCalled();
            expect(downstream.helpers).not.toHaveBeenCalled();
            expect(downstream.database).not.toHaveBeenCalled();
        });
    },
);
