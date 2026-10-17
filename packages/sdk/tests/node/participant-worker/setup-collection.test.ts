import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    PublicInputFailure,
    StorageFailure,
} from '#packages/sdk/src/participant/worker/shared/failures.js';
import type { ParticipantSession } from '#packages/sdk/src/participant/worker/stages/participant-session.js';
import { publishCollectedAggregate } from '#packages/sdk/src/participant/worker/stages/setup/setup-collection.js';
import { publicOperation } from '#packages/sdk/src/participant/worker/stages/setup/setup-public-work.js';
import type { SetupSelection } from '#packages/sdk/src/participant/worker/stages/setup/setup-verification.js';

const controls = vi.hoisted(() => ({
    downloaded: vi.fn(),
    command: vi.fn(),
    restore: vi.fn(),
    blob: vi.fn(),
    bytes: vi.fn(),
    write: vi.fn(),
    clear: vi.fn(),
    publish: vi.fn(),
    find: vi.fn(),
    read: vi.fn(),
    evaluate: vi.fn(),
    aggregate: vi.fn(),
}));

vi.mock(
    '#packages/sdk/src/participant/worker/module/participant-module.js',
    async (original) => ({
        ...(await original<
            typeof import('#packages/sdk/src/participant/worker/module/participant-module.js')
        >()),
        moduleCommand: controls.command,
        tryModuleCommand: controls.restore,
    }),
);
vi.mock(
    '#packages/sdk/src/participant/worker/relay/relay.js',
    async (original) => ({
        ...(await original<
            typeof import('#packages/sdk/src/participant/worker/relay/relay.js')
        >()),
        relayDownloadedBytes: controls.downloaded,
    }),
);
vi.mock('#packages/sdk/src/participant/worker/relay/candidates.js', () => ({
    findCandidate: controls.find,
    readCandidateFile: controls.read,
}));
vi.mock('#packages/sdk/src/participant/worker/relay/publication.js', () => ({
    createCandidatePublication: controls.publish,
}));
vi.mock('#packages/sdk/src/participant/worker/storage/delivery.js', () => ({
    openDelivery: () => Promise.resolve({}),
}));
vi.mock(
    '#packages/sdk/src/participant/worker/stages/setup/setup-collection-cache.js',
    () => ({
        collectionBlob: controls.blob,
        collectionBytes: controls.bytes,
        collectionBuffer: async (blob: Blob) =>
            new Uint8Array(await blob.arrayBuffer()),
        writeCollection: controls.write,
        clearCollectionKind: controls.clear,
    }),
);
vi.mock(
    '#packages/sdk/src/participant/worker/stages/setup/published-aggregate.js',
    async (original) => ({
        ...(await original<
            typeof import('#packages/sdk/src/participant/worker/stages/setup/published-aggregate.js')
        >()),
        verifyEvaluationFile: controls.evaluate,
        readAggregateData: controls.aggregate,
    }),
);

beforeEach(() => {
    for (const control of Object.values(controls)) control.mockReset();
});

// Small public byte fixtures and controlled verifier outcomes isolate SDK
// continuation. Cryptographic acceptance is exercised by the Rust tests.
const fixture = () => {
    const records = new Map<string, Blob>();
    const manifest = Uint8Array.of(1, 7);
    const identity = new Uint8Array(64).fill(9);
    const reference = Uint8Array.of(4, 5, 6);
    const sum = Uint8Array.of(2, 3, 4, 5, 6, 7);
    const calls: number[] = [];
    const publications: Uint8Array[][] = [];
    let refuseLocalSum = false;
    let checks = 0;
    let cut = Number.POSITIVE_INFINITY;
    let outputLength = 0;
    const memory = new WebAssembly.Memory({ initial: 1 });
    const module = {
        memory,
        setup_chunk_capacity: () => 8,
        setup_input_pointer: () => 0,
        setup_input_capacity: () => 128,
        setup_public_output_pointer: () => 256,
        setup_public_output_length: () => outputLength,
        setup_public_work: (operation: number) => {
            calls.push(operation);
            if (
                refuseLocalSum &&
                operation === publicOperation.aggregatePolynomial
            )
                return 1;
            const output =
                operation === publicOperation.sealCollection
                    ? manifest
                    : operation === publicOperation.beginAggregate
                      ? identity
                      : new Uint8Array();
            new Uint8Array(memory.buffer, 256, output.length).set(output);
            outputLength = output.length;
            return 0;
        },
    };
    const session = {
        context: {
            module,
            profile: {
                setupContributorCount: 2,
                contribution: {
                    polynomials: [
                        { expandedIndex: 3, bytes: 6, coefficients: 3 },
                    ],
                    committedPolynomials: [3],
                },
                preparation: {
                    publishedAggregate: {
                        limbs: 2,
                        generatedLimbBytes: 1,
                        manifestBytes: manifest.length,
                        retainedDataBytes: reference.length,
                        maximumProofBytes: 16,
                    },
                },
            },
        },
    } as unknown as ParticipantSession;
    const selection = {
        identity: new Uint8Array(64).fill(8),
        offers: [0, 1].map((position) => ({
            position,
            identity: new Uint8Array(64).fill(position + 1),
        })),
    } as SetupSelection;
    controls.downloaded.mockImplementation(() =>
        ++checks === cut ? 2 ** 31 : 0,
    );
    controls.blob.mockImplementation((_cache, key: string) => records.get(key));
    controls.bytes.mockImplementation(() => sum.slice());
    controls.write.mockImplementation(
        (_cache, change: (store: unknown) => void) =>
            change({
                put: (blob: Blob, key: string) => records.set(key, blob),
                delete: (key: string) => records.delete(key),
            }),
    );
    controls.command.mockReturnValue(reference);
    controls.restore.mockImplementation(
        (_module, _dispatcher, _operation, options: { input: Uint8Array }) => {
            expect(options.input).toEqual(reference);
            return new Uint8Array();
        },
    );
    controls.publish.mockImplementation(() => {
        const parts: Uint8Array[] = [];
        publications.push(parts);
        return {
            addBytes: (_name: string, bytes: Uint8Array) =>
                Promise.resolve(parts.push(bytes.slice())),
            addStream: async (
                _name: string,
                _length: number,
                stream: (
                    accept: (bytes: Uint8Array) => Promise<void>,
                ) => Promise<void>,
            ) => {
                await stream((bytes) => {
                    parts.push(bytes.slice());
                    return Promise.resolve();
                });
            },
            finish: async () => {},
        };
    });
    controls.find.mockImplementation(
        async (
            _relay,
            key: string,
            read: (candidate: { key: string }) => Promise<void>,
        ) => read({ key }),
    );
    controls.read.mockReturnValue(manifest);
    return {
        calls,
        publications,
        records,
        manifest,
        sum,
        refuse: () => {
            refuseLocalSum = true;
        },
        run: (stopAt = Number.POSITIVE_INFINITY) => {
            checks = 0;
            cut = stopAt;
            calls.length = 0;
            return publishCollectedAggregate(
                session,
                { base: 'https://relay.invalid/' },
                {} as IDBDatabase,
                selection,
            );
        },
    };
};

describe('organizer aggregate publication continuation', () => {
    it.each([1, 2, 3, 4])(
        'continues after download cut %s without publishing or verifying an incomplete aggregate',
        async (cut) => {
            const state = fixture();
            expect(await state.run(cut)).toBe(false);
            expect(state.calls).not.toContain(
                publicOperation.finishAggregateCache,
            );
            expect(state.records.has('data')).toBe(cut > 1);
            expect(await state.run()).toBe(true);
            expect(state.calls[state.calls.length - 1]).toBe(
                publicOperation.finishAggregateCache,
            );
            expect(state.publications).toEqual([[state.manifest, state.sum]]);
            expect(controls.restore).toHaveBeenCalledTimes(cut > 1 ? 1 : 0);
            // Every fresh verification checks both selected evaluations, even
            // when an earlier call finished one or both of them.
            expect(
                controls.evaluate.mock.calls
                    .slice(-2)
                    .map((call) => Number(call[3])),
            ).toEqual([0, 1]);
        },
    );

    it('classifies a refused retained sum as disposable storage failure', async () => {
        const state = fixture();
        state.refuse();
        await expect(state.run()).rejects.toBeInstanceOf(StorageFailure);
        expect(state.records.has('data')).toBe(false);
        expect(controls.evaluate).not.toHaveBeenCalled();
        expect(state.calls).not.toContain(publicOperation.finishAggregate);
    });

    it('keeps a wrong relay manifest classified as public input', async () => {
        const state = fixture();
        controls.read.mockReturnValue(Uint8Array.of(1, 99));
        await expect(state.run()).rejects.toBeInstanceOf(PublicInputFailure);
        expect(controls.aggregate).not.toHaveBeenCalled();
        expect(state.calls).not.toContain(publicOperation.finishAggregateCache);
    });
});
