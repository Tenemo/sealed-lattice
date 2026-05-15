import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import type {
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
} from '@sealed-lattice/types';
import { afterEach, describe, expect, it, vi } from 'vitest';

import goldenTranscriptCoreFixturesJson from '../../../../test-vectors/transcript-core/golden-transcript-core.json';
import malformedObjectFixturesJson from '../../../../test-vectors/transcript-core/malformed-objects.json';
import {
    createTranscriptCoreKernelLoader,
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    roundTripBytesThroughKernel,
    type TranscriptCoreKernel,
    verifyTranscriptCoreFixture,
} from '../../src/index';

type NamedFixture = {
    readonly caseName: string;
};

type TranscriptCoreKernelExportsForTests = WebAssembly.Exports & {
    memory: WebAssembly.Memory;
    sealed_lattice_allocate: (length: number) => number;
    sealed_lattice_deallocate: (pointer: number, length: number) => void;
    sealed_lattice_last_output_length: () => number;
    sealed_lattice_transcript_core_command: (
        pointer: number,
        length: number,
    ) => number;
    sealed_lattice_roundtrip: (pointer: number, length: number) => number;
};

const goldenTranscriptCoreFixtures =
    goldenTranscriptCoreFixturesJson as readonly GoldenTranscriptCoreFixture[];
const malformedObjectFixtures =
    malformedObjectFixturesJson as readonly MalformedObjectFixture[];

const findFixture = <Fixture extends NamedFixture>(
    fixtures: readonly Fixture[],
    caseName: string,
): Fixture => {
    const fixture = fixtures.find(
        (candidate) => candidate.caseName === caseName,
    );
    if (fixture === undefined) {
        throw new Error(`Missing fixture: ${caseName}`);
    }

    return fixture;
};

const fullyVerifiedPassiveFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'fully-verified-passive-mhe-transcript-core',
);
const fullyVerifiedActiveFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'fully-verified-active-malicious-transcript-core',
);
const invalidEnumFixture = findFixture(malformedObjectFixtures, 'invalid-enum');

const createMockKernelExports = ({
    allocationPointer = 12,
    commandPointer = 128,
    commandResponse = {
        success: true,
        value: {
            chunkRoot: 'abc123',
            hash512: 'feedface',
        },
    },
    roundTripPointer = allocationPointer,
}: {
    readonly allocationPointer?: number;
    readonly commandPointer?: number;
    readonly commandResponse?: unknown;
    readonly roundTripPointer?: number;
} = {}): {
    readonly deallocate: ReturnType<typeof vi.fn>;
    readonly encodedCommandResponseLength: number;
    readonly getInstantiateCallCount: () => number;
    readonly loadMockKernel: () => Promise<TranscriptCoreKernel>;
    readonly rejectNextInstantiation: (error: Error) => void;
} => {
    const encodedCommandResponse = new TextEncoder().encode(
        JSON.stringify(commandResponse),
    );
    const deallocate = vi.fn();
    const memory = new WebAssembly.Memory({ initial: 1 });
    const fakeModule = {} as WebAssembly.Module;
    const webAssemblyWithByteSourceInstantiate = WebAssembly as unknown as {
        instantiate: (
            source: BufferSource,
            importObject?: WebAssembly.Imports,
        ) => Promise<WebAssembly.WebAssemblyInstantiatedSource>;
    };
    const instantiatedSource: WebAssembly.WebAssemblyInstantiatedSource = {
        instance: {
            exports: {
                memory,
                sealed_lattice_allocate: vi.fn(() => allocationPointer),
                sealed_lattice_deallocate: deallocate,
                sealed_lattice_last_output_length: vi.fn(
                    () => encodedCommandResponse.length,
                ),
                sealed_lattice_transcript_core_command: vi.fn(() => {
                    new Uint8Array(memory.buffer).set(
                        encodedCommandResponse,
                        commandPointer,
                    );

                    return commandPointer;
                }),
                sealed_lattice_roundtrip: vi.fn(() => roundTripPointer),
            } as TranscriptCoreKernelExportsForTests,
        } as WebAssembly.Instance,
        module: fakeModule,
    };

    vi.mocked(readFile).mockResolvedValue(Buffer.from([0]));
    const instantiate = vi
        .spyOn(webAssemblyWithByteSourceInstantiate, 'instantiate')
        .mockResolvedValue(instantiatedSource);
    vi.spyOn(WebAssembly.Module, 'exports').mockReturnValue([
        { kind: 'memory', name: 'memory' },
        { kind: 'function', name: 'sealed_lattice_allocate' },
        { kind: 'function', name: 'sealed_lattice_deallocate' },
        { kind: 'function', name: 'sealed_lattice_last_output_length' },
        { kind: 'function', name: 'sealed_lattice_transcript_core_command' },
        { kind: 'function', name: 'sealed_lattice_roundtrip' },
    ]);

    return {
        deallocate,
        encodedCommandResponseLength: encodedCommandResponse.length,
        getInstantiateCallCount: () => instantiate.mock.calls.length,
        loadMockKernel: createTranscriptCoreKernelLoader(
            pathToFileURL(path.resolve('mock-sealed-lattice-kernel.wasm')),
        ),
        rejectNextInstantiation: (error: Error): void => {
            instantiate.mockRejectedValueOnce(error);
        },
    };
};

vi.mock('node:fs/promises', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:fs/promises')>();

    return {
        ...actual,
        readFile: vi.fn(actual.readFile),
    };
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('transcript-core kernel in Node', () => {
    it('loads the transcript-core module and exposes command exports', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_last_output_length',
                'sealed_lattice_transcript_core_command',
                'sealed_lattice_roundtrip',
            ]),
        );
    });

    it('analyzes golden transcript-core fixtures through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        const fullyVerifiedPassiveAnalysis = kernel.analyzeCanonicalObject({
            canonicalBytesHex: fullyVerifiedPassiveFixture.canonicalBytesHex,
            chunkSize: fullyVerifiedPassiveFixture.chunkSize,
        });
        const fullyVerifiedActiveAnalysis = kernel.analyzeCanonicalObject({
            canonicalBytesHex: fullyVerifiedActiveFixture.canonicalBytesHex,
            chunkSize: fullyVerifiedActiveFixture.chunkSize,
        });

        expect(fullyVerifiedPassiveAnalysis.baseClaimProfile).toBe(
            'FullyVerifiedResult',
        );
        expect(fullyVerifiedPassiveAnalysis.evaluationProofProfileId).toBe(
            'PQEvalProof-STARK-BGVReplay-v1',
        );
        expect(fullyVerifiedActiveAnalysis.mheSecurityStage).toBe(
            'ActiveMalicious',
        );
        expect(fullyVerifiedActiveAnalysis.evaluationProofProfileId).toBe(
            'PQEvalProof-STARK-BGVReplay-v1',
        );
        expect(fullyVerifiedPassiveAnalysis.objectHash512).not.toBe(
            fullyVerifiedActiveAnalysis.objectHash512,
        );
    });

    it('verifies golden and malformed fixtures with stable outputs', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.verifyFixture(fullyVerifiedPassiveFixture)).toEqual({
            verified: true,
            caseName: 'fully-verified-passive-mhe-transcript-core',
            objectHash512: fullyVerifiedPassiveFixture.expectedObjectHash512,
            chunkRoot: fullyVerifiedPassiveFixture.expectedChunkRoot,
            statusLabels: fullyVerifiedPassiveFixture.expectedStatusLabels,
        });
        expect(kernel.verifyFixture(invalidEnumFixture)).toEqual({
            verified: true,
            caseName: 'invalid-enum',
            expectedErrorCode: 'InvalidEnum',
        });
    });

    it('maps canonical rejection errors from command responses', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() =>
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: invalidEnumFixture.canonicalBytesHex,
                chunkSize: 8,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        try {
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: invalidEnumFixture.canonicalBytesHex,
                chunkSize: 8,
            });
        } catch (error) {
            expect(error).toBeInstanceOf(TranscriptCoreKernelCommandError);
            expect((error as TranscriptCoreKernelCommandError).code).toBe(
                'InvalidEnum',
            );
        }
    });

    it('keeps byte round-trip as an allocation smoke path', async () => {
        await expect(
            roundTripBytesThroughKernel(Uint8Array.from([9, 8, 7, 6, 5])),
        ).resolves.toEqual(Uint8Array.from([9, 8, 7, 6, 5]));
    });

    it('verifies fixtures through the public WASM wrapper', async () => {
        await expect(
            verifyTranscriptCoreFixture(fullyVerifiedPassiveFixture),
        ).resolves.toEqual({
            verified: true,
            caseName: 'fully-verified-passive-mhe-transcript-core',
            objectHash512: fullyVerifiedPassiveFixture.expectedObjectHash512,
            chunkRoot: fullyVerifiedPassiveFixture.expectedChunkRoot,
            statusLabels: fullyVerifiedPassiveFixture.expectedStatusLabels,
        });
    });

    it('computes internal hash smoke outputs through the command bridge', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.hashRaw('00')).toMatch(/^[a-f0-9]{128}$/u);
    });

    it('deallocates command inputs and outputs', async () => {
        const { deallocate, encodedCommandResponseLength, loadMockKernel } =
            createMockKernelExports();
        const kernel = await loadMockKernel();

        expect(
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toBe('abc123');
        expect(deallocate).toHaveBeenCalledWith(
            128,
            encodedCommandResponseLength,
        );
        expect(deallocate).toHaveBeenCalledWith(12, expect.any(Number));
    });

    it('deallocates aliased command pointers only once', async () => {
        const { deallocate, encodedCommandResponseLength, loadMockKernel } =
            createMockKernelExports({
                commandPointer: 12,
            });
        const kernel = await loadMockKernel();

        expect(
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toBe('abc123');
        expect(deallocate).toHaveBeenCalledTimes(1);
        expect(deallocate).toHaveBeenCalledWith(
            12,
            encodedCommandResponseLength,
        );
    });

    it('deallocates aliased round-trip pointers only once', async () => {
        const { deallocate, loadMockKernel } = createMockKernelExports();
        const kernel = await loadMockKernel();

        expect(
            Array.from(kernel.roundTripBytes(Uint8Array.from([2, 4, 6, 8]))),
        ).toEqual([2, 4, 6, 8]);
        expect(deallocate).toHaveBeenCalledTimes(1);
        expect(deallocate).toHaveBeenCalledWith(12, 4);
    });

    it('handles empty round-trip inputs without allocating input bytes', async () => {
        const { deallocate, loadMockKernel } = createMockKernelExports();
        const kernel = await loadMockKernel();

        expect(Array.from(kernel.roundTripBytes(new Uint8Array()))).toEqual([]);
        expect(deallocate).toHaveBeenCalledWith(12, 0);
    });

    it('rejects null pointers for non-empty allocations', async () => {
        const { loadMockKernel } = createMockKernelExports({
            allocationPointer: 0,
        });
        const kernel = await loadMockKernel();

        expect(() => kernel.roundTripBytes(Uint8Array.from([1]))).toThrow(
            'The transcript-core kernel returned a null pointer for a non-empty allocation.',
        );
    });

    it('rejects null command output pointers for non-empty outputs', async () => {
        const { loadMockKernel } = createMockKernelExports({
            commandPointer: 0,
        });
        const kernel = await loadMockKernel();

        expect(() =>
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toThrow(
            'The transcript-core kernel returned a null pointer for a non-empty transcript-core command result.',
        );
    });

    it('rejects invalid command response shapes', async () => {
        const { loadMockKernel } = createMockKernelExports({
            commandResponse: {
                success: true,
            },
        });
        const kernel = await loadMockKernel();

        expect(() =>
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toThrow(
            'The transcript-core kernel returned an invalid command response.',
        );
    });

    it('memoizes the loaded kernel promise', async () => {
        const { getInstantiateCallCount, loadMockKernel } =
            createMockKernelExports();
        const [leftKernel, rightKernel] = await Promise.all([
            loadMockKernel(),
            loadMockKernel(),
        ]);

        expect(leftKernel).toBe(rightKernel);
        expect(getInstantiateCallCount()).toBe(1);
    });

    it('retries loading after a failed kernel instantiation', async () => {
        const {
            getInstantiateCallCount,
            loadMockKernel,
            rejectNextInstantiation,
        } = createMockKernelExports();
        rejectNextInstantiation(new Error('first load failed'));

        await expect(loadMockKernel()).rejects.toThrow('first load failed');
        const kernel = await loadMockKernel();

        expect(kernel.exportedFunctionNames).toContain('memory');
        expect(getInstantiateCallCount()).toBe(2);
    });
});
