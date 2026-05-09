import type {
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
} from '@sealed-lattice/protocol';
import { afterEach, describe, expect, it, vi } from 'vitest';

import goldenTranscriptCoreFixturesJson from '../../../../test-vectors/transcript-core/golden-transcript-core.json';
import malformedObjectFixturesJson from '../../../../test-vectors/transcript-core/malformed-objects.json';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    roundTripBytesThroughKernel,
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

const stagePFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'stage-p-transcript-core',
);
const stageXFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'stage-x-transcript-core',
);
const stageAFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'stage-a-transcript-core',
);
const invalidEnumFixture = findFixture(malformedObjectFixtures, 'invalid-enum');

const createMockKernelExports = ({
    allocationPointer = 12,
    commandPointer = 128,
    roundTripPointer = allocationPointer,
}: {
    readonly allocationPointer?: number;
    readonly commandPointer?: number;
    readonly roundTripPointer?: number;
} = {}): {
    readonly deallocate: ReturnType<typeof vi.fn>;
    readonly encodedCommandResponseLength: number;
} => {
    const commandResponse = {
        success: true,
        value: {
            chunkRoot: 'abc123',
        },
    };
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

    vi.spyOn(
        webAssemblyWithByteSourceInstantiate,
        'instantiate',
    ).mockResolvedValue(instantiatedSource);
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
    };
};

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

        const stagePAnalysis = kernel.analyzeCanonicalObject({
            canonicalBytesHex: stagePFixture.canonicalBytesHex,
            chunkSize: stagePFixture.chunkSize,
        });
        const stageAAnalysis = kernel.analyzeCanonicalObject({
            canonicalBytesHex: stageAFixture.canonicalBytesHex,
            chunkSize: stageAFixture.chunkSize,
        });
        const stageXAnalysis = kernel.analyzeCanonicalObject({
            canonicalBytesHex: stageXFixture.canonicalBytesHex,
            chunkSize: stageXFixture.chunkSize,
        });

        expect(stagePAnalysis.objectHash512).toBe(
            stagePFixture.expectedObjectHash512,
        );
        expect(stagePAnalysis.chunkRoot).toBe(stagePFixture.expectedChunkRoot);
        expect(stagePAnalysis.statusLabels).toEqual(
            stagePFixture.expectedStatusLabels,
        );
        expect(stageAAnalysis.securityProfile).toBe('StageA');
        expect(stageAAnalysis.objectHash512).toBe(
            stageAFixture.expectedObjectHash512,
        );
        expect(stageXAnalysis.securityProfile).toBe('StageX');
        expect(stageXAnalysis.evaluationProofProfileId).toBe(
            'transcript-core-optional-evaluation-proof-profile-v1',
        );
        expect(stageAAnalysis.objectHash512).not.toBe(
            stagePAnalysis.objectHash512,
        );
        expect(stageXAnalysis.objectHash512).not.toBe(
            stagePAnalysis.objectHash512,
        );
    });

    it('verifies golden and malformed fixtures with stable outputs', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.verifyFixture(stagePFixture)).toEqual({
            verified: true,
            caseName: 'stage-p-transcript-core',
            objectHash512: stagePFixture.expectedObjectHash512,
            chunkRoot: stagePFixture.expectedChunkRoot,
            statusLabels: stagePFixture.expectedStatusLabels,
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

    it('deallocates command inputs and outputs', async () => {
        const { deallocate, encodedCommandResponseLength } =
            createMockKernelExports();
        const kernel = await loadTranscriptCoreKernel();

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

    it('deallocates aliased round-trip pointers only once', async () => {
        const { deallocate } = createMockKernelExports();
        const kernel = await loadTranscriptCoreKernel();

        expect(
            Array.from(kernel.roundTripBytes(Uint8Array.from([2, 4, 6, 8]))),
        ).toEqual([2, 4, 6, 8]);
        expect(deallocate).toHaveBeenCalledTimes(1);
        expect(deallocate).toHaveBeenCalledWith(12, 4);
    });

    it('rejects null pointers for non-empty allocations', async () => {
        createMockKernelExports({
            allocationPointer: 0,
        });
        const kernel = await loadTranscriptCoreKernel();

        expect(() => kernel.roundTripBytes(Uint8Array.from([1]))).toThrow(
            'The transcript-core kernel returned a null pointer for a non-empty allocation.',
        );
    });
});
