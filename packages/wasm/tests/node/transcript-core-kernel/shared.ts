// Shared transcript-core kernel fixtures.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    type GoldenTranscriptCoreFixture,
    type MalformedObjectFixture,
} from '@sealed-lattice/types';
import { afterEach, expect, vi } from 'vitest';

import {
    createTranscriptCoreKernelLoader,
    type BallotPrivacyKernelVerification,
    type TranscriptCoreKernel,
} from '../../../src/transcript-core-bridge';

import ballotFieldLinearProofBackendVectorsJson from '#test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json';
import encodedRelationVectorsJson from '#test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json';
import linearProofBackendVectorsJson from '#test-vectors/ballot-privacy/proof-backend-linear-vectors.json';
import receiverKeyLinearProofBackendVectorsJson from '#test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json';
import receiverKeyVectorsJson from '#test-vectors/ballot-privacy/receiver-key-proof-vectors.json';
import goldenTranscriptCoreFixturesJson from '#test-vectors/transcript-core/golden-transcript-core.json';
import malformedObjectFixturesJson from '#test-vectors/transcript-core/malformed-objects.json';

type NamedFixture = {
    readonly caseName: string;
};

type TranscriptCoreKernelExportsForTests = WebAssembly.Exports & {
    memory: WebAssembly.Memory;
    sealed_lattice_allocate: (length: number) => number;
    sealed_lattice_deallocate: (pointer: number, length: number) => void;
    sealed_lattice_transcript_core_command_with_length: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_roundtrip: (pointer: number, length: number) => number;
};

const goldenTranscriptCoreFixtures =
    goldenTranscriptCoreFixturesJson as readonly GoldenTranscriptCoreFixture[];

const malformedObjectFixtures =
    malformedObjectFixturesJson as readonly MalformedObjectFixture[];

const linearProofBackendVectors = linearProofBackendVectorsJson as {
    readonly requiredCaseNames: readonly string[];
    readonly cases: readonly Record<string, unknown>[];
};

const receiverKeyLinearProofBackendVectors =
    receiverKeyLinearProofBackendVectorsJson as {
        readonly requiredCaseNames: readonly string[];
        readonly cases: readonly Record<string, unknown>[];
    };

const ballotFieldLinearProofBackendVectors =
    ballotFieldLinearProofBackendVectorsJson as {
        readonly expectedProofSizeBytes: number;
        readonly linearStatement: Record<string, unknown>;
        readonly parameterSet: Record<string, unknown>;
        readonly proofEncoding: Record<string, unknown>;
        readonly proofHex: string;
        readonly publicRandomnessHex: string;
        readonly requiredCaseNames: readonly string[];
        readonly matrixCoefficientRepresentation: string;
        readonly targetCoefficientRepresentation: string;
        readonly cases: readonly Record<string, unknown>[];
    };

const encodedRelationVectors = encodedRelationVectorsJson as {
    readonly requiredCaseNames: readonly string[];
    readonly cases: readonly Record<string, unknown>[];
};

const receiverKeyVectors = receiverKeyVectorsJson as {
    readonly requiredCaseNames: readonly string[];
    readonly cases: readonly Record<string, unknown>[];
};

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

const cloneJsonValue = <JsonValue>(value: JsonValue): JsonValue =>
    JSON.parse(JSON.stringify(value)) as JsonValue;

const expectRefusalMessage = (
    verification: BallotPrivacyKernelVerification,
    expectedMessage: string,
): void => {
    expect(
        verification.refusedObjects.map((refusal) => refusal.message),
    ).toEqual(
        expect.arrayContaining([expect.stringContaining(expectedMessage)]),
    );
};

const patchInteger = (
    patch: Record<string, unknown>,
    fieldName: string,
): number => {
    const value = patch[fieldName];
    if (typeof value !== 'number' || !Number.isInteger(value)) {
        throw new Error(`${fieldName} must be an integer patch field.`);
    }

    return value;
};

const applyStatementMatrixPatch = (
    statementMatrixCoefficients: unknown,
    patch: Record<string, unknown>,
): void => {
    const matrix = statementMatrixCoefficients as number[][][];
    matrix[patchInteger(patch, 'rowIndex')][patchInteger(patch, 'columnIndex')][
        patchInteger(patch, 'coefficientIndex')
    ] = patchInteger(patch, 'coefficient');
};

const applyTargetVectorPatch = (
    targetVectorCoefficients: unknown,
    patch: Record<string, unknown>,
): void => {
    const targetVector = targetVectorCoefficients as number[][];
    targetVector[patchInteger(patch, 'rowIndex')][
        patchInteger(patch, 'coefficientIndex')
    ] = patchInteger(patch, 'coefficient');
};

const expandBallotFieldLinearProofVectorCase = (
    compactCase: Record<string, unknown>,
): Record<string, unknown> => {
    const statementMatrixCoefficients = cloneJsonValue(
        ballotFieldLinearProofBackendVectors.linearStatement
            .statementMatrixCoefficients,
    );
    const targetVectorCoefficients = cloneJsonValue(
        ballotFieldLinearProofBackendVectors.linearStatement
            .targetVectorCoefficients,
    );
    const statementMatrixPatch = compactCase.statementMatrixPatch;
    const targetVectorPatch = compactCase.targetVectorPatch;
    if (
        statementMatrixPatch !== undefined &&
        statementMatrixPatch !== null &&
        typeof statementMatrixPatch === 'object'
    ) {
        applyStatementMatrixPatch(
            statementMatrixCoefficients,
            statementMatrixPatch as Record<string, unknown>,
        );
    }
    if (
        targetVectorPatch !== undefined &&
        targetVectorPatch !== null &&
        typeof targetVectorPatch === 'object'
    ) {
        applyTargetVectorPatch(
            targetVectorCoefficients,
            targetVectorPatch as Record<string, unknown>,
        );
    }

    return {
        caseName: compactCase.caseName,
        description: compactCase.description,
        expectedOutcome: compactCase.expectedOutcome,
        expectedProofSizeBytes:
            ballotFieldLinearProofBackendVectors.expectedProofSizeBytes,
        mutation: compactCase.mutation,
        parameterSet: ballotFieldLinearProofBackendVectors.parameterSet,
        proofEncoding: ballotFieldLinearProofBackendVectors.proofEncoding,
        proofHex:
            compactCase.proofHex ??
            ballotFieldLinearProofBackendVectors.proofHex,
        publicRandomnessHex:
            compactCase.publicRandomnessHex ??
            ballotFieldLinearProofBackendVectors.publicRandomnessHex,
        statementMatrixCoefficients,
        matrixCoefficientRepresentation:
            ballotFieldLinearProofBackendVectors.matrixCoefficientRepresentation,
        targetCoefficientRepresentation:
            ballotFieldLinearProofBackendVectors.targetCoefficientRepresentation,
        targetVectorCoefficients,
        trace: compactCase.trace,
        upstreamVectorAvailable: compactCase.upstreamVectorAvailable,
    };
};

const fullyVerifiedDevelopmentIntegrationFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'fully-verified-development-integration-transcript-core',
);

const fullyVerifiedActiveFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'fully-verified-active-malicious-transcript-core',
);

const invalidEnumFixture = findFixture(malformedObjectFixtures, 'invalid-enum');

const singleZeroByteSha256Hex =
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d';

const textEncoder = new TextEncoder();

const textDecoder = new TextDecoder();

const wasmHeader = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);

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
    allowUnpinnedKernel = false,
    expectedKernelSha256Hex = singleZeroByteSha256Hex,
    onCommand,
    outputLengthAllocationPointer = 512,
    roundTripPointer = allocationPointer,
}: {
    readonly allowUnpinnedKernel?: boolean;
    readonly allocationPointer?: number;
    readonly commandPointer?: number;
    readonly commandResponse?: unknown;
    readonly expectedKernelSha256Hex?: string;
    readonly onCommand?: () => void;
    readonly outputLengthAllocationPointer?: number;
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
    const allocationPointers = [
        allocationPointer,
        outputLengthAllocationPointer,
    ];
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
                sealed_lattice_allocate: vi.fn(
                    () => allocationPointers.shift() ?? allocationPointer,
                ),
                sealed_lattice_deallocate: deallocate,
                sealed_lattice_transcript_core_command_with_length: vi.fn(
                    (
                        _pointer: number,
                        _length: number,
                        outputLengthPointer: number,
                    ) => {
                        onCommand?.();
                        new Uint8Array(memory.buffer).set(
                            encodedCommandResponse,
                            commandPointer,
                        );
                        new DataView(memory.buffer).setUint32(
                            outputLengthPointer,
                            encodedCommandResponse.length,
                            true,
                        );

                        return commandPointer;
                    },
                ),
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
        {
            kind: 'function',
            name: 'sealed_lattice_transcript_core_command_with_length',
        },
        { kind: 'function', name: 'sealed_lattice_roundtrip' },
    ]);

    return {
        deallocate,
        encodedCommandResponseLength: encodedCommandResponse.length,
        getInstantiateCallCount: () => instantiate.mock.calls.length,
        loadMockKernel: createTranscriptCoreKernelLoader(
            pathToFileURL(path.resolve('mock-sealed-lattice-kernel.wasm')),
            allowUnpinnedKernel
                ? { allowUnpinnedKernel: true }
                : { expectedKernelSha256Hex },
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

export {
    linearProofBackendVectors,
    receiverKeyLinearProofBackendVectors,
    ballotFieldLinearProofBackendVectors,
    encodedRelationVectors,
    receiverKeyVectors,
    findFixture,
    cloneJsonValue,
    expectRefusalMessage,
    expandBallotFieldLinearProofVectorCase,
    fullyVerifiedDevelopmentIntegrationFixture,
    fullyVerifiedActiveFixture,
    invalidEnumFixture,
    textEncoder,
    textDecoder,
    wasmHeader,
    createMockKernelExports,
};
export type { NamedFixture };
