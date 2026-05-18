import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    evaluationProofProfileId,
    type GoldenTranscriptCoreFixture,
    type MalformedObjectFixture,
} from '@sealed-lattice/types';
import { afterEach, describe, expect, it, vi } from 'vitest';

import ballotFieldLinearProofBackendVectorsJson from '../../../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json';
import encodedRelationVectorsJson from '../../../../test-vectors/ballot-privacy/encoded-ballot-linear-relation-vectors.json';
import linearProofBackendVectorsJson from '../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json';
import receiverKeyLinearProofBackendVectorsJson from '../../../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json';
import receiverKeyVectorsJson from '../../../../test-vectors/ballot-privacy/receiver-key-proof-vectors.json';
import goldenTranscriptCoreFixturesJson from '../../../../test-vectors/transcript-core/golden-transcript-core.json';
import malformedObjectFixturesJson from '../../../../test-vectors/transcript-core/malformed-objects.json';
import {
    loadTranscriptCoreKernel,
    roundTripBytesThroughKernel,
    verifyTranscriptCoreFixture,
} from '../../src/index';
import {
    createTranscriptCoreKernelLoader,
    currentTranscriptCoreKernelNormalizedSha256HexByBuildRunner,
    normalizeTranscriptCoreKernelBytesForDigest,
    TranscriptCoreKernelCommandError,
    type TranscriptCoreKernelBuildRunner,
    type TranscriptCoreKernel,
} from '../../src/transcript-core-bridge';

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
        targetCoefficientRepresentation:
            ballotFieldLinearProofBackendVectors.targetCoefficientRepresentation,
        targetVectorCoefficients,
        trace: compactCase.trace,
        upstreamVectorAvailable: compactCase.upstreamVectorAvailable,
    };
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
    expectedKernelSha256Hex = singleZeroByteSha256Hex,
    onCommand,
    outputLengthAllocationPointer = 512,
    roundTripPointer = allocationPointer,
}: {
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
            { expectedKernelSha256Hex },
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
    it('keeps the current kernel digest manifest scoped to supported build runners', () => {
        const buildRunners = [
            'githubActionsMacosLatest',
            'githubActionsUbuntuLatest',
            'windowsDeveloperBuild',
        ] as const satisfies readonly TranscriptCoreKernelBuildRunner[];
        const digestEntries = buildRunners.map((buildRunner) => [
            buildRunner,
            currentTranscriptCoreKernelNormalizedSha256HexByBuildRunner[
                buildRunner
            ],
        ]);

        expect(
            digestEntries.map(([buildRunner]) => buildRunner).sort(),
        ).toEqual([...buildRunners].sort());
        expect(new Set(digestEntries.map(([, digest]) => digest)).size).toBe(
            digestEntries.length,
        );
        for (const [, digest] of digestEntries) {
            expect(digest).toMatch(/^[a-f0-9]{64}$/u);
        }
    });

    it('normalizes host-specific Rust source paths before digesting', () => {
        const windowsBytes = textEncoder.encode(
            [
                'prefix',
                'C:\\Users\\Piotr\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\serde_json-1.0.149\\src\\error.rs',
                'crates\\sealed-lattice-kernel\\src\\lib.rs',
                'suffix',
            ].join('\0'),
        );
        const linuxBytes = textEncoder.encode(
            [
                'prefix',
                '/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.149/src/error.rs',
                'crates/sealed-lattice-kernel/src/lib.rs',
                'suffix',
            ].join('\0'),
        );

        const normalizedWindowsBytes =
            normalizeTranscriptCoreKernelBytesForDigest(windowsBytes);
        const normalizedLinuxBytes =
            normalizeTranscriptCoreKernelBytesForDigest(linuxBytes);

        expect(Array.from(normalizedWindowsBytes)).toEqual(
            Array.from(normalizedLinuxBytes),
        );
        expect(textDecoder.decode(normalizedWindowsBytes)).toBe(
            [
                'prefix',
                '/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.149/src/error.rs',
                'crates/sealed-lattice-kernel/src/lib.rs',
                'suffix',
            ].join('\0'),
        );
    });

    it('ignores WASM custom sections before digesting', () => {
        const leftCustomSection = Uint8Array.from([0, 4, 3, 111, 110, 101]);
        const rightCustomSection = Uint8Array.from([0, 4, 3, 116, 119, 111]);
        const emptyTypeSection = Uint8Array.from([1, 1, 0]);

        const leftBytes = Uint8Array.from([
            ...wasmHeader,
            ...leftCustomSection,
            ...emptyTypeSection,
        ]);
        const rightBytes = Uint8Array.from([
            ...wasmHeader,
            ...rightCustomSection,
            ...emptyTypeSection,
        ]);

        expect(
            Array.from(normalizeTranscriptCoreKernelBytesForDigest(leftBytes)),
        ).toEqual(
            Array.from(normalizeTranscriptCoreKernelBytesForDigest(rightBytes)),
        );
        expect(
            Array.from(normalizeTranscriptCoreKernelBytesForDigest(leftBytes)),
        ).toEqual(
            Array.from(Uint8Array.from([...wasmHeader, ...emptyTypeSection])),
        );
    });

    it('rejects malformed WASM sections before digesting', () => {
        const invalidLengthBytes = Uint8Array.from([
            ...wasmHeader,
            1,
            0x80,
            0x80,
            0x80,
            0x80,
            0x80,
        ]);
        const truncatedLengthBytes = Uint8Array.from([...wasmHeader, 1, 0x80]);
        const truncatedSectionBytes = Uint8Array.from([...wasmHeader, 1, 2, 0]);

        expect(() =>
            normalizeTranscriptCoreKernelBytesForDigest(invalidLengthBytes),
        ).toThrow(
            'The transcript-core kernel contains an invalid WASM section length.',
        );
        expect(() =>
            normalizeTranscriptCoreKernelBytesForDigest(truncatedLengthBytes),
        ).toThrow(
            'The transcript-core kernel contains a truncated WASM section length.',
        );
        expect(() =>
            normalizeTranscriptCoreKernelBytesForDigest(truncatedSectionBytes),
        ).toThrow(
            'The transcript-core kernel contains a truncated WASM section.',
        );
    });

    it('loads the transcript-core module and exposes command exports', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_transcript_core_command_with_length',
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
            evaluationProofProfileId,
        );
        expect(fullyVerifiedActiveAnalysis.mheSecurityClosure).toBe(
            'ActiveMalicious',
        );
        expect(fullyVerifiedActiveAnalysis.evaluationProofProfileId).toBe(
            evaluationProofProfileId,
        );
        expect(fullyVerifiedPassiveAnalysis.objectHash512).not.toBe(
            fullyVerifiedActiveAnalysis.objectHash512,
        );
    });

    it('derives claim-bearing digests and field results through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.deriveProtocolDigest({
                namespace: 'PollSpecDigest',
                value: { poll: 'main' },
            }),
        ).toBe(
            '423c71de65abadb5adc05d9b6b704252420bb738af888c62614c8afc53a2be808662585305e76738b23e4f20154f8779e3827c0c8f313455d84675924f4a2c83',
        );
        expect(
            kernel.interpolateShamirConstantTerm({
                sharePoints: [
                    { rosterPosition: 1, value: 15 },
                    { rosterPosition: 2, value: 25 },
                ],
            }),
        ).toBe(5);
        expect(
            kernel.evaluatePlaintextComparison({
                leftTotalScore: 41,
                rightTotalScore: 40,
                rosterSize: 5,
            }),
        ).toEqual({
            greaterThan: 1,
            equal: 0,
            scoreDifference: 1,
        });
        expect(() =>
            kernel.deriveProtocolDigest({
                namespace: 'UnreservedDigest',
                value: {},
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
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
        expect(kernel.listCanonicalErrorCodes()).toContain('InvalidEnum');
        expect(kernel.listReservedRootNamespaces()).toContain(
            'sealed-lattice-root/poll-spec-digest-v1',
        );
        expect(kernel.listReservedRootNamespaces()).toContain(
            'sealed-lattice-root/proof-bytes-digest-v1',
        );
    });

    it('keeps ballot privacy proof commands fail-closed until the backend is available', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const backendStatus = kernel.describeBallotPrivacyProofBackend();

        expect(backendStatus).toMatchObject({
            backendAvailable: false,
            portableRustWasmPortRequired: true,
        });
        expect(backendStatus.requiredComponents).toEqual(
            expect.arrayContaining([
                'ABDLop commitment key generation, commitment, and commitment hashing',
                'tbox proof generation and verification',
                'browser-safe prover randomness source',
            ]),
        );

        expect(
            kernel.verifyReceiverKeyProof({ receiverKeyProof: {} }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            backendStatus: {
                portableRustWasmPortRequired: true,
            },
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            kernel.verifyBallotProof({ statement: {}, ballotProof: {} }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            backendStatus: {
                portableRustWasmPortRequired: true,
            },
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            kernel
                .verifyBallotProof({
                    statement: {},
                    ballotProof: {
                        proofBytesDigest: '0'.repeat(128),
                        proofSizeBytes: 1,
                    },
                    proofBytesHex: 'AA',
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes('proof bytes'),
                ),
        ).toBe(true);
        expect(
            kernel.verifyClaimBearingBallotPackage({ ballotPackage: {} }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            backendStatus: {
                portableRustWasmPortRequired: true,
            },
            operation: 'verifyClaimBearingBallotPackage',
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('routes internal linear proof vectors through the WASM backend gate', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const demoVectorCaseNames = new Set(
            linearProofBackendVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );
        const receiverKeyVectorCaseNames = new Set(
            receiverKeyLinearProofBackendVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );
        const ballotFieldVectorCaseNames = new Set(
            ballotFieldLinearProofBackendVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );

        for (const requiredCaseName of linearProofBackendVectors.requiredCaseNames) {
            expect(demoVectorCaseNames.has(requiredCaseName)).toBe(true);
        }
        for (const requiredCaseName of receiverKeyLinearProofBackendVectors.requiredCaseNames) {
            expect(receiverKeyVectorCaseNames.has(requiredCaseName)).toBe(true);
        }
        for (const requiredCaseName of ballotFieldLinearProofBackendVectors.requiredCaseNames) {
            expect(ballotFieldVectorCaseNames.has(requiredCaseName)).toBe(true);
        }

        const demoVerification = kernel.verifyBallotPrivacyLinearProofVector({
            vectorCase: linearProofBackendVectors.cases[0],
        });

        expect(demoVerification).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'valid-small-linear-proof',
            vectorAvailable: true,
            unresolvedReason: null,
        });
        expect(demoVerification.statusLabels).toContain(
            'QuadraticChallengeRecomputed',
        );

        const receiverKeyLinearProofCases =
            receiverKeyLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validReceiverKeyCase = findFixture(
            receiverKeyLinearProofCases,
            'valid-receiver-key-linear-proof',
        );
        const mutatedReceiverKeyCase = findFixture(
            receiverKeyLinearProofCases,
            'mutated-receiver-key-target-vector',
        );
        const receiverKeyVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: validReceiverKeyCase,
            });
        const mutatedReceiverKeyVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: mutatedReceiverKeyCase,
            });

        expect(receiverKeyVerification).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'valid-receiver-key-linear-proof',
            vectorAvailable: true,
            unresolvedReason: null,
        });
        expect(receiverKeyVerification.statusLabels).toContain(
            'QuadraticChallengeRecomputed',
        );
        expect(mutatedReceiverKeyVerification).toMatchObject({
            ok: false,
            backendAvailable: false,
            caseName: 'mutated-receiver-key-target-vector',
            vectorAvailable: true,
            unresolvedReason: 'InvalidFixture',
        });

        const ballotFieldLinearProofCases =
            ballotFieldLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validBallotFieldCase = findFixture(
            ballotFieldLinearProofCases,
            'valid-encoded-score-field-linear-proof',
        );
        const mutatedBallotFieldCase = findFixture(
            ballotFieldLinearProofCases,
            'mutated-encoded-score-field-target-vector',
        );
        const ballotFieldVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase:
                    expandBallotFieldLinearProofVectorCase(
                        validBallotFieldCase,
                    ),
            });
        const mutatedBallotFieldVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: expandBallotFieldLinearProofVectorCase(
                    mutatedBallotFieldCase,
                ),
            });

        expect(ballotFieldVerification).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'valid-encoded-score-field-linear-proof',
            vectorAvailable: true,
            unresolvedReason: null,
        });
        expect(ballotFieldVerification.statusLabels).toContain(
            'QuadraticChallengeRecomputed',
        );
        expect(mutatedBallotFieldVerification).toMatchObject({
            ok: false,
            backendAvailable: false,
            caseName: 'mutated-encoded-score-field-target-vector',
            vectorAvailable: true,
            unresolvedReason: 'InvalidFixture',
        });
    });

    it('routes encoded ballot relation vectors through the WASM backend gate', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const vectorCaseNames = new Set(
            encodedRelationVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );

        for (const requiredCaseName of encodedRelationVectors.requiredCaseNames) {
            expect(vectorCaseNames.has(requiredCaseName)).toBe(true);
        }

        const miniCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'mini-encoded-ballot-relation',
        );
        const rejectCase = encodedRelationVectors.cases.find(
            (vectorCase) => vectorCase.caseName === 'wrong-quotient-rejects',
        );
        const digestChangeCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'wrong-share-commitment-target-changes-digest',
        );
        const explicitShareCommitmentCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'mini-encoded-ballot-share-commitment-explicit-relation',
        );
        const fullExplicitCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'mini-encoded-ballot-full-explicit-relation',
        );
        const backendPreflightRejectCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'noncanonical-backend-coefficient-rejects',
        );
        const proofComponentRejectCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'backend-proof-component-mutation-rejects',
        );

        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: miniCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'mini-encoded-ballot-relation',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: rejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'wrong-quotient-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: digestChangeCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'wrong-share-commitment-target-changes-digest',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: explicitShareCommitmentCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'mini-encoded-ballot-share-commitment-explicit-relation',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: fullExplicitCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'mini-encoded-ballot-full-explicit-relation',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: backendPreflightRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'noncanonical-backend-coefficient-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: proofComponentRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'backend-proof-component-mutation-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
    });

    it('routes receiver-key proof vectors through the WASM backend gate', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const vectorCaseNames = new Set(
            receiverKeyVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );

        for (const requiredCaseName of receiverKeyVectors.requiredCaseNames) {
            expect(vectorCaseNames.has(requiredCaseName)).toBe(true);
        }

        const validCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'valid-receiver-key-proof-backend-statement',
        );
        const constructionRejectCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'wrong-public-matrix-seed-rejects',
        );
        const backendPreflightRejectCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'noncanonical-backend-modulus-rejects',
        );
        const linearPreflightRejectCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'mutated-linear-statement-target-rejects',
        );
        const proofShellRejectCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'mutated-proof-root-rejects',
        );

        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: validCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'valid-receiver-key-proof-backend-statement',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: constructionRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'wrong-public-matrix-seed-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: backendPreflightRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'noncanonical-backend-modulus-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: linearPreflightRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'mutated-linear-statement-target-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: proofShellRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'mutated-proof-root-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
    });

    it('verifies proof-byte-bearing receiver-key records through the WASM linear proof backend', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const receiverKeyLinearProofCases =
            receiverKeyLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validProofCase = findFixture(
            receiverKeyLinearProofCases,
            'valid-receiver-key-linear-proof',
        );
        const mutatedTargetCase = findFixture(
            receiverKeyLinearProofCases,
            'mutated-receiver-key-target-vector',
        );
        const proofBytesHex = String(validProofCase.proofHex);
        const publicRandomnessHex = String(validProofCase.publicRandomnessHex);
        const proofSizeBytes = proofBytesHex.length / 2;
        const digest = (label: string): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    label,
                    purpose: 'receiver-key-proof-record-wasm-test',
                },
            });
        const createLinearStatement = (
            targetVectorCoefficients: unknown,
        ): Record<string, unknown> => {
            const statementPayload = {
                ceremonyId: 'ceremony-receiver-key-proof-record',
                coefficientModulus: '12289',
                keyMaterialDigest: digest('receiver-key-material'),
                manifestDigest: digest('manifest'),
                objectType: 'ReceiverKeyLinearProofStatement',
                objectVersion: 1,
                publicMatrixSeedDigest: digest('receiver-matrix-seed'),
                receiverEncryptionProfileDigest: digest(
                    'receiver-encryption-profile',
                ),
                receiverIdentity: 'receiver-1',
                receiverPublicKeyDigest: digest('receiver-public-key'),
                receiverRosterPosition: 1,
                recoveryEpoch: 0,
                relation: 'A*w + t = 0',
                ringDegree: 256,
                rosterDigest: digest('roster'),
                sourceRing: 'Z_q[X]/(X^256 + 1)',
                statementColumns: 8,
                statementMatrixCoefficients:
                    validProofCase.statementMatrixCoefficients,
                statementMatrixDigest: digest('statement-matrix'),
                statementProfileId:
                    'receiver-key-linear-module-lwe-statement-v1',
                statementRows: 4,
                targetCoefficientRepresentation:
                    validProofCase.targetCoefficientRepresentation,
                targetVectorCoefficients,
                targetVectorDigest: digest('target-vector'),
                witnessInfinityNormBound: 2,
                witnessL2BoundSquared: '8192',
                witnessVectorLayout: [
                    'receiver secret polynomial 0',
                    'receiver secret polynomial 1',
                    'receiver secret polynomial 2',
                    'receiver secret polynomial 3',
                    'receiver error polynomial 0',
                    'receiver error polynomial 1',
                    'receiver error polynomial 2',
                    'receiver error polynomial 3',
                ],
            };

            return {
                ...statementPayload,
                statementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: statementPayload,
                        purpose: 'receiver-key-linear-proof-statement-v1',
                    },
                }),
            };
        };
        const createReceiverKeyProof = (
            linearStatement: Record<string, unknown>,
            proofInput: {
                readonly parameterSet?: unknown;
                readonly proofEncoding?: unknown;
            } = {},
        ): Record<string, unknown> => {
            const parameterSet =
                proofInput.parameterSet ?? validProofCase.parameterSet;
            const proofEncoding =
                proofInput.proofEncoding ?? validProofCase.proofEncoding;
            const proofBytesDigest = kernel.deriveProtocolDigest({
                namespace: 'ProofBytesDigest',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex,
                    proofSizeBytes,
                },
            });
            const proofEncodingProfileDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    proofEncoding,
                    purpose: 'receiver-key-linear-proof-encoding-profile-v1',
                },
            });
            const proofParameterSetDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    parameterSet,
                    purpose: 'receiver-key-linear-proof-parameter-set-v1',
                },
            });
            const publicRandomnessDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    publicRandomnessHex,
                    purpose: 'receiver-key-linear-proof-public-randomness-v1',
                },
            });
            const proofRoot = kernel.deriveProtocolDigest({
                namespace: 'ReceiverKeyProofRoot',
                value: {
                    linearStatementDigest: linearStatement.statementDigest,
                    proofBytesDigest,
                    proofEncodingProfileDigest,
                    proofParameterSetDigest,
                    publicRandomnessDigest,
                    purpose: 'receiver-key-linear-proof-record-root-v1',
                },
            });
            const proofPayload = {
                backendStatementDigest: digest('backend-statement'),
                ceremonyId: 'ceremony-receiver-key-proof-record',
                linearStatementDigest: linearStatement.statementDigest,
                manifestDigest: digest('manifest'),
                objectType: 'ReceiverKeyProof',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofRoot,
                proofSizeBytes,
                publicRandomnessDigest,
                receiverEncryptionProfileDigest: digest(
                    'receiver-encryption-profile',
                ),
                receiverIdentity: 'receiver-1',
                receiverPublicKeyDigest: digest('receiver-public-key'),
                receiverRosterPosition: 1,
                recoveryEpoch: 0,
                rosterDigest: digest('roster'),
            };

            return {
                ...proofPayload,
                receiverKeyProofRoot: kernel.deriveProtocolDigest({
                    namespace: 'ReceiverKeyProofRoot',
                    value: proofPayload,
                }),
            };
        };
        const validLinearStatement = createLinearStatement(
            validProofCase.targetVectorCoefficients,
        );
        const validReceiverKeyProof =
            createReceiverKeyProof(validLinearStatement);
        const mutatedLinearStatement = createLinearStatement(
            mutatedTargetCase.targetVectorCoefficients,
        );
        const mutatedReceiverKeyProof = createReceiverKeyProof(
            mutatedLinearStatement,
        );

        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: validLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex,
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                receiverKeyProof: validReceiverKeyProof,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: false,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: mutatedLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex,
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                receiverKeyProof: mutatedReceiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'InvalidFixture',
        });
        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: validLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex: proofBytesHex.slice(0, -2),
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                receiverKeyProof: validReceiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        const sizeUnboundParameterSet = {
            ...(validProofCase.parameterSet as Record<string, unknown>),
            expectedProofSizeBytes: proofSizeBytes + 1,
        };
        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: validLinearStatement,
                parameterSet: sizeUnboundParameterSet,
                proofBytesHex,
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                receiverKeyProof: createReceiverKeyProof(validLinearStatement, {
                    parameterSet: sizeUnboundParameterSet,
                }),
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        const sizeUnboundProofEncoding = {
            ...(validProofCase.proofEncoding as Record<string, unknown>),
            expectedProofSizeBytes: proofSizeBytes + 1,
        };
        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: validLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex,
                proofEncoding: sizeUnboundProofEncoding,
                publicRandomnessHex,
                receiverKeyProof: createReceiverKeyProof(validLinearStatement, {
                    proofEncoding: sizeUnboundProofEncoding,
                }),
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('prepares receiver-key proof generation witness material through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const receiverKeyLinearProofCases =
            receiverKeyLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validProofCase = findFixture(
            receiverKeyLinearProofCases,
            'valid-receiver-key-linear-proof',
        );
        const receiverKeyModulus = 12_289;
        const receiverKeyRingDegree = 256;
        const receiverKeyStatementRows = 4;
        const receiverKeyStatementColumns = 8;
        const createZeroPolynomial = (): number[] =>
            Array.from({ length: receiverKeyRingDegree }, () => 0);
        const createUnitPolynomial = (): number[] => {
            const polynomial = createZeroPolynomial();
            polynomial[0] = 1;

            return polynomial;
        };
        const canonicalSignedPolynomial = (
            polynomial: readonly number[],
        ): number[] =>
            polynomial.map((coefficient) =>
                coefficient < 0
                    ? receiverKeyModulus - Math.abs(coefficient)
                    : Math.abs(coefficient),
            );
        const witnessVector: number[][] = Array.from(
            { length: receiverKeyStatementColumns },
            () => createZeroPolynomial(),
        );
        witnessVector[0][0] = 2;
        witnessVector[0][5] = -1;
        witnessVector[1][1] = 1;
        witnessVector[4][0] = -2;
        witnessVector[5][7] = 1;
        const statementMatrixCoefficients = Array.from(
            { length: receiverKeyStatementRows },
            () =>
                Array.from(
                    { length: receiverKeyStatementColumns },
                    createZeroPolynomial,
                ),
        );
        for (
            let rowIndex = 0;
            rowIndex < receiverKeyStatementRows;
            rowIndex += 1
        ) {
            const statementMatrixRow = statementMatrixCoefficients[rowIndex];
            statementMatrixRow[rowIndex] = createUnitPolynomial();
            statementMatrixRow[rowIndex + receiverKeyStatementRows] =
                createUnitPolynomial();
        }
        const targetVectorCoefficients = Array.from(
            { length: receiverKeyStatementRows },
            (_, rowIndex) => {
                const secretPolynomial = canonicalSignedPolynomial(
                    witnessVector[rowIndex],
                );
                const errorPolynomial = canonicalSignedPolynomial(
                    witnessVector[rowIndex + receiverKeyStatementRows],
                );

                return secretPolynomial.map((coefficient, coefficientIndex) => {
                    const publicKeyCoefficient =
                        (coefficient +
                            (errorPolynomial[coefficientIndex] ?? 0)) %
                        receiverKeyModulus;

                    return publicKeyCoefficient === 0
                        ? 0
                        : receiverKeyModulus - publicKeyCoefficient;
                });
            },
        );
        const digest = (label: string): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    label,
                    purpose: 'receiver-key-prover-preflight-wasm-test',
                },
            });
        const linearStatementPayload = {
            ceremonyId: 'ceremony-receiver-key-prover-preflight',
            coefficientModulus: '12289',
            keyMaterialDigest: digest('receiver-key-material'),
            manifestDigest: digest('manifest'),
            objectType: 'ReceiverKeyLinearProofStatement',
            objectVersion: 1,
            publicMatrixSeedDigest: digest('receiver-matrix-seed'),
            receiverEncryptionProfileDigest: digest(
                'receiver-encryption-profile',
            ),
            receiverIdentity: 'receiver-1',
            receiverPublicKeyDigest: digest('receiver-public-key'),
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            relation: 'A*w + t = 0',
            ringDegree: receiverKeyRingDegree,
            rosterDigest: digest('roster'),
            sourceRing: 'Z_q[X]/(X^256 + 1)',
            statementColumns: receiverKeyStatementColumns,
            statementMatrixCoefficients,
            statementMatrixDigest: digest('statement-matrix'),
            statementProfileId: 'receiver-key-linear-module-lwe-statement-v1',
            statementRows: receiverKeyStatementRows,
            targetCoefficientRepresentation: 'centeredSignedSourceModulus',
            targetVectorCoefficients,
            targetVectorDigest: digest('target-vector'),
            witnessInfinityNormBound: 2,
            witnessL2BoundSquared: '8192',
            witnessVectorLayout: [
                'receiver secret polynomial 0',
                'receiver secret polynomial 1',
                'receiver secret polynomial 2',
                'receiver secret polynomial 3',
                'receiver error polynomial 0',
                'receiver error polynomial 1',
                'receiver error polynomial 2',
                'receiver error polynomial 3',
            ],
        };
        const linearStatement = {
            ...linearStatementPayload,
            statementDigest: kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    payload: linearStatementPayload,
                    purpose: 'receiver-key-linear-proof-statement-v1',
                },
            }),
        };
        const secretState = {
            secretVector: witnessVector.slice(0, receiverKeyStatementRows),
            errorVector: witnessVector.slice(receiverKeyStatementRows),
        };
        const preparation = kernel.prepareReceiverKeyProofGeneration({
            linearStatement,
            parameterSet: validProofCase.parameterSet,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState,
            proverRandomnessHex: '09'.repeat(32),
        });

        expect(preparation).toMatchObject({
            ok: true,
            backendAvailable: false,
            generatedProofBytes: false,
            operation: 'prepareReceiverKeyProofGeneration',
            summary: {
                normSlack: '8181',
                preparedShortWitnessPolynomialCount: 33,
                relationWitnessPolynomialCount: 32,
                shortWitnessPolynomialCount: 33,
                witnessL2Squared: '11',
                abdlopCommitment: {
                    compressedCommitmentPolynomialCount: 19,
                    openingRandomnessPolynomialCount: 55,
                    openingRemainderPolynomialCount: 19,
                    proverRandomnessSeedBytes: 32,
                    subprotocolSeedBytes: 32,
                },
            },
            unresolvedReason: null,
        });
        expect(preparation.statusLabels).toContain(
            'ReceiverKeyProofRingWitnessPrepared',
        );
        expect(preparation.statusLabels).toContain(
            'ReceiverKeyAbdlopCommitmentPrepared',
        );
        expect(
            preparation.summary?.abdlopCommitment?.abdlopCommitmentHash,
        ).toMatch(/^[0-9a-f]{64}$/u);

        const generatedProof = kernel.generateReceiverKeyProof({
            linearStatement,
            parameterSet: validProofCase.parameterSet,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState,
            proverRandomnessHex: '09'.repeat(32),
        });
        const repeatedGeneratedProof = kernel.generateReceiverKeyProof({
            linearStatement,
            parameterSet: validProofCase.parameterSet,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState,
            proverRandomnessHex: '09'.repeat(32),
        });
        const changedGeneratedProof = kernel.generateReceiverKeyProof({
            linearStatement,
            parameterSet: validProofCase.parameterSet,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState,
            proverRandomnessHex: '0a'.repeat(32),
        });

        expect(generatedProof).toMatchObject({
            ok: true,
            backendAvailable: false,
            generatedProofBytes: true,
            operation: 'generateReceiverKeyProof',
            unresolvedReason: null,
        });
        expect(generatedProof.statusLabels).toContain(
            'ReceiverKeyGeneratedProofVerified',
        );
        expect(generatedProof.proofBytesHex).toMatch(/^[0-9a-f]+$/u);
        expect(generatedProof.proofSizeBytes).toBe(
            String(generatedProof.proofBytesHex).length / 2,
        );
        expect(repeatedGeneratedProof.proofBytesHex).toBe(
            generatedProof.proofBytesHex,
        );
        expect(changedGeneratedProof.proofBytesHex).not.toBe(
            generatedProof.proofBytesHex,
        );

        const generatedVectorCase = {
            caseName: 'generated-receiver-key-proof',
            description:
                'Receiver-key linear proof generated by the internal Rust prover.',
            mutation: 'none',
            expectedOutcome: 'accept',
            upstreamVectorAvailable: true,
            parameterSet: validProofCase.parameterSet,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            statementMatrixCoefficients,
            targetVectorCoefficients,
            targetCoefficientRepresentation: 'centeredSignedSourceModulus',
            proofHex: generatedProof.proofBytesHex,
            expectedProofSizeBytes: generatedProof.proofSizeBytes,
        };
        const generatedVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: generatedVectorCase,
            });
        expect(generatedVerification).toMatchObject({
            ok: true,
            backendAvailable: false,
            caseName: 'generated-receiver-key-proof',
            unresolvedReason: null,
        });

        const mutatedGeneratedVectorCase = cloneJsonValue(generatedVectorCase);
        mutatedGeneratedVectorCase.caseName =
            'generated-receiver-key-proof-mutated-target';
        mutatedGeneratedVectorCase.expectedOutcome = 'reject';
        mutatedGeneratedVectorCase.targetVectorCoefficients[0][0] =
            (mutatedGeneratedVectorCase.targetVectorCoefficients[0][0] + 1) %
            receiverKeyModulus;
        expect(
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: mutatedGeneratedVectorCase,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            caseName: 'generated-receiver-key-proof-mutated-target',
            unresolvedReason: 'InvalidFixture',
        });

        const wrongSecretState = cloneJsonValue(secretState);
        wrongSecretState.secretVector[0][0] = 3;
        const rejection = kernel.prepareReceiverKeyProofGeneration({
            linearStatement,
            parameterSet: validProofCase.parameterSet,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState: wrongSecretState,
            proverRandomnessHex: '09'.repeat(32),
        });

        expect(rejection).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'prepareReceiverKeyProofGeneration',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(String(rejection.refusedObjects[0]?.message)).toContain(
            'source witness',
        );
    });

    it('generates ballot and dense component proof bytes through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const ringDegree = 64;
        const coefficientModulus = 65_537;
        const createZeroPolynomial = (): number[] =>
            Array.from({ length: ringDegree }, () => 0);
        const unitPolynomial = createZeroPolynomial();
        unitPolynomial[0] = 1;
        const targetPolynomial = createZeroPolynomial();
        targetPolynomial[0] = coefficientModulus - 5;
        const witnessPolynomial = createZeroPolynomial();
        witnessPolynomial[0] = 5;
        const parameterSet = {
            profileId: 'full-encoded-score-ballot-linear-compatibility-v1',
            source: 'sealed-lattice/linear-proof/full-encoded-score-ballot-wasm-test-parameters-v1',
            relation: 'A*w + t = 0',
            ringDegree,
            proofSystemRingDegree: ringDegree,
            coefficientModulus,
            statementRows: 1,
            statementColumns: 1,
            witnessL2BoundSquared: 65_536,
        };
        const proofEncoding = {
            ...cloneJsonValue(
                ballotFieldLinearProofBackendVectors.proofEncoding,
            ),
            profileId: 'full-encoded-score-ballot-linear-proof-encoding-v1',
            source: 'sealed-lattice/linear-proof/full-encoded-score-ballot-wasm-test-encoding-v1',
            shortResponseVectorLength: 2,
        };
        const linearStatement = {
            objectType: 'BallotProofLinearProofStatement',
            objectVersion: 1,
            parameterProfileId: parameterSet.profileId,
            projectionCoverage: 'full-encoded-score-ballot-relation',
            relation: 'A*w + t = 0',
            statementMatrixCoefficients: [[unitPolynomial]],
            targetCoefficientRepresentation: 'centeredSignedSourceModulus',
            targetVectorCoefficients: [targetPolynomial],
        };
        const secretState = {
            sourceWitnessCoefficients: [witnessPolynomial],
        };
        const publicRandomnessHex = '00'.repeat(32);
        const proverRandomnessHex = '07'.repeat(32);

        const generatedProof = kernel.generateBallotProof({
            linearStatement,
            parameterSet,
            proofEncoding,
            publicRandomnessHex,
            secretState,
            proverRandomnessHex,
        });

        expect(generatedProof).toMatchObject({
            ok: true,
            backendAvailable: false,
            generatedProofBytes: true,
            operation: 'generateBallotProof',
            unresolvedReason: null,
        });
        expect(generatedProof.statusLabels).toContain(
            'BallotGeneratedProofVerified',
        );
        expect(generatedProof.proofBytesHex).toMatch(/^[0-9a-f]+$/u);
        expect(generatedProof.proofSizeBytes).toBe(
            String(generatedProof.proofBytesHex).length / 2,
        );

        const proofInput = {
            componentId: 'score-and-shamir-field-component',
            proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
            proofStatement: linearStatement,
            proofParameterSet: parameterSet,
            proofEncoding,
            publicRandomnessHex,
        };
        const componentProof = kernel.generateBallotComponentProof({
            componentId: 'score-and-shamir-field-component',
            proofInput,
            secretState,
            proverRandomnessHex,
        });

        expect(componentProof).toMatchObject({
            ok: true,
            backendAvailable: false,
            generatedProofBytes: true,
            operation: 'generateBallotComponentProof',
            unresolvedReason: null,
        });
        expect(componentProof.statusLabels).toContain(
            'BallotComponentGeneratedProofVerified',
        );

        const wrongSecretState = {
            sourceWitnessCoefficients: [
                [6, ...createZeroPolynomial().slice(1)],
            ],
        };
        expect(
            kernel.generateBallotProof({
                linearStatement,
                parameterSet,
                proofEncoding,
                publicRandomnessHex,
                secretState: wrongSecretState,
                proverRandomnessHex,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'generateBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('rejects field-incomplete ballot records after WASM linear proof verification', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const linearProofCases =
            linearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validProofCase = findFixture(
            linearProofCases,
            'valid-small-linear-proof',
        );
        const mutatedTargetCase = findFixture(
            linearProofCases,
            'mutated-target-vector',
        );
        const proofBytesHex = String(validProofCase.proofHex);
        const publicRandomnessHex = String(validProofCase.publicRandomnessHex);
        const proofSizeBytes = proofBytesHex.length / 2;
        const validParameterSet = {
            ...cloneJsonValue(
                validProofCase.parameterSet as Record<string, unknown>,
            ),
            expectedProofSizeBytes: proofSizeBytes,
        };
        const validProofEncoding = {
            ...cloneJsonValue(
                validProofCase.proofEncoding as Record<string, unknown>,
            ),
            expectedProofSizeBytes: proofSizeBytes,
        };
        const digest = (label: string): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    label,
                    purpose: 'ballot-proof-record-wasm-test',
                },
            });
        const createStatement = (): Record<string, unknown> => {
            const statementPayload = {
                actionContextDigest: digest('action-context'),
                aggregateInputEncodingProfileDigest: digest(
                    'aggregate-input-encoding-profile',
                ),
                ballotPackageDigest: digest('ballot-package'),
                ballotProofProfileDigest: digest('ballot-proof-profile'),
                ballotScoreEncodingProfileDigest: digest(
                    'ballot-score-encoding-profile',
                ),
                ballotShareLayoutProfileDigest: digest(
                    'ballot-share-layout-profile',
                ),
                ceremonyId: 'ceremony-ballot-proof-record',
                challengeDomainDigest: digest('challenge-domain'),
                duplicateBallotPolicyDigest: digest('duplicate-policy'),
                encodedAggregateLayoutDigest: digest(
                    'encoded-aggregate-layout',
                ),
                encodedShareVectorLayoutDigest: digest(
                    'encoded-share-vector-layout',
                ),
                manifestDigest: digest('manifest'),
                objectType: 'BallotProofStatement',
                objectVersion: 1,
                optionCount: 20,
                pollSpecDigest: digest('poll-spec'),
                receiverEncryptionProfileDigest: digest(
                    'receiver-encryption-profile',
                ),
                receiverKeyProofRoot: digest('receiver-key-proof-root'),
                receiverKeyRoot: digest('receiver-key-root'),
                receiverPayloads: [
                    {
                        receiverIdentity: 'receiver-1',
                        receiverPayloadCiphertextRoot: digest(
                            'receiver-ciphertext-1',
                        ),
                        receiverPayloadDigest: digest('receiver-payload-1'),
                        receiverRosterPosition: 1,
                    },
                ],
                receiverPublicKeys: [
                    {
                        receiverIdentity: 'receiver-1',
                        receiverPublicKeyDigest: digest(
                            'receiver-public-key-1',
                        ),
                        receiverRosterPosition: 1,
                    },
                ],
                rosterDigest: digest('roster'),
                rosterExternalAcceptanceDigest: digest('external-acceptance'),
                scoreDomainDigest: digest('score-domain'),
                scoreMembershipProfileDigest: digest(
                    'score-membership-profile',
                ),
                shareCommitmentMessageBoundCertDigest: digest(
                    'share-commitment-bound-cert',
                ),
                shareCommitmentProfileDigest: digest(
                    'share-commitment-profile',
                ),
                shareCommitments: [
                    {
                        receiverIdentity: 'receiver-1',
                        receiverRosterPosition: 1,
                        shareCommitmentDigest: digest('share-commitment-1'),
                    },
                ],
                shareVectorWidth: 220,
                thresholdProfileDigest: digest('threshold-profile'),
                tiePolicyDigest: digest('tie-policy'),
                topOptionCount: 3,
                voterIdentityDigest: digest('voter-1'),
                voterRosterPosition: 1,
                voterSigningKeyDigest: digest('voter-signing-key'),
            };

            return {
                ...statementPayload,
                ballotProofStatementDigest: kernel.deriveProtocolDigest({
                    namespace: 'BallotProofStatementDigest',
                    value: statementPayload,
                }),
            };
        };
        const createLinearStatement = (
            statement: Record<string, unknown>,
            targetVectorCoefficients: unknown,
        ): Record<string, unknown> => {
            const linearStatementPayload = {
                backendStatementDigest: digest('backend-statement'),
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                coefficientModulus: '4294962689',
                objectType: 'BallotProofLinearProofStatement',
                objectVersion: 1,
                parameterProfileId: String(
                    (validParameterSet as Record<string, unknown>).profileId,
                ),
                relation: 'A*w + t = 0',
                relationStatementDigest: digest('relation-statement'),
                ringDegree: 256,
                statementColumns: 8,
                statementMatrixCoefficients:
                    validProofCase.statementMatrixCoefficients,
                statementMatrixDigest: digest('statement-matrix'),
                statementRows: 4,
                targetCoefficientRepresentation:
                    validProofCase.targetCoefficientRepresentation,
                targetVectorCoefficients,
                targetVectorDigest: digest('target-vector'),
                witnessL2BoundSquared: '2048',
            };

            return {
                ...linearStatementPayload,
                statementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: linearStatementPayload,
                        purpose: 'ballot-proof-linear-proof-statement-v1',
                    },
                }),
            };
        };
        const createBallotProof = (
            statement: Record<string, unknown>,
            linearStatement: Record<string, unknown>,
            componentBundleStatement?: Record<string, unknown>,
            componentProofBundle?: Record<string, unknown>,
            parameterSet: Record<string, unknown> = validParameterSet,
            proofEncoding: Record<string, unknown> = validProofEncoding,
        ): Record<string, unknown> => {
            const proofBytesDigest = kernel.deriveProtocolDigest({
                namespace: 'ProofBytesDigest',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex,
                    proofSizeBytes,
                },
            });
            const proofEncodingProfileDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
            const proofParameterSetDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
            const publicRandomnessDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    publicRandomnessHex,
                    purpose: 'ballot-proof-linear-proof-public-randomness-v1',
                },
            });
            const proofRoot = kernel.deriveProtocolDigest({
                namespace: 'BallotProofRecordDigest',
                value: {
                    linearStatementDigest: linearStatement.statementDigest,
                    proofBytesDigest,
                    proofEncodingProfileDigest,
                    proofParameterSetDigest,
                    publicRandomnessDigest,
                    purpose: 'ballot-proof-linear-proof-record-root-v1',
                },
            });
            const proofPayloadWithoutChallenge = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofProfileDigest: statement.ballotProofProfileDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                ...(componentBundleStatement === undefined
                    ? {}
                    : {
                          componentBundleStatementDigest:
                              componentBundleStatement.componentBundleStatementDigest,
                      }),
                ...(componentProofBundle === undefined
                    ? {}
                    : {
                          componentProofBundleDigest:
                              componentProofBundle.componentProofBundleDigest,
                      }),
                linearStatementDigest: linearStatement.statementDigest,
                objectType: 'BallotProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofRoot,
                proofSizeBytes,
                publicRandomnessDigest,
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
                statementMatrixDigest: linearStatement.statementMatrixDigest,
                targetVectorDigest: linearStatement.targetVectorDigest,
            };
            const challengeDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    backendStatementDigest:
                        proofPayloadWithoutChallenge.backendStatementDigest,
                    ballotProofStatementDigest:
                        statement.ballotProofStatementDigest,
                    challengeDomainDigest: statement.challengeDomainDigest,
                    ...(componentBundleStatement === undefined
                        ? {}
                        : {
                              componentBundleStatementDigest:
                                  componentBundleStatement.componentBundleStatementDigest,
                          }),
                    ...(componentProofBundle === undefined
                        ? {}
                        : {
                              componentProofBundleDigest:
                                  componentProofBundle.componentProofBundleDigest,
                          }),
                    linearStatementDigest:
                        proofPayloadWithoutChallenge.linearStatementDigest,
                    proofBytesDigest:
                        proofPayloadWithoutChallenge.proofBytesDigest,
                    proofEncodingProfileDigest:
                        proofPayloadWithoutChallenge.proofEncodingProfileDigest,
                    proofParameterSetDigest:
                        proofPayloadWithoutChallenge.proofParameterSetDigest,
                    proofRoot: proofPayloadWithoutChallenge.proofRoot,
                    publicRandomnessDigest:
                        proofPayloadWithoutChallenge.publicRandomnessDigest,
                    relationStatementDigest:
                        proofPayloadWithoutChallenge.relationStatementDigest,
                    statementMatrixDigest:
                        proofPayloadWithoutChallenge.statementMatrixDigest,
                    targetVectorDigest:
                        proofPayloadWithoutChallenge.targetVectorDigest,
                },
            });
            const proofPayload = {
                ...proofPayloadWithoutChallenge,
                challengeDigest,
            };

            return {
                ...proofPayload,
                ballotProofRecordDigest: kernel.deriveProtocolDigest({
                    namespace: 'BallotProofRecordDigest',
                    value: proofPayload,
                }),
            };
        };
        const statement = createStatement();
        const validLinearStatement = createLinearStatement(
            statement,
            validProofCase.targetVectorCoefficients,
        );
        const validBallotProof = createBallotProof(
            statement,
            validLinearStatement,
        );
        const mutatedLinearStatement = createLinearStatement(
            statement,
            mutatedTargetCase.targetVectorCoefficients,
        );
        const mutatedBallotProof = createBallotProof(
            statement,
            mutatedLinearStatement,
        );

        expect(
            kernel.verifyBallotProof({
                ballotProof: validBallotProof,
                linearStatement: validLinearStatement,
                parameterSet: validParameterSet,
                proofBytesHex,
                proofEncoding: validProofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        const sizeUnboundParameterSet = {
            ...validParameterSet,
            expectedProofSizeBytes: proofSizeBytes + 1,
        };
        const sizeUnboundParameterBallotProof = createBallotProof(
            statement,
            validLinearStatement,
            undefined,
            undefined,
            sizeUnboundParameterSet,
            validProofEncoding,
        );
        const sizeUnboundParameterVerification = kernel.verifyBallotProof({
            ballotProof: sizeUnboundParameterBallotProof,
            linearStatement: validLinearStatement,
            parameterSet: sizeUnboundParameterSet,
            proofBytesHex,
            proofEncoding: validProofEncoding,
            publicRandomnessHex,
            statement,
        });

        expect(sizeUnboundParameterVerification).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            sizeUnboundParameterVerification.refusedObjects.some((refusal) =>
                refusal.message.includes('byte length'),
            ),
        ).toBe(true);

        const sizeUnboundProofEncoding = {
            ...validProofEncoding,
            expectedProofSizeBytes: proofSizeBytes + 1,
        };
        const sizeUnboundEncodingBallotProof = createBallotProof(
            statement,
            validLinearStatement,
            undefined,
            undefined,
            validParameterSet,
            sizeUnboundProofEncoding,
        );
        const sizeUnboundEncodingVerification = kernel.verifyBallotProof({
            ballotProof: sizeUnboundEncodingBallotProof,
            linearStatement: validLinearStatement,
            parameterSet: validParameterSet,
            proofBytesHex,
            proofEncoding: sizeUnboundProofEncoding,
            publicRandomnessHex,
            statement,
        });

        expect(sizeUnboundEncodingVerification).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            sizeUnboundEncodingVerification.refusedObjects.some((refusal) =>
                refusal.message.includes('byte length'),
            ),
        ).toBe(true);

        const relabeledLinearStatement = cloneJsonValue(validLinearStatement);
        delete relabeledLinearStatement.statementDigest;
        relabeledLinearStatement.projectionCoverage =
            'full-encoded-score-ballot-relation';
        relabeledLinearStatement.statementDigest = kernel.deriveProtocolDigest({
            namespace: 'ChallengeDomainDigest',
            value: {
                payload: relabeledLinearStatement,
                purpose: 'ballot-proof-linear-proof-statement-v1',
            },
        });
        const relabeledBallotProof = createBallotProof(
            statement,
            relabeledLinearStatement,
        );
        const relabeledVerification = kernel.verifyBallotProof({
            ballotProof: relabeledBallotProof,
            linearStatement: relabeledLinearStatement,
            parameterSet: validParameterSet,
            proofBytesHex,
            proofEncoding: validProofEncoding,
            publicRandomnessHex,
            statement,
        });

        expect(relabeledVerification).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            relabeledVerification.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'dedicated full-relation parameter profile',
                ),
            ),
        ).toBe(true);
        expect(
            kernel.verifyBallotProof({
                ballotProof: mutatedBallotProof,
                linearStatement: mutatedLinearStatement,
                parameterSet: validParameterSet,
                proofBytesHex,
                proofEncoding: validProofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'InvalidFixture',
        });
        expect(
            kernel.verifyBallotProof({
                ballotProof: validBallotProof,
                linearStatement: validLinearStatement,
                parameterSet: validParameterSet,
                proofBytesHex: proofBytesHex.slice(0, -2),
                proofEncoding: validProofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('rejects encoded-score field-only ballot proof records after WASM proof verification', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const ballotFieldLinearProofCases =
            ballotFieldLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validProofCase = expandBallotFieldLinearProofVectorCase(
            findFixture(
                ballotFieldLinearProofCases,
                'valid-encoded-score-field-linear-proof',
            ),
        );
        const mutatedTargetCase = expandBallotFieldLinearProofVectorCase(
            findFixture(
                ballotFieldLinearProofCases,
                'mutated-encoded-score-field-target-vector',
            ),
        );
        const proofBytesHex = String(validProofCase.proofHex);
        const publicRandomnessHex = String(validProofCase.publicRandomnessHex);
        const proofSizeBytes = proofBytesHex.length / 2;
        const digest = (label: string): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    label,
                    purpose:
                        'encoded-score-field-ballot-proof-record-wasm-test',
                },
            });
        const deriveProofBytesDigestForTest = (
            proofBytesHexForTest: string,
        ): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ProofBytesDigest',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex: proofBytesHexForTest,
                    proofSizeBytes: proofBytesHexForTest.length / 2,
                },
            });
        const deriveBallotProofEncodingDigestForTest = (
            proofEncoding: unknown,
        ): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
        const deriveBallotProofParameterSetDigestForTest = (
            parameterSet: unknown,
        ): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
        const deriveBallotProofPublicRandomnessDigestForTest = (
            componentPublicRandomnessHex: string,
        ): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    publicRandomnessHex: componentPublicRandomnessHex,
                    purpose: 'ballot-proof-linear-proof-public-randomness-v1',
                },
            });
        const createStatement = (): Record<string, unknown> => {
            const statementPayload = {
                actionContextDigest: digest('action-context'),
                aggregateInputEncodingProfileDigest: digest(
                    'aggregate-input-encoding-profile',
                ),
                ballotPackageDigest: digest('ballot-package'),
                ballotProofProfileDigest: digest('ballot-proof-profile'),
                ballotScoreEncodingProfileDigest: digest(
                    'ballot-score-encoding-profile',
                ),
                ballotShareLayoutProfileDigest: digest(
                    'ballot-share-layout-profile',
                ),
                ceremonyId: 'ceremony-encoded-score-field-ballot-proof-record',
                challengeDomainDigest: digest('challenge-domain'),
                duplicateBallotPolicyDigest: digest('duplicate-policy'),
                encodedAggregateLayoutDigest: digest(
                    'encoded-aggregate-layout',
                ),
                encodedShareVectorLayoutDigest: digest(
                    'encoded-share-vector-layout',
                ),
                manifestDigest: digest('manifest'),
                objectType: 'BallotProofStatement',
                objectVersion: 1,
                optionCount: 20,
                pollSpecDigest: digest('poll-spec'),
                receiverEncryptionProfileDigest: digest(
                    'receiver-encryption-profile',
                ),
                receiverKeyProofRoot: digest('receiver-key-proof-root'),
                receiverKeyRoot: digest('receiver-key-root'),
                receiverPayloads: [
                    {
                        receiverIdentity: 'receiver-1',
                        receiverPayloadCiphertextRoot: digest(
                            'receiver-ciphertext-1',
                        ),
                        receiverPayloadDigest: digest('receiver-payload-1'),
                        receiverRosterPosition: 1,
                    },
                ],
                receiverPublicKeys: [
                    {
                        receiverIdentity: 'receiver-1',
                        receiverPublicKeyDigest: digest(
                            'receiver-public-key-1',
                        ),
                        receiverRosterPosition: 1,
                    },
                ],
                rosterDigest: digest('roster'),
                rosterExternalAcceptanceDigest: digest('external-acceptance'),
                scoreDomainDigest: digest('score-domain'),
                scoreMembershipProfileDigest: digest(
                    'score-membership-profile',
                ),
                shareCommitmentMessageBoundCertDigest: digest(
                    'share-commitment-bound-cert',
                ),
                shareCommitmentProfileDigest: digest(
                    'share-commitment-profile',
                ),
                shareCommitments: [
                    {
                        receiverIdentity: 'receiver-1',
                        receiverRosterPosition: 1,
                        shareCommitmentDigest: digest('share-commitment-1'),
                    },
                ],
                shareVectorWidth: 220,
                thresholdProfileDigest: digest('threshold-profile'),
                tiePolicyDigest: digest('tie-policy'),
                topOptionCount: 3,
                voterIdentityDigest: digest('voter-1'),
                voterRosterPosition: 1,
                voterSigningKeyDigest: digest('voter-signing-key'),
            };

            return {
                ...statementPayload,
                ballotProofStatementDigest: kernel.deriveProtocolDigest({
                    namespace: 'BallotProofStatementDigest',
                    value: statementPayload,
                }),
            };
        };
        const createLinearStatement = (
            statement: Record<string, unknown>,
            vectorCase: Record<string, unknown>,
        ): Record<string, unknown> => {
            const statementMatrixCoefficients =
                vectorCase.statementMatrixCoefficients;
            const targetVectorCoefficients =
                vectorCase.targetVectorCoefficients;
            const linearStatementPayload = {
                ...cloneJsonValue(
                    ballotFieldLinearProofBackendVectors.linearStatement,
                ),
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                statementMatrixCoefficients,
                statementMatrixDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        purpose: 'ballot-proof-linear-statement-matrix-v1',
                        statementMatrixCoefficients,
                    },
                }),
                targetVectorCoefficients,
                targetVectorDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        purpose: 'ballot-proof-linear-target-vector-v1',
                        targetVectorCoefficients,
                    },
                }),
            } as Record<string, unknown>;
            delete linearStatementPayload.statementDigest;

            return {
                ...linearStatementPayload,
                statementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: linearStatementPayload,
                        purpose: 'ballot-proof-linear-proof-statement-v1',
                    },
                }),
            };
        };
        const createBallotProof = (
            statement: Record<string, unknown>,
            linearStatement: Record<string, unknown>,
            componentBundleStatement?: Record<string, unknown>,
            componentProofBundle?: Record<string, unknown>,
        ): Record<string, unknown> => {
            const proofBytesDigest = kernel.deriveProtocolDigest({
                namespace: 'ProofBytesDigest',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex,
                    proofSizeBytes,
                },
            });
            const proofEncodingProfileDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    proofEncoding: validProofCase.proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
            const proofParameterSetDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    parameterSet: validProofCase.parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
            const publicRandomnessDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    publicRandomnessHex,
                    purpose: 'ballot-proof-linear-proof-public-randomness-v1',
                },
            });
            const proofRoot = kernel.deriveProtocolDigest({
                namespace: 'BallotProofRecordDigest',
                value: {
                    linearStatementDigest: linearStatement.statementDigest,
                    proofBytesDigest,
                    proofEncodingProfileDigest,
                    proofParameterSetDigest,
                    publicRandomnessDigest,
                    purpose: 'ballot-proof-linear-proof-record-root-v1',
                },
            });
            const proofPayloadWithoutChallenge = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofProfileDigest: statement.ballotProofProfileDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                ...(componentBundleStatement === undefined
                    ? {}
                    : {
                          componentBundleStatementDigest:
                              componentBundleStatement.componentBundleStatementDigest,
                      }),
                ...(componentProofBundle === undefined
                    ? {}
                    : {
                          componentProofBundleDigest:
                              componentProofBundle.componentProofBundleDigest,
                      }),
                linearStatementDigest: linearStatement.statementDigest,
                objectType: 'BallotProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofRoot,
                proofSizeBytes,
                publicRandomnessDigest,
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
                statementMatrixDigest: linearStatement.statementMatrixDigest,
                targetVectorDigest: linearStatement.targetVectorDigest,
            };
            const challengeDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    backendStatementDigest:
                        proofPayloadWithoutChallenge.backendStatementDigest,
                    ballotProofStatementDigest:
                        statement.ballotProofStatementDigest,
                    challengeDomainDigest: statement.challengeDomainDigest,
                    ...(componentBundleStatement === undefined
                        ? {}
                        : {
                              componentBundleStatementDigest:
                                  componentBundleStatement.componentBundleStatementDigest,
                          }),
                    ...(componentProofBundle === undefined
                        ? {}
                        : {
                              componentProofBundleDigest:
                                  componentProofBundle.componentProofBundleDigest,
                          }),
                    linearStatementDigest:
                        proofPayloadWithoutChallenge.linearStatementDigest,
                    proofBytesDigest:
                        proofPayloadWithoutChallenge.proofBytesDigest,
                    proofEncodingProfileDigest:
                        proofPayloadWithoutChallenge.proofEncodingProfileDigest,
                    proofParameterSetDigest:
                        proofPayloadWithoutChallenge.proofParameterSetDigest,
                    proofRoot: proofPayloadWithoutChallenge.proofRoot,
                    publicRandomnessDigest:
                        proofPayloadWithoutChallenge.publicRandomnessDigest,
                    relationStatementDigest:
                        proofPayloadWithoutChallenge.relationStatementDigest,
                    statementMatrixDigest:
                        proofPayloadWithoutChallenge.statementMatrixDigest,
                    targetVectorDigest:
                        proofPayloadWithoutChallenge.targetVectorDigest,
                },
            });
            const proofPayload = {
                ...proofPayloadWithoutChallenge,
                challengeDigest,
            };

            return {
                ...proofPayload,
                ballotProofRecordDigest: kernel.deriveProtocolDigest({
                    namespace: 'BallotProofRecordDigest',
                    value: proofPayload,
                }),
            };
        };
        const componentIds = [
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
            'share-commitment-component',
            'receiver-encryption-component',
            'receiver-key-binding-component',
        ];
        const createComponentStatement = (
            linearStatement: Record<string, unknown>,
            statement: Record<string, unknown>,
            componentId: string,
            componentIndex: number,
            proofLoweringStatus: string,
        ): Record<string, unknown> => {
            const componentPayload = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                coefficientModulus: '65537',
                componentDigest: digest(`${componentId}-component`),
                componentId,
                matrixDigest: digest(`${componentId}-matrix`),
                objectType: 'BallotProofComponentStatement',
                objectVersion: 1,
                proofLoweringStatus,
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
                rowBatchMatrixDigests: [digest(`${componentId}-row-matrix`)],
                rowBatchNames: [`${componentId}-rows`],
                rowBatchTargetVectorDigests: [
                    digest(`${componentId}-row-target`),
                ],
                rowCount: 1,
                rowKinds: ['EncodedScoreFieldRows'],
                targetVectorDigest: digest(`${componentId}-target`),
                variableColumnCount: 1,
                variableColumnIndices: [componentIndex],
            };

            return {
                ...componentPayload,
                componentStatementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: componentPayload,
                        purpose: 'ballot-proof-component-statement-v1',
                    },
                }),
            };
        };
        const createComponentBundleStatement = (
            linearStatement: Record<string, unknown>,
            statement: Record<string, unknown>,
            options: { readonly fullCoverage?: boolean } = {},
        ): Record<string, unknown> => {
            const componentStatements = componentIds.map(
                (componentId, componentIndex) =>
                    createComponentStatement(
                        linearStatement,
                        statement,
                        componentId,
                        componentIndex,
                        options.fullCoverage === true || componentIndex === 0
                            ? 'explicitRowsAvailable'
                            : 'digestExpandedRowsPending',
                    ),
            );
            const componentBundlePayload = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                bundleCoverage:
                    options.fullCoverage === true
                        ? 'full-encoded-score-ballot-relation'
                        : 'component-bundle-incomplete',
                componentStatements,
                objectType: 'BallotProofComponentBundleStatement',
                objectVersion: 1,
                relationLabel: 'BallotPrivacyPvssRelation',
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
                requiredComponentIds: componentIds,
            };

            return {
                ...componentBundlePayload,
                componentBundleStatementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: componentBundlePayload,
                        purpose: 'ballot-proof-component-bundle-statement-v1',
                    },
                }),
            };
        };
        const createComponentProofStatement = (input: {
            readonly componentId: string;
            readonly componentProofStatementDigest?: string;
            readonly componentStatementDigest: string;
            readonly proofStatementFormat: string;
        }): Record<string, unknown> => {
            if (
                input.proofStatementFormat ===
                'dense-polynomial-matrix-linear-proof-v1'
            ) {
                const statementPayload = {
                    componentId: input.componentId,
                    componentStatementDigest: input.componentStatementDigest,
                    objectType: 'BallotProofLinearProofStatement',
                    objectVersion: 1,
                    proofStatementFormat: input.proofStatementFormat,
                };

                return {
                    ...statementPayload,
                    statementDigest: kernel.deriveProtocolDigest({
                        namespace: 'ChallengeDomainDigest',
                        value: {
                            payload: statementPayload,
                            purpose: 'ballot-proof-linear-proof-statement-v1',
                        },
                    }),
                };
            }
            if (
                input.proofStatementFormat ===
                'sparse-polynomial-matrix-linear-proof-v1'
            ) {
                const statementPayload = {
                    componentId: input.componentId,
                    componentStatementDigest: input.componentStatementDigest,
                    objectType:
                        'BallotProofSparseComponentLinearProofStatement',
                    objectVersion: 1,
                    proofStatementFormat: input.proofStatementFormat,
                };

                return {
                    ...statementPayload,
                    statementDigest: kernel.deriveProtocolDigest({
                        namespace: 'ChallengeDomainDigest',
                        value: {
                            payload: statementPayload,
                            purpose:
                                'ballot-proof-sparse-linear-proof-statement-v1',
                        },
                    }),
                };
            }
            const statementPayload = {
                backendStatementDigest: digest(`${input.componentId}-backend`),
                coefficientModulus:
                    input.componentId === 'share-commitment-component'
                        ? '18446744069414584321'
                        : input.componentId ===
                                'score-and-shamir-field-component' ||
                            input.componentId ===
                                'payload-plaintext-field-component'
                          ? '65537'
                          : '12289',
                componentId: input.componentId,
                componentStatementDigest: input.componentStatementDigest,
                denseCoefficientCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? '1024'
                        : null,
                matrixDigest: digest(`${input.componentId}-matrix`),
                objectType: 'BallotProofComponentProofStatementPlan',
                objectVersion: 1,
                proofBytesAvailability:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 'requires-structured-proof-statement'
                        : 'public-zero-witness-binding-check',
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat: input.proofStatementFormat,
                proofSystemRingDegree:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 64
                        : null,
                relation: 'A*w + t = 0',
                relationStatementDigest: digest(
                    `${input.componentId}-relation`,
                ),
                rowBatchMatrixDigests: [
                    digest(`${input.componentId}-row-matrix`),
                ],
                rowBatchNames: [
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 'receiver_payload_encryption_equation_rows'
                        : 'receiver_key_binding_rows',
                ],
                rowBatchTargetVectorDigests: [
                    digest(`${input.componentId}-row-target`),
                ],
                rowBatchTermCounts: [
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? '1024'
                        : '0',
                ],
                rowCount: 1,
                sparseTermCount: null,
                sourceRingDegree:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 256
                        : null,
                structuredCiphertextChunkCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 1
                        : null,
                structuredReceiverCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 1
                        : null,
                structuredWitnessTermCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? '1024'
                        : null,
                targetVectorDigest: digest(`${input.componentId}-target`),
                variableColumnCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 1
                        : 0,
                variableColumnIndices:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? [0]
                        : [],
            };

            return {
                ...statementPayload,
                componentProofStatementDigest:
                    input.componentProofStatementDigest ??
                    kernel.deriveProtocolDigest({
                        namespace: 'ChallengeDomainDigest',
                        value: {
                            payload: statementPayload,
                            purpose:
                                'ballot-proof-component-proof-statement-plan-v1',
                        },
                    }),
            };
        };
        const createComponentProofInput = (
            componentId: string,
            componentStatementDigest: string,
        ): Record<string, unknown> => {
            const componentIndex = componentIds.indexOf(componentId);
            const publicRandomnessByte = (componentIndex + 1)
                .toString(16)
                .padStart(2, '0');
            const proofStatementFormat =
                componentId === 'receiver-encryption-component'
                    ? 'structured-module-lwe-linear-proof-v1'
                    : componentId === 'receiver-key-binding-component'
                      ? 'public-zero-witness-binding-check-v1'
                      : componentId === 'score-and-shamir-field-component'
                        ? 'dense-polynomial-matrix-linear-proof-v1'
                        : 'sparse-polynomial-matrix-linear-proof-v1';
            const componentProofStatementDigest = digest(
                `${componentId}-proof-statement`,
            );
            const proofStatement = createComponentProofStatement({
                componentId,
                componentProofStatementDigest:
                    proofStatementFormat ===
                        'structured-module-lwe-linear-proof-v1' ||
                    proofStatementFormat ===
                        'public-zero-witness-binding-check-v1'
                        ? undefined
                        : componentProofStatementDigest,
                componentStatementDigest,
                proofStatementFormat,
            });
            const suppliedComponentProofStatementDigest =
                proofStatement.componentProofStatementDigest;
            const boundComponentProofStatementDigest =
                typeof suppliedComponentProofStatementDigest === 'string'
                    ? suppliedComponentProofStatementDigest
                    : componentProofStatementDigest;
            const componentProofBytesHex =
                proofStatementFormat === 'public-zero-witness-binding-check-v1'
                    ? ''
                    : digest(`${componentId}-proof-bytes-material`);

            return {
                componentId,
                componentProofStatementDigest:
                    boundComponentProofStatementDigest,
                proofBytesHex: componentProofBytesHex,
                proofEncoding: {
                    profileId: 'ballot-proof-component-encoding-v1',
                    componentId,
                },
                proofParameterSet: {
                    profileId: 'ballot-proof-component-parameter-set-v1',
                    componentId,
                },
                proofStatement,
                proofStatementFormat,
                publicRandomnessHex: publicRandomnessByte.repeat(32),
                statementDigest: componentStatementDigest,
            };
        };
        const createComponentProofRecord = (
            linearStatement: Record<string, unknown>,
            statement: Record<string, unknown>,
            componentStatement: Record<string, unknown>,
            componentId: string,
        ): Record<string, unknown> => {
            const componentProofInput = createComponentProofInput(
                componentId,
                String(componentStatement.componentStatementDigest),
            );
            const proofBytesDigest = deriveProofBytesDigestForTest(
                String(componentProofInput.proofBytesHex),
            );
            const proofEncodingProfileDigest =
                deriveBallotProofEncodingDigestForTest(
                    componentProofInput.proofEncoding,
                );
            const proofParameterSetDigest =
                deriveBallotProofParameterSetDigestForTest(
                    componentProofInput.proofParameterSet,
                );
            const publicRandomnessDigest =
                deriveBallotProofPublicRandomnessDigestForTest(
                    String(componentProofInput.publicRandomnessHex),
                );
            const proofRoot = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    componentId,
                    componentProofStatementDigest:
                        componentProofInput.componentProofStatementDigest,
                    componentStatementDigest:
                        componentStatement.componentStatementDigest,
                    proofBytesDigest,
                    proofEncodingProfileDigest,
                    proofParameterSetDigest,
                    proofStatementFormat:
                        componentProofInput.proofStatementFormat,
                    publicRandomnessDigest,
                    purpose: 'ballot-proof-component-proof-root-v1',
                    statementDigest:
                        componentStatement.componentStatementDigest,
                },
            });
            const proofRecordPayload = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                componentId,
                componentProofStatementDigest:
                    componentProofInput.componentProofStatementDigest,
                componentStatementDigest:
                    componentStatement.componentStatementDigest,
                objectType: 'BallotProofComponentProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofRoot,
                proofSizeBytes:
                    String(componentProofInput.proofBytesHex).length / 2,
                publicRandomnessDigest,
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
            };

            return {
                ...proofRecordPayload,
                componentProofRecordDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: proofRecordPayload,
                        purpose: 'ballot-proof-component-proof-record-v1',
                    },
                }),
            };
        };
        const createComponentProofInputs = (
            componentProofs: readonly Record<string, unknown>[],
        ): readonly Record<string, unknown>[] =>
            componentProofs.map((componentProof) =>
                createComponentProofInput(
                    String(componentProof.componentId),
                    String(componentProof.componentStatementDigest),
                ),
            );
        const createComponentProofBundle = (
            componentBundleStatement: Record<string, unknown>,
            componentProofs: readonly Record<string, unknown>[],
        ): Record<string, unknown> => {
            const proofBundlePayload = {
                backendStatementDigest:
                    componentBundleStatement.backendStatementDigest,
                ballotProofStatementDigest:
                    componentBundleStatement.ballotProofStatementDigest,
                bundleCoverage: componentBundleStatement.bundleCoverage,
                componentBundleStatementDigest:
                    componentBundleStatement.componentBundleStatementDigest,
                componentProofs,
                objectType: 'BallotProofComponentProofBundle',
                objectVersion: 1,
                relationStatementDigest:
                    componentBundleStatement.relationStatementDigest,
                requiredComponentIds: componentIds,
            };

            return {
                ...proofBundlePayload,
                componentProofBundleDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: proofBundlePayload,
                        purpose: 'ballot-proof-component-proof-bundle-v1',
                    },
                }),
            };
        };
        const statement = createStatement();
        const validLinearStatement = createLinearStatement(
            statement,
            validProofCase,
        );
        const validBallotProof = createBallotProof(
            statement,
            validLinearStatement,
        );
        const mutatedLinearStatement = createLinearStatement(
            statement,
            mutatedTargetCase,
        );
        const mutatedBallotProof = createBallotProof(
            statement,
            mutatedLinearStatement,
        );
        const incompleteComponentBundleStatement =
            createComponentBundleStatement(validLinearStatement, statement);
        const proofBoundToIncompleteComponentBundle = createBallotProof(
            statement,
            validLinearStatement,
            incompleteComponentBundleStatement,
        );

        expect(
            kernel.verifyBallotProof({
                ballotProof: validBallotProof,
                linearStatement: validLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex,
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        const relabeledEncodedLinearStatement =
            cloneJsonValue(validLinearStatement);
        delete relabeledEncodedLinearStatement.statementDigest;
        relabeledEncodedLinearStatement.projectionCoverage =
            'full-encoded-score-ballot-relation';
        relabeledEncodedLinearStatement.statementDigest =
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    payload: relabeledEncodedLinearStatement,
                    purpose: 'ballot-proof-linear-proof-statement-v1',
                },
            });
        const relabeledEncodedBallotProof = createBallotProof(
            statement,
            relabeledEncodedLinearStatement,
        );
        const relabeledEncodedVerification = kernel.verifyBallotProof({
            ballotProof: relabeledEncodedBallotProof,
            linearStatement: relabeledEncodedLinearStatement,
            parameterSet: validProofCase.parameterSet,
            proofBytesHex,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex,
            statement,
        });

        expect(relabeledEncodedVerification).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            relabeledEncodedVerification.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'dedicated full-relation parameter profile',
                ),
            ),
        ).toBe(true);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToIncompleteComponentBundle,
                    componentBundleStatement:
                        incompleteComponentBundleStatement,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'component bundle is still incomplete',
                    ),
                ),
        ).toBe(true);

        const fullComponentBundleStatement = createComponentBundleStatement(
            validLinearStatement,
            statement,
            {
                fullCoverage: true,
            },
        );
        const fullComponentStatements =
            fullComponentBundleStatement.componentStatements as readonly Record<
                string,
                unknown
            >[];
        const componentProofs = componentIds.map(
            (componentId, componentIndex) =>
                createComponentProofRecord(
                    validLinearStatement,
                    statement,
                    fullComponentStatements[componentIndex] ?? {},
                    componentId,
                ),
        );
        const componentProofInputs =
            createComponentProofInputs(componentProofs);
        const componentProofBundle = createComponentProofBundle(
            fullComponentBundleStatement,
            componentProofs,
        );
        const proofBoundToComponentBundleWithoutProofBundle = createBallotProof(
            statement,
            validLinearStatement,
            fullComponentBundleStatement,
        );
        const proofBoundToComponentProofBundle = createBallotProof(
            statement,
            validLinearStatement,
            fullComponentBundleStatement,
            componentProofBundle,
        );

        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentBundleWithoutProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'requires a component proof bundle',
                    ),
                ),
        ).toBe(true);
        const validComponentBundlePreflight = kernel.verifyBallotProof({
            ballotProof: proofBoundToComponentProofBundle,
            componentBundleStatement: fullComponentBundleStatement,
            componentProofBundle,
            componentProofInputs,
            linearStatement: validLinearStatement,
            parameterSet: validProofCase.parameterSet,
            proofBytesHex,
            proofEncoding: validProofCase.proofEncoding,
            publicRandomnessHex,
            statement,
        });
        expect(
            validComponentBundlePreflight.refusedObjects.some((refusal) =>
                refusal.message.includes(
                    'component proof bundle has an invalid canonical shape',
                ),
            ),
        ).toBe(false);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'requires public proof inputs for every component proof',
                    ),
                ),
        ).toBe(true);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle,
                    componentProofInputs: componentProofInputs.map(
                        (componentProofInput, componentIndex) =>
                            componentIndex === 0
                                ? {
                                      ...componentProofInput,
                                      proofBytesHex: 'ff'.repeat(
                                          String(
                                              componentProofInput.proofBytesHex,
                                          ).length / 2,
                                      ),
                                  }
                                : componentProofInput,
                    ),
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'proof bytes do not match the proof record digest',
                    ),
                ),
        ).toBe(true);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle,
                    componentProofInputs: componentProofInputs.map(
                        (componentProofInput, componentIndex) =>
                            componentIndex === 0
                                ? {
                                      ...componentProofInput,
                                      componentProofStatementDigest: digest(
                                          'wrong-component-proof-statement',
                                      ),
                                  }
                                : componentProofInput,
                    ),
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'proof statement for score-and-shamir-field-component does not match the proof record',
                    ),
                ),
        ).toBe(true);
        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle,
                    componentProofInputs: componentProofInputs.map(
                        (componentProofInput, componentIndex) =>
                            componentIndex === 3
                                ? {
                                      ...componentProofInput,
                                      proofStatement:
                                          createComponentProofStatement({
                                              componentId: String(
                                                  componentProofInput.componentId,
                                              ),
                                              componentProofStatementDigest:
                                                  digest(
                                                      'wrong-supplied-component-proof-statement-canonical-digest',
                                                  ),
                                              componentStatementDigest: String(
                                                  componentProofInput.statementDigest,
                                              ),
                                              proofStatementFormat: String(
                                                  componentProofInput.proofStatementFormat,
                                              ),
                                          }),
                                  }
                                : componentProofInput,
                    ),
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'proof statement digest for receiver-encryption-component does not match its canonical payload',
                    ),
                ),
        ).toBe(true);
        const reorderedComponentProofBundle = createComponentProofBundle(
            fullComponentBundleStatement,
            [...componentProofs].reverse(),
        );
        const reorderedComponentProofInputs = createComponentProofInputs(
            [...componentProofs].reverse(),
        );
        const proofBoundToReorderedComponentProofBundle = createBallotProof(
            statement,
            validLinearStatement,
            fullComponentBundleStatement,
            reorderedComponentProofBundle,
        );

        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToReorderedComponentProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle: reorderedComponentProofBundle,
                    componentProofInputs: reorderedComponentProofInputs,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes('invalid canonical shape'),
                ),
        ).toBe(true);
        const wrongComponentStatementProofs = [
            createComponentProofRecord(
                validLinearStatement,
                statement,
                { componentStatementDigest: digest('wrong-component') },
                componentIds[0] ?? 'score-and-shamir-field-component',
            ),
            ...componentProofs.slice(1),
        ];
        const wrongComponentStatementProofBundle = createComponentProofBundle(
            fullComponentBundleStatement,
            wrongComponentStatementProofs,
        );
        const wrongComponentStatementProofInputs = createComponentProofInputs(
            wrongComponentStatementProofs,
        );
        const proofBoundToWrongComponentStatementProofBundle =
            createBallotProof(
                statement,
                validLinearStatement,
                fullComponentBundleStatement,
                wrongComponentStatementProofBundle,
            );

        expect(
            kernel
                .verifyBallotProof({
                    ballotProof: proofBoundToWrongComponentStatementProofBundle,
                    componentBundleStatement: fullComponentBundleStatement,
                    componentProofBundle: wrongComponentStatementProofBundle,
                    componentProofInputs: wrongComponentStatementProofInputs,
                    linearStatement: validLinearStatement,
                    parameterSet: validProofCase.parameterSet,
                    proofBytesHex,
                    proofEncoding: validProofCase.proofEncoding,
                    publicRandomnessHex,
                    statement,
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'not bound to the supplied component statement',
                    ),
                ),
        ).toBe(true);
        expect(
            kernel.verifyBallotProof({
                ballotProof: mutatedBallotProof,
                linearStatement: mutatedLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex,
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'InvalidFixture',
        });
        expect(
            kernel.verifyBallotProof({
                ballotProof: validBallotProof,
                linearStatement: validLinearStatement,
                parameterSet: validProofCase.parameterSet,
                proofBytesHex: proofBytesHex.slice(0, -2),
                proofEncoding: validProofCase.proofEncoding,
                publicRandomnessHex,
                statement,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: false,
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
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
        expect(deallocate).toHaveBeenCalledWith(512, 4);
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
        expect(deallocate).toHaveBeenCalledTimes(2);
        expect(deallocate).toHaveBeenCalledWith(
            12,
            encodedCommandResponseLength,
        );
        expect(deallocate).toHaveBeenCalledWith(512, 4);
        expect(
            deallocate.mock.calls.filter(([pointer]) => pointer === 12),
        ).toEqual([[12, encodedCommandResponseLength]]);
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

    it('rejects null command output-length allocations', async () => {
        const { loadMockKernel } = createMockKernelExports({
            outputLengthAllocationPointer: 0,
        });
        const kernel = await loadMockKernel();

        expect(() =>
            kernel.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toThrow(
            'The transcript-core kernel returned a null pointer for the output-length allocation.',
        );
    });

    it('rejects overlapping kernel commands on one instance', async () => {
        const loadedKernelReference: { current?: TranscriptCoreKernel } = {};
        const { loadMockKernel } = createMockKernelExports({
            onCommand: () => {
                loadedKernelReference.current?.hashRaw('00');
            },
        });
        loadedKernelReference.current = await loadMockKernel();

        expect(() =>
            loadedKernelReference.current?.computeChunkRoot({
                inputHex: '00ff',
                chunkSize: 2,
            }),
        ).toThrow(
            'The transcript-core kernel cannot run overlapping command operations on one instance.',
        );
    });

    it('rejects a transcript-core kernel with the wrong integrity digest', async () => {
        const { getInstantiateCallCount, loadMockKernel } =
            createMockKernelExports({
                expectedKernelSha256Hex:
                    '0000000000000000000000000000000000000000000000000000000000000000',
            });

        await expect(loadMockKernel()).rejects.toThrow(
            'The transcript-core kernel failed integrity verification',
        );
        expect(getInstantiateCallCount()).toBe(0);
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
