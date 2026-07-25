import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    contributeGeneratedAcceptedSetupPublicKeyShareToPackage,
    contributeGeneratedAcceptedSetupSameSecretToPackage,
    generateAcceptedSetupPublicKeyShareInClosedWorker,
    generateAcceptedSetupSameSecretInClosedWorker,
    verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker,
    verifyGeneratedAcceptedSetupSameSecretInClosedWorker,
} from '#packages/wasm/src/accepted-setup-key-relation-generation-runtime';
import { canonicalStreamDomains } from '#packages/wasm/src/canonical-stream-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const boundaryMocks = vi.hoisted(() => {
    const activeContext: {
        value: TranscriptCoreKernelCommandRuntime | undefined;
    } = { value: undefined };
    const generatedCapabilityRelease = vi.fn();
    const generatedCapability = Object.freeze({
        release: generatedCapabilityRelease,
    });
    const verifiedVssShareLinkageTerminal = Object.freeze({});
    const generatedConsumptionOutcomes: boolean[] = [];
    return {
        activeContext,
        applyGeneratedCapability: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (
                    handle: number,
                ) => Readonly<{ consumed: boolean; result: number }>,
            ) => {
                const outcome = apply(301);
                generatedConsumptionOutcomes.push(outcome.consumed);
                return outcome.result;
            },
        ),
        deriveProofDescriptor: vi.fn(() =>
            Promise.resolve(Uint8Array.of(0xd1, 0xd2)),
        ),
        generatedCapability,
        generatedCapabilityRelease,
        generatedConsumptionOutcomes,
        openGenerationAdapter: vi.fn(() => Object.freeze({})),
        releaseGenerationAdapter: vi.fn(),
        runGeneration: vi.fn(
            async (
                _adapter: unknown,
                openExecution: (description: unknown) => unknown,
            ) => {
                const execution = (await openExecution(Object.freeze({}))) as {
                    options?: unknown;
                    outputStore: unknown;
                };
                return Object.freeze({
                    generatedCapability,
                    options: execution.options,
                    outputChunkByteLengths: Object.freeze([2]),
                    outputStore: execution.outputStore,
                });
            },
        ),
        verifyGeneratedPublicKeyShare: vi.fn(
            (
                _input: unknown,
                _capability: unknown,
                _statementSourceHandle: number,
            ) => Promise.resolve(undefined),
        ),
        verifyGeneratedSameSecret: vi.fn(
            (
                _input: unknown,
                _capability: unknown,
                _statementSourceHandle: number,
            ) => Promise.resolve(undefined),
        ),
        verifiedVssShareLinkageTerminal,
    };
});

vi.mock('#packages/wasm/src/setup-generation-recipient-payload', () => ({
    resolveSetupGenerationAuthorityKernelAuthorization: () => ({ handle: 14 }),
}));

vi.mock(
    '#packages/wasm/src/local-storage-root-worker-kernel/worker-kernel',
    () => ({
        withClosedWorkerProductionOperationAuthority: (
            workerKernel: { kernel: TranscriptCoreKernel },
            _productionOperationIdentifiers: unknown,
            operation: (authority: unknown) => unknown,
        ) =>
            Promise.resolve().then(() =>
                operation(
                    Object.freeze({
                        withExactKernelAuthorization: <Result>(
                            callback: (authorization: unknown) => Result,
                        ): Result =>
                            callback(
                                Object.freeze({
                                    actionRandomnessContext:
                                        boundaryMocks.activeContext.value,
                                    actionRandomnessHandle: 13,
                                    kernel: workerKernel.kernel,
                                    stateReservationCapabilityMemory:
                                        boundaryMocks.activeContext.value
                                            ?.memory,
                                    stateReservationCapabilityPointer: 128,
                                    stateReservationHandle: 15,
                                    stateVerifierSessionHandle: 16,
                                }),
                            ),
                    }),
                ),
            ),
    }),
);

vi.mock('#packages/wasm/src/vss-share-linkage-verification-runtime', () => ({
    resolveOrderedVerifiedBoardObjectAuthorization: () => {
        const handleBytes = new Uint8Array(4);
        new DataView(handleBytes.buffer).setUint32(0, 17, true);
        return Object.freeze({
            capabilityPointer: 192,
            handleBytes,
            sessionHandle: 18,
        });
    },
}));

vi.mock('#packages/wasm/src/generated-common-proof-output-runtime', () => ({
    deriveGeneratedCommonProofDescriptor: boundaryMocks.deriveProofDescriptor,
}));

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    applyClosedWorkerGeneratedCommonProofCapability:
        boundaryMocks.applyGeneratedCapability,
    openClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.openGenerationAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.releaseGenerationAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener:
        boundaryMocks.runGeneration,
}));

vi.mock('#packages/wasm/src/accepted-setup-package-builder-runtime', () => ({
    requireAcceptedSetupPackageBuilderKernelOwner: (
        _builder: unknown,
        kernel: TranscriptCoreKernel,
    ) => ({
        context: boundaryMocks.activeContext.value,
        handle: 41,
        kernel,
    }),
}));

vi.mock('#packages/wasm/src/accepted-setup-proof-verification-runtime', () => ({
    verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker:
        boundaryMocks.verifyGeneratedPublicKeyShare,
    verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker:
        boundaryMocks.verifyGeneratedSameSecret,
}));

type SetupKeyRelationFamily = 'publicKeyShare' | 'sameSecret';
type GenerationMode = 'fresh' | 'resumed';

type FakeSetupKeyRelationRuntime = Readonly<{
    allocations: ReadonlyMap<number, number>;
    cancelledGeneratedSources: Array<
        Readonly<{
            family: SetupKeyRelationFamily;
            generatedProofHandle: number;
            statementSourceHandle: number;
        }>
    >;
    contributedGeneratedSources: Array<
        Readonly<{
            builderHandle: number;
            family: SetupKeyRelationFamily;
            generatedProofHandle: number;
            statementSourceHandle: number;
        }>
    >;
    discardedStatementSources: number[];
    generationPreparations: Array<
        Readonly<{ family: SetupKeyRelationFamily; mode: GenerationMode }>
    >;
    kernel: TranscriptCoreKernel;
    selectedSuiteReleases: number[];
}>;

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeRuntime = (): FakeSetupKeyRelationRuntime => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const cancelledGeneratedSources: Array<
        Readonly<{
            family: SetupKeyRelationFamily;
            generatedProofHandle: number;
            statementSourceHandle: number;
        }>
    > = [];
    const contributedGeneratedSources: Array<
        Readonly<{
            builderHandle: number;
            family: SetupKeyRelationFamily;
            generatedProofHandle: number;
            statementSourceHandle: number;
        }>
    > = [];
    const discardedStatementSources: number[] = [];
    const generationPreparations: Array<
        Readonly<{ family: SetupKeyRelationFamily; mode: GenerationMode }>
    > = [];
    const selectedSuiteReleases: number[] = [];
    let nextPointer = 1_024;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake key-relation allocation was released with the wrong length.',
            );
        }
        allocations.delete(pointer);
    };
    const prepare = (
        family: SetupKeyRelationFamily,
        mode: GenerationMode,
        sourceHandlePointer: number,
        statusPointer: number,
    ): number => {
        generationPreparations.push({ family, mode });
        new DataView(memory.buffer).setUint32(
            sourceHandlePointer,
            family === 'sameSecret' ? 21 : 22,
            true,
        );
        writeStatus(memory, statusPointer, 0);
        return family === 'sameSecret' ? 31 : 32;
    };
    type PrepareArguments = [
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
    ];
    const preparation =
        (family: SetupKeyRelationFamily, mode: GenerationMode) =>
        (...parameters: PrepareArguments): number =>
            prepare(family, mode, parameters[13], parameters[14]);
    const cancelGeneratedSource =
        (family: SetupKeyRelationFamily) =>
        (
            statementSourceHandle: number,
            generatedProofHandle: number,
        ): number => {
            cancelledGeneratedSources.push({
                family,
                generatedProofHandle,
                statementSourceHandle,
            });
            return 0;
        };
    const contributeGeneratedSource =
        (family: SetupKeyRelationFamily) =>
        (
            builderHandle: number,
            statementSourceHandle: number,
            generatedProofHandle: number,
        ): number => {
            contributedGeneratedSources.push({
                builderHandle,
                family,
                generatedProofHandle,
                statementSourceHandle,
            });
            return 0;
        };

    const wasmExports = {
        sealed_lattice_common_proof_release_suite: (handle: number) => {
            selectedSuiteReleases.push(handle);
            return 0;
        },
        sealed_lattice_common_proof_select_suite: (
            _pointer: number,
            _byteLength: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 11;
        },
        sealed_lattice_public_key_share_prepare_generation: preparation(
            'publicKeyShare',
            'fresh',
        ),
        sealed_lattice_public_key_share_prepare_resumed_generation: preparation(
            'publicKeyShare',
            'resumed',
        ),
        sealed_lattice_public_key_share_generation_cancel:
            cancelGeneratedSource('publicKeyShare'),
        sealed_lattice_public_key_share_generation_contribute_package:
            contributeGeneratedSource('publicKeyShare'),
        sealed_lattice_same_secret_prepare_generation: preparation(
            'sameSecret',
            'fresh',
        ),
        sealed_lattice_same_secret_prepare_resumed_generation: preparation(
            'sameSecret',
            'resumed',
        ),
        sealed_lattice_same_secret_generation_cancel:
            cancelGeneratedSource('sameSecret'),
        sealed_lattice_same_secret_generation_contribute_package:
            contributeGeneratedSource('sameSecret'),
        sealed_lattice_setup_key_relation_generation_statement_discard: (
            handle: number,
        ) => {
            discardedStatementSources.push(handle);
            return 0;
        },
    };
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error(
                'The focused key-relation test does not use commands.',
            );
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports,
    } as unknown as TranscriptCoreKernelCommandRuntime;
    registerCommonProofKernelContext(kernel, context);
    boundaryMocks.activeContext.value = context;
    return Object.freeze({
        allocations,
        cancelledGeneratedSources,
        contributedGeneratedSources,
        discardedStatementSources,
        generationPreparations,
        kernel,
        selectedSuiteReleases,
    });
};

const generationInput = (
    runtime: FakeSetupKeyRelationRuntime,
    mode: GenerationMode,
) => ({
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    checkpointLineageIdentifier: new Uint8Array(32).fill(7),
    generationMode: mode,
    kernel: runtime.kernel,
    openProofGenerationExecution: () =>
        Promise.resolve(
            Object.freeze({
                externalMemory: Object.freeze({}),
                options:
                    mode === 'resumed'
                        ? Object.freeze({ resume: Object.freeze({}) })
                        : undefined,
                outputStore: Object.freeze({}),
            }),
        ),
    productionOperationIdentifiers: Object.freeze({}),
    setupGenerationAuthority: Object.freeze({}),
    setupIntentObject: Object.freeze({}),
    workerKernel: Object.freeze({ kernel: runtime.kernel }),
});

const verificationInput = (
    kernel: TranscriptCoreKernel,
    generatedProof: Awaited<
        ReturnType<typeof generateAcceptedSetupSameSecretInClosedWorker>
    >,
) => ({
    assembly: Object.freeze({}),
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    generatedProof,
    inputStore: Object.freeze({}),
    kernel,
    verifiedVssShareLinkageTerminal:
        boundaryMocks.verifiedVssShareLinkageTerminal,
});

beforeEach(() => {
    vi.clearAllMocks();
    boundaryMocks.generatedConsumptionOutcomes.splice(0);
    boundaryMocks.deriveProofDescriptor.mockResolvedValue(
        Uint8Array.of(0xd1, 0xd2),
    );
    boundaryMocks.verifyGeneratedPublicKeyShare.mockResolvedValue(undefined);
    boundaryMocks.verifyGeneratedSameSecret.mockResolvedValue(undefined);
});

describe('accepted-setup key-relation generation', () => {
    it.each([
        [
            'sameSecret',
            'fresh',
            generateAcceptedSetupSameSecretInClosedWorker,
            canonicalStreamDomains.sameSecretProof,
            21,
        ],
        [
            'sameSecret',
            'resumed',
            generateAcceptedSetupSameSecretInClosedWorker,
            canonicalStreamDomains.sameSecretProof,
            21,
        ],
        [
            'publicKeyShare',
            'fresh',
            generateAcceptedSetupPublicKeyShareInClosedWorker,
            canonicalStreamDomains.publicKeyShareProof,
            22,
        ],
        [
            'publicKeyShare',
            'resumed',
            generateAcceptedSetupPublicKeyShareInClosedWorker,
            canonicalStreamDomains.publicKeyShareProof,
            22,
        ],
    ] as const)(
        'retains the exact %s %s proof for package verification',
        async (
            family,
            mode,
            generate,
            expectedStreamDomain,
            statementSourceHandle,
        ) => {
            const runtime = createFakeRuntime();
            const proof = await generate(
                generationInput(runtime, mode) as never,
            );

            expect(runtime.generationPreparations).toEqual([{ family, mode }]);
            expect(proof.copyProofDescriptorBytes()).toEqual(
                Uint8Array.of(0xd1, 0xd2),
            );
            expect(boundaryMocks.deriveProofDescriptor).toHaveBeenCalledWith(
                expect.objectContaining({ streamDomain: expectedStreamDomain }),
            );
            expect(runtime.selectedSuiteReleases).toEqual([11]);
            expect(runtime.discardedStatementSources).toEqual([]);
            expect(runtime.allocations.size).toBe(0);

            proof.release();
            expect(runtime.cancelledGeneratedSources).toEqual([
                {
                    family,
                    generatedProofHandle: 301,
                    statementSourceHandle,
                },
            ]);
            expect(boundaryMocks.generatedConsumptionOutcomes).toEqual([true]);
            expect(
                boundaryMocks.generatedCapabilityRelease,
            ).not.toHaveBeenCalled();
            expect(() => proof.copyProofDescriptorBytes()).toThrow(/consumed/u);
        },
    );

    it('refuses unsupported generation modes before preparing any family', async () => {
        const runtime = createFakeRuntime();
        await expect(
            generateAcceptedSetupSameSecretInClosedWorker({
                ...generationInput(runtime, 'fresh'),
                generationMode: 'invalid',
            } as never),
        ).rejects.toThrow(/wrongContext/u);
        await expect(
            generateAcceptedSetupPublicKeyShareInClosedWorker({
                ...generationInput(runtime, 'resumed'),
                generationMode: undefined,
            } as never),
        ).rejects.toThrow(/wrongContext/u);
        expect(runtime.generationPreparations).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('releases generated authority when proof-descriptor derivation fails', async () => {
        const runtime = createFakeRuntime();
        boundaryMocks.deriveProofDescriptor.mockRejectedValueOnce(
            new Error('descriptor failed'),
        );
        await expect(
            generateAcceptedSetupPublicKeyShareInClosedWorker(
                generationInput(runtime, 'fresh') as never,
            ),
        ).rejects.toThrow('descriptor failed');
        expect(runtime.cancelledGeneratedSources).toEqual([
            {
                family: 'publicKeyShare',
                generatedProofHandle: 301,
                statementSourceHandle: 22,
            },
        ]);
        expect(boundaryMocks.generatedCapabilityRelease).not.toHaveBeenCalled();
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });
});

describe('generated accepted-setup key-relation verification', () => {
    it.each([
        [
            generateAcceptedSetupSameSecretInClosedWorker,
            verifyGeneratedAcceptedSetupSameSecretInClosedWorker,
            boundaryMocks.verifyGeneratedSameSecret,
        ],
        [
            generateAcceptedSetupPublicKeyShareInClosedWorker,
            verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker,
            boundaryMocks.verifyGeneratedPublicKeyShare,
        ],
    ] as const)(
        'consumes generated authority only after package-backed positive verification',
        async (generate, verifyGenerated, verifyCapability) => {
            const runtime = createFakeRuntime();
            const proof = await generate(
                generationInput(runtime, 'resumed') as never,
            );
            await verifyGenerated(
                verificationInput(runtime.kernel, proof) as never,
            );

            expect(verifyCapability).toHaveBeenCalledTimes(1);
            expect(verifyCapability.mock.calls[0]?.[1]).toBe(
                boundaryMocks.generatedCapability,
            );
            expect(verifyCapability.mock.calls[0]?.[2]).toBe(
                generate === generateAcceptedSetupSameSecretInClosedWorker
                    ? 21
                    : 22,
            );
            expect(
                boundaryMocks.generatedCapabilityRelease,
            ).not.toHaveBeenCalled();
            expect(() => proof.copyProofDescriptorBytes()).toThrow(/consumed/u);
        },
    );

    it('keeps a refused generated proof retryable and rejects cross-family use', async () => {
        const runtime = createFakeRuntime();
        const proof = await generateAcceptedSetupSameSecretInClosedWorker(
            generationInput(runtime, 'fresh') as never,
        );
        await expect(
            verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker(
                verificationInput(runtime.kernel, proof) as never,
            ),
        ).rejects.toThrow(/wrongContext/u);
        boundaryMocks.verifyGeneratedSameSecret.mockRejectedValueOnce(
            new Error('package refused'),
        );
        await expect(
            verifyGeneratedAcceptedSetupSameSecretInClosedWorker(
                verificationInput(runtime.kernel, proof) as never,
            ),
        ).rejects.toThrow('package refused');
        expect(proof.copyProofDescriptorBytes()).toEqual(
            Uint8Array.of(0xd1, 0xd2),
        );

        await verifyGeneratedAcceptedSetupSameSecretInClosedWorker(
            verificationInput(runtime.kernel, proof) as never,
        );
        expect(boundaryMocks.verifyGeneratedSameSecret).toHaveBeenCalledTimes(
            2,
        );
        expect(() => proof.copyProofDescriptorBytes()).toThrow(/consumed/u);
    });

    it('rejects cross-worker verification without consuming the proof', async () => {
        const sourceRuntime = createFakeRuntime();
        const proof = await generateAcceptedSetupSameSecretInClosedWorker(
            generationInput(sourceRuntime, 'fresh') as never,
        );
        const otherRuntime = createFakeRuntime();
        await expect(
            verifyGeneratedAcceptedSetupSameSecretInClosedWorker(
                verificationInput(otherRuntime.kernel, proof) as never,
            ),
        ).rejects.toThrow(/wrongContext/u);
        expect(proof.copyProofDescriptorBytes()).toEqual(
            Uint8Array.of(0xd1, 0xd2),
        );
        proof.release();
    });
});

describe('generated accepted-setup package contribution', () => {
    it.each([
        [
            'sameSecret',
            generateAcceptedSetupSameSecretInClosedWorker,
            contributeGeneratedAcceptedSetupSameSecretToPackage,
            21,
        ],
        [
            'publicKeyShare',
            generateAcceptedSetupPublicKeyShareInClosedWorker,
            contributeGeneratedAcceptedSetupPublicKeyShareToPackage,
            22,
        ],
    ] as const)(
        'contributes the retained %s source and proof without host descriptors',
        async (family, generate, contribute, statementSourceHandle) => {
            const runtime = createFakeRuntime();
            const proof = await generate(
                generationInput(runtime, 'fresh') as never,
            );

            contribute({
                generatedProof: proof,
                packageBuilder: Object.freeze({}) as never,
            });

            expect(runtime.contributedGeneratedSources).toEqual([
                {
                    builderHandle: 41,
                    family,
                    generatedProofHandle: 301,
                    statementSourceHandle,
                },
            ]);
            expect(boundaryMocks.generatedConsumptionOutcomes).toEqual([false]);

            proof.release();
        },
    );

    it('rejects a cross-family contribution without changing source custody', async () => {
        const runtime = createFakeRuntime();
        const proof = await generateAcceptedSetupSameSecretInClosedWorker(
            generationInput(runtime, 'fresh') as never,
        );

        expect(() =>
            contributeGeneratedAcceptedSetupPublicKeyShareToPackage({
                generatedProof: proof,
                packageBuilder: Object.freeze({}) as never,
            }),
        ).toThrow(/wrongContext/u);
        expect(runtime.contributedGeneratedSources).toEqual([]);
        expect(proof.copyProofDescriptorBytes()).toEqual(
            Uint8Array.of(0xd1, 0xd2),
        );

        proof.release();
    });
});
