import { refusalReasonCodes } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    verifyAcceptedSetupCompactPublicKeyShareInClosedWorker,
    verifyAcceptedSetupSameSecretInClosedWorker,
    verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker,
    verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker,
} from '#packages/wasm/src/accepted-setup-proof-verification-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const boundaryMocks = vi.hoisted(() => {
    const generatedCapabilityRelease = vi.fn();
    const verifiedCapabilityRelease = vi.fn();
    const generatedCapability = Object.freeze({
        release: generatedCapabilityRelease,
    });
    const vssLowDegreeEvidence = Object.freeze({});
    const verifiedCapability = Object.freeze({
        release: verifiedCapabilityRelease,
    });
    const generatedConsumptionOutcomes: boolean[] = [];
    const verifiedConsumptionOutcomes: boolean[] = [];
    return {
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
        applyVerifiedCapability: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (
                    handle: number,
                ) => Readonly<{ consumed: boolean; result: number }>,
            ) => {
                const outcome = apply(401);
                verifiedConsumptionOutcomes.push(outcome.consumed);
                return outcome.result;
            },
        ),
        generatedCapability,
        generatedCapabilityRelease,
        generatedConsumptionOutcomes,
        openVerificationAdapter: vi.fn(() => Object.freeze({})),
        releaseVerificationAdapter: vi.fn(),
        requireAssemblyOwner: vi.fn(
            (_assembly: unknown, kernel: TranscriptCoreKernel) =>
                Object.freeze({ handle: 19, kernel }),
        ),
        runVerification: vi.fn(() => Promise.resolve(verifiedCapability)),
        vssLowDegreeEvidence,
        verifiedCapabilityRelease,
        verifiedConsumptionOutcomes,
        consumeVerifiedVssLowDegreeEvidence: vi.fn(
            (input: Readonly<{ consume(handle: number): unknown }>) =>
                input.consume(501),
        ),
    };
});

vi.mock('#packages/wasm/src/accepted-setup-assembly-runtime', () => ({
    requireAcceptedSetupVerificationAssemblyKernelOwner:
        boundaryMocks.requireAssemblyOwner,
}));

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    applyClosedWorkerGeneratedCommonProofCapability:
        boundaryMocks.applyGeneratedCapability,
    applyClosedWorkerVerifiedCommonProofCapability:
        boundaryMocks.applyVerifiedCapability,
    openClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.openVerificationAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.releaseVerificationAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.runVerification,
}));

vi.mock('#packages/wasm/src/vss-share-linkage-verification-runtime', () => ({
    consumeVerifiedVssLowDegreeEvidence:
        boundaryMocks.consumeVerifiedVssLowDegreeEvidence,
}));

type VerificationFamily = 'publicKeyShare' | 'sameSecret';

type FakeAcceptedSetupProofVerificationRuntime = Readonly<{
    allocations: ReadonlyMap<number, number>;
    compactPublicKey: {
        beginStatus: number;
        cancelledOperationHandles: number[];
        discardedCapabilityHandles: number[];
        discardedPreparedHandles: number[];
        finishStatus: number;
        observedCheckpointBytes: number[];
        observedProofBytes: number[];
        observedPublicInputBytes: number[];
        pollOutcomes: Array<
            Readonly<{
                checkpointSafeBoundaryOrdinal: number;
                completedWorkUnitCount: number;
                pollKind: number;
                status: number;
                verifiedCapabilityHandle: number;
            }>
        >;
        pollRefusalReleaseCount: number;
        preparationStatus: number;
    };
    discardedTerminalSources: number[];
    finishStatus: { value: number };
    generatedFinishes: Array<
        Readonly<{
            family: VerificationFamily;
            generatedProofHandle: number;
            terminalSourceHandle: number;
            verifiedProofHandle: number;
        }>
    >;
    kernel: TranscriptCoreKernel;
    ordinaryFinishes: Array<
        Readonly<{
            family: VerificationFamily;
            terminalSourceHandle: number;
            verifiedProofHandle: number;
        }>
    >;
    preparedStatements: Array<
        Readonly<{ bytes: number[]; family: VerificationFamily }>
    >;
    preparedGeneratedSources: Array<
        Readonly<{
            family: VerificationFamily;
            generationStatementSourceHandle: number;
        }>
    >;
    selectedSuiteReleases: number[];
}>;

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeRuntime = (): FakeAcceptedSetupProofVerificationRuntime => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const compactPublicKey: FakeAcceptedSetupProofVerificationRuntime['compactPublicKey'] =
        {
            beginStatus: 0,
            cancelledOperationHandles: [],
            discardedCapabilityHandles: [],
            discardedPreparedHandles: [],
            finishStatus: 0,
            observedCheckpointBytes: [],
            observedProofBytes: [],
            observedPublicInputBytes: [],
            pollOutcomes: [
                {
                    checkpointSafeBoundaryOrdinal: 0xffff_ffff,
                    completedWorkUnitCount: 7,
                    pollKind: 1,
                    status: 0,
                    verifiedCapabilityHandle: 0,
                },
                {
                    checkpointSafeBoundaryOrdinal: 0xffff_ffff,
                    completedWorkUnitCount: 0,
                    pollKind: 5,
                    status: 0,
                    verifiedCapabilityHandle: 81,
                },
            ],
            pollRefusalReleaseCount: 0,
            preparationStatus: 0,
        };
    const discardedTerminalSources: number[] = [];
    const finishStatus = { value: 0 };
    const generatedFinishes: Array<
        Readonly<{
            family: VerificationFamily;
            generatedProofHandle: number;
            terminalSourceHandle: number;
            verifiedProofHandle: number;
        }>
    > = [];
    const ordinaryFinishes: Array<
        Readonly<{
            family: VerificationFamily;
            terminalSourceHandle: number;
            verifiedProofHandle: number;
        }>
    > = [];
    const preparedStatements: Array<
        Readonly<{ bytes: number[]; family: VerificationFamily }>
    > = [];
    const preparedGeneratedSources: Array<
        Readonly<{
            family: VerificationFamily;
            generationStatementSourceHandle: number;
        }>
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
                'The fake accepted-setup proof allocation was released with the wrong length.',
            );
        }
        allocations.delete(pointer);
    };
    const prepare = (
        family: VerificationFamily,
        statementPointer: number,
        statementByteLength: number,
        sourceHandlePointer: number,
        statusPointer: number,
    ): number => {
        preparedStatements.push({
            bytes: Array.from(
                new Uint8Array(
                    memory.buffer,
                    statementPointer,
                    statementByteLength,
                ),
            ),
            family,
        });
        new DataView(memory.buffer).setUint32(
            sourceHandlePointer,
            family === 'sameSecret' ? 61 : 62,
            true,
        );
        writeStatus(memory, statusPointer, 0);
        return family === 'sameSecret' ? 71 : 72;
    };
    const finishGenerated = (
        family: VerificationFamily,
        verifiedProofHandle: number,
        terminalSourceHandle: number,
        generatedProofHandle: number,
    ): number => {
        generatedFinishes.push({
            family,
            generatedProofHandle,
            terminalSourceHandle,
            verifiedProofHandle,
        });
        return finishStatus.value;
    };
    const prepareGenerated = (
        family: VerificationFamily,
        generationStatementSourceHandle: number,
        sourceHandlePointer: number,
        statusPointer: number,
    ): number => {
        preparedGeneratedSources.push({
            family,
            generationStatementSourceHandle,
        });
        new DataView(memory.buffer).setUint32(
            sourceHandlePointer,
            family === 'sameSecret' ? 61 : 62,
            true,
        );
        writeStatus(memory, statusPointer, 0);
        return family === 'sameSecret' ? 71 : 72;
    };
    const finishOrdinary = (
        family: VerificationFamily,
        verifiedProofHandle: number,
        terminalSourceHandle: number,
    ): number => {
        ordinaryFinishes.push({
            family,
            terminalSourceHandle,
            verifiedProofHandle,
        });
        return finishStatus.value;
    };

    const wasmExports = {
        sealed_lattice_accepted_setup_compact_public_key_begin_verification: (
            preparedHandle: number,
            proofPointer: number,
            proofByteLength: number,
            publicInputPointer: number,
            publicInputByteLength: number,
            statusPointer: number,
        ) => {
            expect(preparedHandle).toBe(81);
            compactPublicKey.observedProofBytes = Array.from(
                new Uint8Array(memory.buffer, proofPointer, proofByteLength),
            );
            compactPublicKey.observedPublicInputBytes = Array.from(
                new Uint8Array(
                    memory.buffer,
                    publicInputPointer,
                    publicInputByteLength,
                ),
            );
            writeStatus(memory, statusPointer, compactPublicKey.beginStatus);
            return compactPublicKey.beginStatus === 0 ? 81 : 0;
        },
        sealed_lattice_accepted_setup_compact_public_key_cancel_verification: (
            handle: number,
        ) => {
            compactPublicKey.cancelledOperationHandles.push(handle);
            return 0;
        },
        sealed_lattice_accepted_setup_compact_public_key_copy_verification_checkpoint:
            (
                operationHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                expect(operationHandle).toBe(81);
                expect(outputByteLength).toBe(404);
                new Uint8Array(
                    memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).fill(0x5c);
                return 0;
            },
        sealed_lattice_accepted_setup_compact_public_key_discard_capability: (
            handle: number,
        ) => {
            compactPublicKey.discardedCapabilityHandles.push(handle);
            return 0;
        },
        sealed_lattice_accepted_setup_compact_public_key_discard_prepared_verification:
            (handle: number) => {
                compactPublicKey.discardedPreparedHandles.push(handle);
                return 0;
            },
        sealed_lattice_accepted_setup_compact_public_key_finish_verification: (
            handle: number,
        ) => {
            expect(handle).toBe(81);
            return compactPublicKey.finishStatus;
        },
        sealed_lattice_accepted_setup_compact_public_key_resume_verification: (
            preparedHandle: number,
            proofPointer: number,
            proofByteLength: number,
            publicInputPointer: number,
            publicInputByteLength: number,
            checkpointPointer: number,
            checkpointByteLength: number,
            statusPointer: number,
        ) => {
            expect(preparedHandle).toBe(81);
            compactPublicKey.observedProofBytes = Array.from(
                new Uint8Array(memory.buffer, proofPointer, proofByteLength),
            );
            compactPublicKey.observedPublicInputBytes = Array.from(
                new Uint8Array(
                    memory.buffer,
                    publicInputPointer,
                    publicInputByteLength,
                ),
            );
            compactPublicKey.observedCheckpointBytes = Array.from(
                new Uint8Array(
                    memory.buffer,
                    checkpointPointer,
                    checkpointByteLength,
                ),
            );
            writeStatus(memory, statusPointer, compactPublicKey.beginStatus);
            return compactPublicKey.beginStatus === 0 ? 81 : 0;
        },
        sealed_lattice_accepted_setup_compact_public_key_verification_poll: (
            operationHandle: number,
            maximumWorkUnitCount: number,
            pollKindPointer: number,
            completedWorkUnitCountPointer: number,
            checkpointSafeBoundaryOrdinalPointer: number,
            verifiedCapabilityHandlePointer: number,
        ) => {
            expect(operationHandle).toBe(81);
            expect(maximumWorkUnitCount).toBe(7);
            const outcome = compactPublicKey.pollOutcomes.shift();
            if (outcome === undefined) {
                throw new Error(
                    'The focused compact public-key verifier exhausted its poll outcomes.',
                );
            }
            if (outcome.status !== 0) {
                compactPublicKey.pollRefusalReleaseCount += 1;
                return outcome.status;
            }
            writeStatus(memory, pollKindPointer, outcome.pollKind);
            writeStatus(
                memory,
                completedWorkUnitCountPointer,
                outcome.completedWorkUnitCount,
            );
            writeStatus(
                memory,
                checkpointSafeBoundaryOrdinalPointer,
                outcome.checkpointSafeBoundaryOrdinal,
            );
            writeStatus(
                memory,
                verifiedCapabilityHandlePointer,
                outcome.verifiedCapabilityHandle,
            );
            return 0;
        },
        sealed_lattice_accepted_setup_public_key_share_prepare_compact_verification:
            (
                _assemblyHandle: number,
                statementPointer: number,
                statementByteLength: number,
                statusPointer: number,
            ) => {
                preparedStatements.push({
                    bytes: Array.from(
                        new Uint8Array(
                            memory.buffer,
                            statementPointer,
                            statementByteLength,
                        ),
                    ),
                    family: 'publicKeyShare',
                });
                writeStatus(
                    memory,
                    statusPointer,
                    compactPublicKey.preparationStatus,
                );
                return compactPublicKey.preparationStatus === 0 ? 81 : 0;
            },
        sealed_lattice_compact_public_key_algebraic_verification_checkpoint_byte_length:
            () => 400,
        sealed_lattice_compact_public_key_algebraic_verification_safe_boundary_count:
            () => 290,
        sealed_lattice_accepted_setup_compact_public_key_verification_checkpoint_byte_length:
            () => 404,
        sealed_lattice_accepted_setup_compact_public_key_verification_safe_boundary_count:
            () => 4_509,
        sealed_lattice_accepted_setup_public_key_share_discard_terminal_source:
            (handle: number) => {
                discardedTerminalSources.push(handle);
                return 0;
            },
        sealed_lattice_accepted_setup_public_key_share_finish_generated_verification:
            (
                verifiedProofHandle: number,
                terminalSourceHandle: number,
                generatedProofHandle: number,
            ) =>
                finishGenerated(
                    'publicKeyShare',
                    verifiedProofHandle,
                    terminalSourceHandle,
                    generatedProofHandle,
                ),
        sealed_lattice_accepted_setup_public_key_share_finish_verification: (
            verifiedProofHandle: number,
            terminalSourceHandle: number,
        ) =>
            finishOrdinary(
                'publicKeyShare',
                verifiedProofHandle,
                terminalSourceHandle,
            ),
        sealed_lattice_accepted_setup_public_key_share_prepare_verification: (
            _selectedSuiteHandle: number,
            _assemblyHandle: number,
            statementPointer: number,
            statementByteLength: number,
            sourceHandlePointer: number,
            statusPointer: number,
        ) =>
            prepare(
                'publicKeyShare',
                statementPointer,
                statementByteLength,
                sourceHandlePointer,
                statusPointer,
            ),
        sealed_lattice_accepted_setup_public_key_share_prepare_generated_verification:
            (
                _selectedSuiteHandle: number,
                _assemblyHandle: number,
                generationStatementSourceHandle: number,
                sourceHandlePointer: number,
                statusPointer: number,
            ) =>
                prepareGenerated(
                    'publicKeyShare',
                    generationStatementSourceHandle,
                    sourceHandlePointer,
                    statusPointer,
                ),
        sealed_lattice_accepted_setup_same_secret_discard_terminal_source: (
            handle: number,
        ) => {
            discardedTerminalSources.push(handle);
            return 0;
        },
        sealed_lattice_accepted_setup_same_secret_finish_generated_verification:
            (
                verifiedProofHandle: number,
                terminalSourceHandle: number,
                generatedProofHandle: number,
            ) =>
                finishGenerated(
                    'sameSecret',
                    verifiedProofHandle,
                    terminalSourceHandle,
                    generatedProofHandle,
                ),
        sealed_lattice_accepted_setup_same_secret_finish_verification: (
            verifiedProofHandle: number,
            terminalSourceHandle: number,
        ) =>
            finishOrdinary(
                'sameSecret',
                verifiedProofHandle,
                terminalSourceHandle,
            ),
        sealed_lattice_accepted_setup_same_secret_prepare_verification: (
            _selectedSuiteHandle: number,
            _assemblyHandle: number,
            _vssLowDegreeEvidenceHandle: number,
            statementPointer: number,
            statementByteLength: number,
            sourceHandlePointer: number,
            statusPointer: number,
        ) =>
            prepare(
                'sameSecret',
                statementPointer,
                statementByteLength,
                sourceHandlePointer,
                statusPointer,
            ),
        sealed_lattice_accepted_setup_same_secret_prepare_generated_verification:
            (
                _selectedSuiteHandle: number,
                _assemblyHandle: number,
                generationStatementSourceHandle: number,
                sourceHandlePointer: number,
                statusPointer: number,
            ) =>
                prepareGenerated(
                    'sameSecret',
                    generationStatementSourceHandle,
                    sourceHandlePointer,
                    statusPointer,
                ),
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
    };
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error(
                'The focused accepted-setup proof test does not use commands.',
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
    return Object.freeze({
        allocations,
        compactPublicKey,
        discardedTerminalSources,
        finishStatus,
        generatedFinishes,
        kernel,
        ordinaryFinishes,
        preparedGeneratedSources,
        preparedStatements,
        selectedSuiteReleases,
    });
};

const verificationInput = (kernel: TranscriptCoreKernel) => ({
    assembly: Object.freeze({}),
    canonicalApplicationStatementBytes: Uint8Array.of(4, 5, 6, 7),
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    inputStore: Object.freeze({}),
    kernel,
});

const compactPublicKeyVerificationInput = (kernel: TranscriptCoreKernel) => ({
    assembly: Object.freeze({}),
    canonicalApplicationStatementBytes: Uint8Array.of(4, 5, 6, 7),
    canonicalProofBytes: Uint8Array.of(8, 9, 10),
    canonicalPublicInputBytes: Uint8Array.of(11, 12),
    kernel,
    options: {
        maximumWorkUnitCountPerPoll: 7,
        yieldControl: () => Promise.resolve(),
    },
});

beforeEach(() => {
    vi.clearAllMocks();
    boundaryMocks.generatedConsumptionOutcomes.splice(0);
    boundaryMocks.verifiedConsumptionOutcomes.splice(0);
});

describe('accepted-setup generated proof verification', () => {
    it.each([
        [
            'sameSecret',
            verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker,
            61,
        ],
        [
            'publicKeyShare',
            verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker,
            62,
        ],
    ] as const)(
        'atomically consumes the %s generated and positive verifier capabilities',
        async (family, verifyGenerated, terminalSourceHandle) => {
            const runtime = createFakeRuntime();
            await verifyGenerated(
                verificationInput(runtime.kernel) as never,
                boundaryMocks.generatedCapability,
                51,
            );

            expect(runtime.generatedFinishes).toEqual([
                {
                    family,
                    generatedProofHandle: 301,
                    terminalSourceHandle,
                    verifiedProofHandle: 401,
                },
            ]);
            expect(boundaryMocks.generatedConsumptionOutcomes).toEqual([true]);
            expect(boundaryMocks.verifiedConsumptionOutcomes).toEqual([true]);
            expect(
                boundaryMocks.generatedCapabilityRelease,
            ).not.toHaveBeenCalled();
            expect(
                boundaryMocks.verifiedCapabilityRelease,
            ).not.toHaveBeenCalled();
            expect(runtime.discardedTerminalSources).toEqual([]);
            expect(runtime.preparedGeneratedSources).toEqual([
                {
                    family,
                    generationStatementSourceHandle: 51,
                },
            ]);
            expect(runtime.preparedStatements).toEqual([]);
            expect(runtime.selectedSuiteReleases).toEqual([11]);
            expect(runtime.allocations.size).toBe(0);
        },
    );

    it('keeps generated authority live when package binding is refused', async () => {
        const runtime = createFakeRuntime();
        runtime.finishStatus.value = refusalReasonCodes.wrongContext;
        await expect(
            verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker(
                verificationInput(runtime.kernel) as never,
                boundaryMocks.generatedCapability,
                51,
            ),
        ).rejects.toThrow(/wrongContext/u);

        expect(boundaryMocks.generatedConsumptionOutcomes).toEqual([false]);
        expect(boundaryMocks.verifiedConsumptionOutcomes).toEqual([false]);
        expect(boundaryMocks.generatedCapabilityRelease).not.toHaveBeenCalled();
        expect(boundaryMocks.verifiedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.discardedTerminalSources).toEqual([61]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('preserves the received-proof finish path without generated authority', async () => {
        const runtime = createFakeRuntime();
        await verifyAcceptedSetupSameSecretInClosedWorker({
            ...verificationInput(runtime.kernel),
            vssLowDegreeEvidence: boundaryMocks.vssLowDegreeEvidence,
        } as never);

        expect(runtime.ordinaryFinishes).toEqual([
            {
                family: 'sameSecret',
                terminalSourceHandle: 61,
                verifiedProofHandle: 401,
            },
        ]);
        expect(runtime.generatedFinishes).toEqual([]);
        expect(boundaryMocks.applyGeneratedCapability).not.toHaveBeenCalled();
        expect(boundaryMocks.verifiedConsumptionOutcomes).toEqual([true]);
        expect(runtime.allocations.size).toBe(0);
    });
});

describe('accepted-setup compact public-key verification', () => {
    it('commits only the source-bound positive capability', async () => {
        const runtime = createFakeRuntime();

        await expect(
            verifyAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactPublicKeyVerificationInput(runtime.kernel) as never,
            ),
        ).resolves.toEqual({ isValid: true, value: undefined });

        expect(runtime.compactPublicKey.observedProofBytes).toEqual([8, 9, 10]);
        expect(runtime.compactPublicKey.observedPublicInputBytes).toEqual([
            11, 12,
        ]);
        expect(runtime.compactPublicKey.pollOutcomes).toEqual([]);
        expect(runtime.compactPublicKey.cancelledOperationHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedPreparedHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedCapabilityHandles).toEqual([]);
        expect(runtime.preparedStatements).toEqual([
            {
                bytes: [4, 5, 6, 7],
                family: 'publicKeyShare',
            },
        ]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('publishes a source-correspondence checkpoint beyond the algebra-only schedule', async () => {
        const runtime = createFakeRuntime();
        runtime.compactPublicKey.pollOutcomes[0] = {
            checkpointSafeBoundaryOrdinal: 291,
            completedWorkUnitCount: 1,
            pollKind: 1,
            status: 0,
            verifiedCapabilityHandle: 0,
        };
        const publishedCheckpoints: Array<{
            bytes: number[];
            safeBoundaryOrdinal: number;
        }> = [];
        const release = vi.fn(() => Promise.resolve());
        const checkpointCustody = {
            publishAuthenticatedCheckpoint: vi.fn(
                (
                    canonicalCheckpointBytes: Uint8Array,
                    safeBoundaryOrdinal: number,
                ) => {
                    publishedCheckpoints.push({
                        bytes: Array.from(canonicalCheckpointBytes),
                        safeBoundaryOrdinal,
                    });
                    return Promise.resolve();
                },
            ),
            release,
            restoreAuthenticatedCheckpoint: vi.fn(() =>
                Promise.reject(
                    new Error(
                        'fresh verification must not restore a checkpoint',
                    ),
                ),
            ),
        };
        const input = compactPublicKeyVerificationInput(runtime.kernel);

        await expect(
            verifyAcceptedSetupCompactPublicKeyShareInClosedWorker({
                ...input,
                options: {
                    ...input.options,
                    checkpointCustody,
                },
            } as never),
        ).resolves.toEqual({ isValid: true, value: undefined });

        expect(publishedCheckpoints).toEqual([
            {
                bytes: Array.from({ length: 404 }, () => 0x5c),
                safeBoundaryOrdinal: 291,
            },
        ]);
        expect(release).toHaveBeenCalledOnce();
        expect(runtime.allocations.size).toBe(0);
    });

    it('restores a source-correspondence cursor and requires its exact replay boundary', async () => {
        const runtime = createFakeRuntime();
        runtime.compactPublicKey.pollOutcomes.splice(
            0,
            2,
            {
                checkpointSafeBoundaryOrdinal: 291,
                completedWorkUnitCount: 1,
                pollKind: 7,
                status: 0,
                verifiedCapabilityHandle: 0,
            },
            {
                checkpointSafeBoundaryOrdinal: 0xffff_ffff,
                completedWorkUnitCount: 0,
                pollKind: 5,
                status: 0,
                verifiedCapabilityHandle: 81,
            },
        );
        const restoredBytes = new Uint8Array(404).fill(0x6d);
        const release = vi.fn(() => Promise.resolve());
        const checkpointCustody = {
            publishAuthenticatedCheckpoint: vi.fn(() => Promise.resolve()),
            release,
            restoreAuthenticatedCheckpoint: vi.fn(() =>
                Promise.resolve({
                    canonicalCheckpointBytes: restoredBytes.slice(),
                    safeBoundaryOrdinal: 291,
                }),
            ),
        };
        const input = compactPublicKeyVerificationInput(runtime.kernel);

        await expect(
            verifyAcceptedSetupCompactPublicKeyShareInClosedWorker({
                ...input,
                options: {
                    ...input.options,
                    resume: { checkpointCustody },
                },
            } as never),
        ).resolves.toEqual({ isValid: true, value: undefined });

        expect(runtime.compactPublicKey.observedCheckpointBytes).toEqual(
            Array.from(restoredBytes),
        );
        expect(
            checkpointCustody.publishAuthenticatedCheckpoint,
        ).not.toHaveBeenCalled();
        expect(release).toHaveBeenCalledOnce();
        expect(runtime.allocations.size).toBe(0);
    });

    it('refuses split checkpoint custody before preparing verification and releases both identities', async () => {
        const runtime = createFakeRuntime();
        const freshRelease = vi.fn(() => Promise.resolve());
        const resumedRelease = vi.fn(() => Promise.resolve());
        const freshCheckpointCustody = {
            publishAuthenticatedCheckpoint: vi.fn(() => Promise.resolve()),
            release: freshRelease,
            restoreAuthenticatedCheckpoint: vi.fn(() =>
                Promise.reject(new Error('fresh custody cannot restore')),
            ),
        };
        const resumedCheckpointCustody = {
            publishAuthenticatedCheckpoint: vi.fn(() => Promise.resolve()),
            release: resumedRelease,
            restoreAuthenticatedCheckpoint: vi.fn(() =>
                Promise.resolve({
                    canonicalCheckpointBytes: new Uint8Array(404),
                    safeBoundaryOrdinal: 291,
                }),
            ),
        };
        const input = compactPublicKeyVerificationInput(runtime.kernel);

        await expect(
            verifyAcceptedSetupCompactPublicKeyShareInClosedWorker({
                ...input,
                options: {
                    ...input.options,
                    checkpointCustody: freshCheckpointCustody,
                    resume: { checkpointCustody: resumedCheckpointCustody },
                },
            } as never),
        ).rejects.toThrow(/never both/u);

        expect(freshRelease).toHaveBeenCalledOnce();
        expect(resumedRelease).toHaveBeenCalledOnce();
        expect(
            freshCheckpointCustody.publishAuthenticatedCheckpoint,
        ).not.toHaveBeenCalled();
        expect(
            resumedCheckpointCustody.restoreAuthenticatedCheckpoint,
        ).not.toHaveBeenCalled();
        expect(runtime.preparedStatements).toEqual([]);
        expect(runtime.compactPublicKey.cancelledOperationHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedPreparedHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedCapabilityHandles).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('discards the restored prepared authority after a begin refusal', async () => {
        const runtime = createFakeRuntime();
        runtime.compactPublicKey.beginStatus = refusalReasonCodes.wrongContext;

        await expect(
            verifyAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactPublicKeyVerificationInput(runtime.kernel) as never,
            ),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'wrongContext',
        });

        expect(runtime.compactPublicKey.discardedPreparedHandles).toEqual([81]);
        expect(runtime.compactPublicKey.cancelledOperationHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedCapabilityHandles).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('treats a poll refusal as terminal without cancelling a consumed operation', async () => {
        const runtime = createFakeRuntime();
        runtime.compactPublicKey.pollOutcomes.splice(0, 2, {
            checkpointSafeBoundaryOrdinal: 0xffff_ffff,
            completedWorkUnitCount: 0,
            pollKind: 0,
            status: refusalReasonCodes.invalidProof,
            verifiedCapabilityHandle: 0,
        });

        await expect(
            verifyAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactPublicKeyVerificationInput(runtime.kernel) as never,
            ),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'invalidProof',
        });

        expect(runtime.compactPublicKey.pollRefusalReleaseCount).toBe(1);
        expect(runtime.compactPublicKey.cancelledOperationHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedPreparedHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedCapabilityHandles).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('discards a positive capability when its destination slot refuses commit', async () => {
        const runtime = createFakeRuntime();
        runtime.compactPublicKey.finishStatus = refusalReasonCodes.wrongContext;

        await expect(
            verifyAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactPublicKeyVerificationInput(runtime.kernel) as never,
            ),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'wrongContext',
        });

        expect(runtime.compactPublicKey.discardedCapabilityHandles).toEqual([
            81,
        ]);
        expect(runtime.compactPublicKey.cancelledOperationHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedPreparedHandles).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels the live verifier when the worker is aborted between slices', async () => {
        const runtime = createFakeRuntime();
        const cancellationController = new AbortController();
        const input = compactPublicKeyVerificationInput(runtime.kernel);

        await expect(
            verifyAcceptedSetupCompactPublicKeyShareInClosedWorker({
                ...input,
                options: {
                    ...input.options,
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort();
                        return Promise.resolve();
                    },
                },
            } as never),
        ).rejects.toThrow(/cancelled/u);

        expect(runtime.compactPublicKey.cancelledOperationHandles).toEqual([
            81,
        ]);
        expect(runtime.compactPublicKey.discardedPreparedHandles).toEqual([]);
        expect(runtime.compactPublicKey.discardedCapabilityHandles).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });
});
