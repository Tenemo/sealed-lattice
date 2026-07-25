import { refusalReasonCodes } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
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
    const verifiedVssShareLinkageTerminal = Object.freeze({});
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
        verifiedVssShareLinkageTerminal,
        verifiedCapabilityRelease,
        verifiedConsumptionOutcomes,
        withVerifiedVssShareLinkageTerminal: vi.fn(
            (input: Readonly<{ inspect(handle: number): unknown }>) =>
                input.inspect(501),
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
    withVerifiedVssShareLinkageTerminal:
        boundaryMocks.withVerifiedVssShareLinkageTerminal,
}));

type VerificationFamily = 'publicKeyShare' | 'sameSecret';

type FakeAcceptedSetupProofVerificationRuntime = Readonly<{
    allocations: ReadonlyMap<number, number>;
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
            _verifiedVssShareLinkageTerminalHandle: number,
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
                _verifiedVssShareLinkageTerminalHandle: number,
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
                boundaryMocks.verifiedVssShareLinkageTerminal as never,
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
                boundaryMocks.verifiedVssShareLinkageTerminal as never,
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
            verifiedVssShareLinkageTerminal:
                boundaryMocks.verifiedVssShareLinkageTerminal,
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
