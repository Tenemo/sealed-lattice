import { refusalReasonCodes, type RefusalReason } from '@sealed-lattice/types';
import { describe, expect, it, vi } from 'vitest';

import type { AcceptedSetupVerificationSession } from '#packages/wasm/src/accepted-setup-assembly-runtime';
import {
    beginAcceptedSetupPackageBuilder,
    type AcceptedSetupPackageBuilder,
} from '#packages/wasm/src/accepted-setup-package-builder-runtime';
import type { AggregateThresholdShareRecipientAuthority } from '#packages/wasm/src/aggregate-threshold-share-authenticated-recipient';
import type { CanonicalBoardVerifierSession } from '#packages/wasm/src/canonical-board-runtime';
import { CanonicalStreamRefusalError } from '#packages/wasm/src/canonical-stream-runtime';
import type {
    ClosedWorkerGeneratedCommonProofCapability,
    VerifiedCommonProofCapability,
} from '#packages/wasm/src/common-proof-worker-runtime/runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

type CapturedProofSource = Readonly<{
    capabilityHandle: number;
    sourceKind: number;
    statement: Uint8Array<ArrayBuffer>;
}>;

type FakeBuilderState = {
    adoptionFailure: Error | undefined;
    readonly allocations: Map<number, number>;
    readonly authority: AggregateThresholdShareRecipientAuthority;
    readonly boardVerifierSession: CanonicalBoardVerifierSession;
    beginCount: number;
    cancelCount: number;
    readonly canonicalPackageBytes: Uint8Array<ArrayBuffer>;
    copyCount: number;
    copyStatuses: number[];
    readonly kernel: TranscriptCoreKernel;
    readonly memory: WebAssembly.Memory;
    readonly proofSources: CapturedProofSource[];
    finishCount: number;
    readonly verificationCancelHandles: number[];
    readonly verificationSession: AcceptedSetupVerificationSession;
};

const fakeStates = vi.hoisted(() => new WeakMap<object, FakeBuilderState>());

vi.mock('#packages/wasm/src/accepted-setup-assembly-runtime', () => ({
    adoptAcceptedSetupVerificationAssemblyFromKernelHandle: (input: {
        assemblyHandle: number;
        kernel: TranscriptCoreKernel;
        vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
    }): AcceptedSetupVerificationSession => {
        const state = fakeStates.get(input.kernel);
        if (
            state === undefined ||
            input.assemblyHandle !== 19 ||
            input.vssRecipientAuthority !== state.authority
        ) {
            throw new Error('Unexpected accepted-setup assembly adoption.');
        }
        if (state.adoptionFailure !== undefined) {
            throw state.adoptionFailure;
        }
        return state.verificationSession;
    },
}));

vi.mock(
    '#packages/wasm/src/aggregate-threshold-share-authenticated-recipient',
    () => ({
        requireAggregateThresholdShareRecipientAuthorityKernelOwner: (
            authority: AggregateThresholdShareRecipientAuthority,
            kernel: TranscriptCoreKernel,
        ) => {
            const state = fakeStates.get(kernel);
            if (state?.authority !== authority) {
                throw new CanonicalStreamRefusalError('wrongContext');
            }
            return Object.freeze({ handle: 17, kernel });
        },
    }),
);

vi.mock('#packages/wasm/src/canonical-board-runtime', () => ({
    resolveCanonicalBoardVerifierSessionKernelAuthorization: (
        session: CanonicalBoardVerifierSession,
        kernel: TranscriptCoreKernel,
    ) => {
        const state = fakeStates.get(kernel);
        if (state?.boardVerifierSession !== session) {
            throw new TypeError('Unexpected canonical-board verifier session.');
        }
        return Object.freeze({
            capabilityByteLength: 32,
            capabilityMemory: state.memory,
            capabilityPointer: 64,
            sessionHandle: 23,
        });
    },
}));

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    applyClosedWorkerGeneratedCommonProofCapability: (
        _proof: ClosedWorkerGeneratedCommonProofCapability,
        _context: TranscriptCoreKernelCommandRuntime,
        apply: (handle: number) => Readonly<{
            consumed: boolean;
            result: number;
        }>,
    ): number => apply(31).result,
    applyClosedWorkerVerifiedCommonProofCapability: (
        _proof: VerifiedCommonProofCapability,
        _context: TranscriptCoreKernelCommandRuntime,
        apply: (handle: number) => Readonly<{
            consumed: boolean;
            result: number;
        }>,
    ): number => apply(32).result,
}));

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeBuilderState = (): FakeBuilderState => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    let nextPointer = 1024;
    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake package-builder allocation had the wrong length.',
            );
        }
        allocations.delete(pointer);
    };
    const kernel = Object.freeze(Object.create(null)) as TranscriptCoreKernel;
    const state: FakeBuilderState = {
        adoptionFailure: undefined,
        allocations,
        authority: Object.freeze(
            {},
        ) as AggregateThresholdShareRecipientAuthority,
        boardVerifierSession: Object.freeze(
            {},
        ) as CanonicalBoardVerifierSession,
        beginCount: 0,
        cancelCount: 0,
        canonicalPackageBytes: Uint8Array.of(0xa1, 0xa2, 0xa3, 0xa4),
        copyCount: 0,
        copyStatuses: [],
        finishCount: 0,
        kernel,
        memory,
        proofSources: [],
        verificationCancelHandles: [],
        verificationSession: Object.freeze(
            {},
        ) as AcceptedSetupVerificationSession,
    };
    const context: TranscriptCoreKernelCommandRuntime = {
        allocate,
        deallocate,
        executeCommand: <Result>(): Result => {
            throw new Error('The fake package builder has no JSON command.');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports: {
            memory,
            sealed_lattice_accepted_setup_package_builder_add_proof_source: (
                _builderHandle: number,
                sourceKind: number,
                capabilityHandle: number,
                statementPointer: number,
                statementByteLength: number,
            ) => {
                state.proofSources.push({
                    capabilityHandle,
                    sourceKind,
                    statement: Uint8Array.from(
                        new Uint8Array(
                            memory.buffer,
                            statementPointer,
                            statementByteLength,
                        ),
                    ),
                });
                return 0;
            },
            sealed_lattice_accepted_setup_package_builder_begin: (
                authorityHandle: number,
                boardVerifierSessionHandle: number,
                boardVerifierSessionCapabilityPointer: number,
                boardVerifierSessionCapabilityByteLength: number,
                statusPointer: number,
            ) => {
                expect(authorityHandle).toBe(17);
                expect(boardVerifierSessionHandle).toBe(23);
                expect(boardVerifierSessionCapabilityPointer).toBe(64);
                expect(boardVerifierSessionCapabilityByteLength).toBe(32);
                state.beginCount += 1;
                writeStatus(memory, statusPointer, 0);
                return 11;
            },
            sealed_lattice_accepted_setup_package_builder_cancel: (
                builderHandle: number,
            ) => {
                expect(builderHandle).toBe(11);
                state.cancelCount += 1;
                return 0;
            },
            sealed_lattice_accepted_setup_package_builder_copy_bytes: (
                builderHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                expect(builderHandle).toBe(11);
                state.copyCount += 1;
                const status = state.copyStatuses.shift() ?? 0;
                if (status === 0) {
                    expect(outputByteLength).toBe(
                        state.canonicalPackageBytes.byteLength,
                    );
                    new Uint8Array(
                        memory.buffer,
                        outputPointer,
                        outputByteLength,
                    ).set(state.canonicalPackageBytes);
                }
                return status;
            },
            sealed_lattice_accepted_setup_package_builder_finish: (
                builderHandle: number,
                statusPointer: number,
            ) => {
                expect(builderHandle).toBe(11);
                state.finishCount += 1;
                writeStatus(memory, statusPointer, 0);
                return state.canonicalPackageBytes.byteLength;
            },
            sealed_lattice_accepted_setup_verification_begin_from_package_builder:
                (builderHandle: number, statusPointer: number) => {
                    expect(builderHandle).toBe(11);
                    writeStatus(memory, statusPointer, 0);
                    return 19;
                },
            sealed_lattice_accepted_setup_verification_cancel: (
                assemblyHandle: number,
            ) => {
                state.verificationCancelHandles.push(assemblyHandle);
                return 0;
            },
        },
    };
    fakeStates.set(kernel, state);
    registerCommonProofKernelContext(kernel, context);
    return state;
};

const expectRefusal = (
    operation: () => unknown,
    refusalReason: RefusalReason,
): void => {
    try {
        operation();
        throw new Error('Expected the package-builder operation to refuse.');
    } catch (error) {
        expect(error).toBeInstanceOf(CanonicalStreamRefusalError);
        expect((error as CanonicalStreamRefusalError).refusalReason).toBe(
            refusalReason,
        );
    }
};

const beginBuilder = (state: FakeBuilderState): AcceptedSetupPackageBuilder =>
    beginAcceptedSetupPackageBuilder({
        boardVerifierSession: state.boardVerifierSession,
        kernel: state.kernel,
        vssRecipientAuthority: state.authority,
    });

describe('Accepted-setup package builder runtime', () => {
    it('retains generated and verified proof capabilities without consuming them', () => {
        const state = createFakeBuilderState();
        const builder = beginBuilder(state);
        builder.addGeneratedProof({
            canonicalApplicationStatement: Uint8Array.of(0x11, 0x12),
            proof: Object.freeze(
                {},
            ) as ClosedWorkerGeneratedCommonProofCapability,
        });
        builder.addVerifiedProof({
            canonicalApplicationStatement: Uint8Array.of(0x21, 0x22, 0x23),
            proof: Object.freeze({}) as VerifiedCommonProofCapability,
        });

        expect(state.proofSources).toEqual([
            {
                capabilityHandle: 31,
                sourceKind: 1,
                statement: Uint8Array.of(0x11, 0x12),
            },
            {
                capabilityHandle: 32,
                sourceKind: 2,
                statement: Uint8Array.of(0x21, 0x22, 0x23),
            },
        ]);
        builder.cancel();
        expect(state.cancelCount).toBe(1);
        expect(state.allocations.size).toBe(0);
    });

    it('retries only the package copy after Rust has finished the inventory', () => {
        const state = createFakeBuilderState();
        const builder = beginBuilder(state);
        state.copyStatuses.push(refusalReasonCodes.wrongHashOrRoot, 0);

        expectRefusal(() => builder.finish(), 'wrongHashOrRoot');
        expect(builder.finish()).toEqual(state.canonicalPackageBytes);
        expect(state.finishCount).toBe(1);
        expect(state.copyCount).toBe(2);
        expectRefusal(
            () =>
                builder.addGeneratedProof({
                    canonicalApplicationStatement: Uint8Array.of(1),
                    proof: Object.freeze(
                        {},
                    ) as ClosedWorkerGeneratedCommonProofCapability,
                }),
            'consumedState',
        );
        expect(state.allocations.size).toBe(0);
        builder.cancel();
    });

    it('consumes the builder only after adopting its positive verification assembly', () => {
        const state = createFakeBuilderState();
        const builder = beginBuilder(state);
        expect(builder.finish()).toEqual(state.canonicalPackageBytes);
        expect(builder.beginVerification()).toBe(state.verificationSession);
        expectRefusal(() => builder.cancel(), 'consumedState');
        expect(state.verificationCancelHandles).toEqual([]);
        expect(state.allocations.size).toBe(0);
    });

    it('retires a Rust-consumed assembly when JavaScript adoption fails', () => {
        const state = createFakeBuilderState();
        const builder = beginBuilder(state);
        builder.finish();
        state.adoptionFailure = new Error('adoption failed');

        expect(() => builder.beginVerification()).toThrow('adoption failed');
        expect(state.verificationCancelHandles).toEqual([19]);
        expectRefusal(() => builder.cancel(), 'consumedState');
        expect(state.allocations.size).toBe(0);
    });
});
