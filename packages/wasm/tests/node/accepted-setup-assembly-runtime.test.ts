import { refusalReasonCodes } from '@sealed-lattice/types';
import { describe, expect, it, vi } from 'vitest';

import {
    beginAcceptedSetupEvaluatorSourceCatalog,
    beginAcceptedSetupVerification,
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner,
    requireAcceptedSetupVerificationAssemblyKernelOwner,
} from '#packages/wasm/src/accepted-setup-assembly-runtime';
import type { AggregateThresholdShareRecipientAuthority } from '#packages/wasm/src/aggregate-threshold-share-authenticated-recipient';
import {
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
} from '#packages/wasm/src/canonical-stream-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const aggregateAuthorityOwners = vi.hoisted(
    () =>
        new WeakMap<
            object,
            Readonly<{ handle: number; kernel: TranscriptCoreKernel }>
        >(),
);
const markAggregateAuthorityConsumed = vi.hoisted(() => vi.fn());

vi.mock(
    '#packages/wasm/src/aggregate-threshold-share-authenticated-recipient',
    () => ({
        markAggregateThresholdShareRecipientAuthorityConsumedAfterKernelSuccess:
            markAggregateAuthorityConsumed,
        requireAggregateThresholdShareRecipientAuthorityKernelOwner: (
            authority: object,
            kernel: TranscriptCoreKernel,
        ) => {
            const owner = aggregateAuthorityOwners.get(authority);
            if (owner === undefined) {
                throw new CanonicalStreamRefusalError('consumedState');
            }
            if (owner.kernel !== kernel) {
                throw new TypeError(
                    'The aggregate recipient authority belongs to another WASM kernel.',
                );
            }
            return Object.freeze(owner);
        },
    }),
);

const maximumWasm32UnsignedInteger = 0xffff_ffff;

type FakeAcceptedSetupRuntime = Readonly<{
    acceptedSetupCancellationHandles: number[];
    allocations: ReadonlyMap<number, number>;
    catalogCancellationHandles: number[];
    catalogCompletionHandles: number[];
    createAggregateAuthority(
        handle: number,
    ): AggregateThresholdShareRecipientAuthority;
    kernel: TranscriptCoreKernel;
    transferCalls: Array<
        Readonly<{ acceptedSetupHandle: number; catalogHandle: number }>
    >;
}>;

const createFakeAcceptedSetupRuntime = (
    options: Readonly<{
        acceptedSetupHandle?: number;
        catalogCancellationStatuses?: readonly number[];
        catalogCompletionStatuses?: readonly number[];
        catalogHandle?: number;
        transferStatuses?: readonly number[];
    }> = {},
): FakeAcceptedSetupRuntime => {
    const memory = new WebAssembly.Memory({ initial: 1 });
    const allocations = new Map<number, number>();
    const acceptedSetupCancellationHandles: number[] = [];
    const catalogCancellationHandles: number[] = [];
    const catalogCompletionHandles: number[] = [];
    const transferCalls: Array<
        Readonly<{ acceptedSetupHandle: number; catalogHandle: number }>
    > = [];
    const catalogCancellationStatuses = [
        ...(options.catalogCancellationStatuses ?? [0]),
    ];
    const catalogCompletionStatuses = [
        ...(options.catalogCompletionStatuses ?? [0]),
    ];
    const transferStatuses = [...(options.transferStatuses ?? [0])];
    let nextPointer = 8;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        if (nextPointer > memory.buffer.byteLength) {
            memory.grow(
                Math.ceil((nextPointer - memory.buffer.byteLength) / 65_536),
            );
        }
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake accepted-setup allocation was released with the wrong byte length.',
            );
        }
        allocations.delete(pointer);
    };
    const writeStatus = (pointer: number, status: number): void => {
        new DataView(memory.buffer).setUint32(pointer, status, true);
    };

    const kernel = Object.freeze(Object.create(null)) as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error('The test does not use the JSON command boundary.');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports: {
            sealed_lattice_accepted_setup_authority_release: () => 0,
            sealed_lattice_accepted_setup_verification_begin: (
                _aggregateAuthorityHandle: number,
                _canonicalPackagePointer: number,
                _canonicalPackageByteLength: number,
                statusPointer: number,
            ) => {
                writeStatus(statusPointer, 0);
                return options.acceptedSetupHandle ?? 31;
            },
            sealed_lattice_accepted_setup_verification_cancel: (
                acceptedSetupHandle: number,
            ) => {
                acceptedSetupCancellationHandles.push(acceptedSetupHandle);
                return 0;
            },
            sealed_lattice_accepted_setup_verification_complete_evaluator_sources:
                () => 0,
            sealed_lattice_accepted_setup_verification_complete_public_proofs:
                () => 0,
            sealed_lattice_accepted_setup_verification_finalize: () => 0,
            sealed_lattice_accepted_setup_verification_transfer_prepackage_evaluator_sources:
                (acceptedSetupHandle: number, catalogHandle: number) => {
                    transferCalls.push({ acceptedSetupHandle, catalogHandle });
                    return transferStatuses.shift() ?? 0;
                },
            sealed_lattice_prepackage_evaluator_source_catalog_begin: (
                _aggregateAuthorityHandle: number,
                statusPointer: number,
            ) => {
                writeStatus(statusPointer, 0);
                return options.catalogHandle ?? 21;
            },
            sealed_lattice_prepackage_evaluator_source_catalog_cancel: (
                catalogHandle: number,
            ) => {
                catalogCancellationHandles.push(catalogHandle);
                return catalogCancellationStatuses.shift() ?? 0;
            },
            sealed_lattice_prepackage_evaluator_source_catalog_complete: (
                catalogHandle: number,
            ) => {
                catalogCompletionHandles.push(catalogHandle);
                return catalogCompletionStatuses.shift() ?? 0;
            },
        },
    } as unknown as TranscriptCoreKernelCommandRuntime;
    registerCommonProofKernelContext(kernel, context);

    return Object.freeze({
        acceptedSetupCancellationHandles,
        allocations,
        catalogCancellationHandles,
        catalogCompletionHandles,
        createAggregateAuthority: (handle) => {
            const authority = Object.freeze({
                release: vi.fn(),
            }) as unknown as AggregateThresholdShareRecipientAuthority;
            aggregateAuthorityOwners.set(authority, { handle, kernel });
            return authority;
        },
        kernel,
        transferCalls,
    });
};

const beginAcceptedSetup = (
    runtime: FakeAcceptedSetupRuntime,
    aggregateAuthority: AggregateThresholdShareRecipientAuthority,
) =>
    beginAcceptedSetupVerification({
        canonicalPackageBytes: Uint8Array.of(0xa1, 0xb2),
        kernel: runtime.kernel,
        vssRecipientAuthority: aggregateAuthority,
    });

describe('Accepted-setup evaluator-source catalog runtime', () => {
    it('transfers one complete catalog into the exact live accepted-setup assembly', () => {
        const runtime = createFakeAcceptedSetupRuntime();
        const aggregateAuthority = runtime.createAggregateAuthority(11);
        const catalog = beginAcceptedSetupEvaluatorSourceCatalog({
            kernel: runtime.kernel,
            vssRecipientAuthority: aggregateAuthority,
        });
        const acceptedSetup = beginAcceptedSetup(runtime, aggregateAuthority);

        catalog.complete();
        catalog.transferTo(acceptedSetup);

        expect(runtime.catalogCompletionHandles).toEqual([21]);
        expect(runtime.transferCalls).toEqual([
            { acceptedSetupHandle: 31, catalogHandle: 21 },
        ]);
        expect(() => catalog.cancel()).toThrow('already consumed');
        expect(() =>
            requireAcceptedSetupVerificationAssemblyKernelOwner(
                acceptedSetup,
                runtime.kernel,
                'collecting',
            ),
        ).not.toThrow();

        acceptedSetup.completeEvaluatorSources();
        acceptedSetup.cancel();

        expect(runtime.acceptedSetupCancellationHandles).toEqual([31]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('keeps both owners live and retryable when Rust refuses an atomic transfer', () => {
        const runtime = createFakeAcceptedSetupRuntime({
            transferStatuses: [refusalReasonCodes.wrongContext, 0],
        });
        const aggregateAuthority = runtime.createAggregateAuthority(12);
        const catalog = beginAcceptedSetupEvaluatorSourceCatalog({
            kernel: runtime.kernel,
            vssRecipientAuthority: aggregateAuthority,
        });
        const acceptedSetup = beginAcceptedSetup(runtime, aggregateAuthority);
        catalog.complete();

        expect(() => catalog.transferTo(acceptedSetup)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(() =>
            requireAcceptedSetupVerificationAssemblyKernelOwner(
                acceptedSetup,
                runtime.kernel,
                'collecting',
            ),
        ).not.toThrow();

        catalog.transferTo(acceptedSetup);
        acceptedSetup.cancel();

        expect(runtime.transferCalls).toHaveLength(2);
        expect(runtime.catalogCancellationHandles).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('keeps completion and cancellation retryable after a Rust refusal', () => {
        const runtime = createFakeAcceptedSetupRuntime({
            catalogCancellationStatuses: [refusalReasonCodes.wrongContext, 0],
            catalogCompletionStatuses: [
                refusalReasonCodes.missingPrerequisite,
                0,
            ],
        });
        const catalog = beginAcceptedSetupEvaluatorSourceCatalog({
            kernel: runtime.kernel,
            vssRecipientAuthority: runtime.createAggregateAuthority(13),
        });

        expect(() => catalog.complete()).toThrow(CanonicalStreamRefusalError);
        expect(
            requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
                catalog,
                runtime.kernel,
            ),
        ).toEqual({ handle: 21, kernel: runtime.kernel });
        catalog.complete();

        expect(() => catalog.cancel()).toThrow(CanonicalStreamRefusalError);
        expect(() => catalog.cancel()).not.toThrow();
        expect(() => catalog.cancel()).toThrow('already consumed');
        expect(runtime.catalogCompletionHandles).toEqual([21, 21]);
        expect(runtime.catalogCancellationHandles).toEqual([21, 21]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('requires the exact kernel and VSS authority object before transfer', () => {
        const firstRuntime = createFakeAcceptedSetupRuntime();
        const secondRuntime = createFakeAcceptedSetupRuntime();
        const firstAuthority = firstRuntime.createAggregateAuthority(14);
        const secondAuthority = firstRuntime.createAggregateAuthority(15);
        const catalog = beginAcceptedSetupEvaluatorSourceCatalog({
            kernel: firstRuntime.kernel,
            vssRecipientAuthority: firstAuthority,
        });
        catalog.complete();
        const wrongAuthoritySetup = beginAcceptedSetup(
            firstRuntime,
            secondAuthority,
        );
        const wrongKernelSetup = beginAcceptedSetup(
            secondRuntime,
            secondRuntime.createAggregateAuthority(16),
        );

        expect(() => catalog.transferTo(wrongAuthoritySetup)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(() => catalog.transferTo(wrongKernelSetup)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(firstRuntime.transferCalls).toEqual([]);
        expect(secondRuntime.transferCalls).toEqual([]);

        catalog.cancel();
        wrongAuthoritySetup.cancel();
        wrongKernelSetup.cancel();
        expect(firstRuntime.allocations.size).toBe(0);
        expect(secondRuntime.allocations.size).toBe(0);
    });

    it('retires invalid nonzero handles returned with a successful status', () => {
        const invalidHandle = maximumWasm32UnsignedInteger + 1;
        const catalogRuntime = createFakeAcceptedSetupRuntime({
            catalogHandle: invalidHandle,
        });
        const catalogAuthority = catalogRuntime.createAggregateAuthority(17);

        expect(() =>
            beginAcceptedSetupEvaluatorSourceCatalog({
                kernel: catalogRuntime.kernel,
                vssRecipientAuthority: catalogAuthority,
            }),
        ).toThrow(CanonicalStreamInternalError);
        expect(catalogRuntime.catalogCancellationHandles).toEqual([
            invalidHandle,
        ]);
        expect(catalogRuntime.allocations.size).toBe(0);

        const acceptedSetupRuntime = createFakeAcceptedSetupRuntime({
            acceptedSetupHandle: invalidHandle,
        });
        expect(() =>
            beginAcceptedSetup(
                acceptedSetupRuntime,
                acceptedSetupRuntime.createAggregateAuthority(18),
            ),
        ).toThrow(CanonicalStreamInternalError);
        expect(acceptedSetupRuntime.acceptedSetupCancellationHandles).toEqual([
            invalidHandle,
        ]);
        expect(acceptedSetupRuntime.allocations.size).toBe(0);
    });
});
