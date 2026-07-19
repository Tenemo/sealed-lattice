import {
    foundationProfile,
    refusalReasonCodes,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { VerifiedTranscriptObject } from '#packages/wasm/src/canonical-board-runtime';
import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    type CanonicalStreamKernelContext,
} from '#packages/wasm/src/canonical-stream-runtime';
import { FoundationBootstrapInternalError } from '#packages/wasm/src/foundation-bootstrap-errors';
import {
    createClosedWorkerProductionOperationAuthority,
    type ClosedWorkerProductionOperationAuthority,
    workerProductionOperationAuthorityRunners,
} from '#packages/wasm/src/local-storage-root-worker-kernel/authorities';
import {
    openBrowserOwnedSetupGenerationAuthorityInClosedWorker,
    selectedSetupGenerationPublicKeyShareBodyByteLength,
    type BrowserOwnedSetupGenerationAuthority,
    type BrowserOwnedSetupGenerationAuthorityInput,
} from '#packages/wasm/src/setup-generation-recipient-payload';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const boundaryMocks = vi.hoisted(() => ({
    resolvePublicRandomnessBoardAuthorization: vi.fn(),
}));

vi.mock('#packages/wasm/src/vss-share-linkage-verification-runtime', () => ({
    resolveAggregatePublicRandomnessBoardAuthorization:
        boundaryMocks.resolvePublicRandomnessBoardAuthorization,
}));

type MockSetupGenerationContext = Readonly<{
    authorityBeginCount(): number;
    cancelledPublicKeyShareSourceCount(): number;
    cancelledSourceCount(): number;
    context: CanonicalStreamKernelContext;
    deallocatedByteLengths(): readonly number[];
    deallocatedRangesWereZeroed(): boolean;
    kernel: TranscriptCoreKernel;
    productionAuthorityBorrowCount(): number;
    productionAuthorityWasRevoked(): boolean;
    releasedAuthorityCount(): number;
    releasedSelectedSuiteCount(): number;
    selectedSuiteCount(): number;
    workerKernel: BrowserActionStorageWorkerKernel;
}>;

type MockSetupGenerationContextInput = Readonly<{
    authorityBeginResults?: readonly Readonly<{
        handle: number;
        status: number;
    }>[];
    authorityReleaseStatuses?: readonly number[];
    allocationFailureOrdinal?: number;
    cancellationStatus?: number;
    privateAuthorityMemory?: WebAssembly.Memory;
    productionOperationCompletionError?: Error;
    reportedPublicKeyShareSourceByteLength?: bigint;
    reportedSourceByteLength?: bigint;
    selectedSuiteReleaseStatuses?: readonly number[];
}>;

const createMockSetupGenerationContext = (
    input?: MockSetupGenerationContextInput,
): MockSetupGenerationContext => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const payload = Uint8Array.of(11, 22, 33, 44, 55, 66);
    const authorityBeginResults = [
        ...(input?.authorityBeginResults ?? [{ handle: 41, status: 0 }]),
    ];
    const authorityReleaseStatuses = [
        ...(input?.authorityReleaseStatuses ?? []),
    ];
    const selectedSuiteReleaseStatuses = [
        ...(input?.selectedSuiteReleaseStatuses ?? []),
    ];
    let nextAllocationPointer = 512;
    let allocationCount = 0;
    let sourceNextOffset = 0;
    let sourceActive = false;
    let publicKeyShareSourceNextOffset = 0;
    let publicKeyShareSourceActive = false;
    let cancelledPublicKeyShareSourceCount = 0;
    let cancelledSourceCount = 0;
    let releasedAuthorityCount = 0;
    let selectedSuiteCount = 0;
    let releasedSelectedSuiteCount = 0;
    let authorityBeginCount = 0;
    let productionAuthorityBorrowCount = 0;
    let lastProductionAuthority:
        | ClosedWorkerProductionOperationAuthority
        | undefined;
    let exclusiveOperationActive = false;
    const zeroedDeallocatedRanges: boolean[] = [];
    const deallocatedByteLengths: number[] = [];

    const writeStatus = (pointer: number, status: number): void => {
        new DataView(memory.buffer).setUint32(pointer, status, true);
    };
    const allocate = (byteLength: number): number => {
        allocationCount += 1;
        if (allocationCount === input?.allocationFailureOrdinal) {
            return 0;
        }
        const pointer = nextAllocationPointer;
        nextAllocationPointer += byteLength + 16;
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        deallocatedByteLengths.push(byteLength);
        zeroedDeallocatedRanges.push(
            new Uint8Array(memory.buffer, pointer, byteLength).every(
                (value) => value === 0,
            ),
        );
    };

    const context = {
        allocate,
        deallocate,
        memory,
        runExclusive<Result>(
            _operationName: string,
            operation: () => Result,
        ): Result {
            if (exclusiveOperationActive) {
                throw new Error('The mock detected a nested kernel operation.');
            }
            exclusiveOperationActive = true;
            try {
                return operation();
            } finally {
                exclusiveOperationActive = false;
            }
        },
        setupGenerationAuthorityBegin(
            selectedSuiteHandle: number,
            boardVerifierSessionHandle: number,
            boardVerifierSessionCapabilityPointer: number,
            boardVerifierSessionCapabilityByteLength: number,
            orderedHandlesPointer: number,
            orderedHandlesByteLength: number,
            actionRandomnessHandle: number,
            stateVerifierSessionHandle: number,
            stateVerifierSessionCapabilityPointer: number,
            stateVerifierSessionCapabilityByteLength: number,
            verifiedReservationHandle: number,
            statusPointer: number,
        ): number {
            authorityBeginCount += 1;
            expect([
                selectedSuiteHandle,
                boardVerifierSessionHandle,
                actionRandomnessHandle,
                stateVerifierSessionHandle,
                verifiedReservationHandle,
            ]).toEqual([7, 8, 9, 10, 11]);
            expect(boardVerifierSessionCapabilityPointer).toBe(32);
            expect(stateVerifierSessionCapabilityPointer).toBe(96);
            expect(boardVerifierSessionCapabilityByteLength).toBe(32);
            expect(stateVerifierSessionCapabilityByteLength).toBe(32);
            expect(orderedHandlesByteLength).toBe(30 * 4);
            const orderedHandlesView = new DataView(
                memory.buffer,
                orderedHandlesPointer,
                orderedHandlesByteLength,
            );
            expect(
                Array.from({ length: 30 }, (_, handleIndex) =>
                    orderedHandlesView.getUint32(handleIndex * 4, true),
                ),
            ).toEqual(
                Array.from({ length: 30 }, (_, handleIndex) => handleIndex + 1),
            );
            const result = authorityBeginResults.shift() ?? {
                handle: 41,
                status: 0,
            };
            writeStatus(statusPointer, result.status);
            return result.handle;
        },
        setupGenerationAuthorityRelease(authorityHandle: number): number {
            expect(authorityHandle).toBe(41);
            releasedAuthorityCount += 1;
            sourceActive = false;
            publicKeyShareSourceActive = false;
            return authorityReleaseStatuses.shift() ?? 0;
        },
        setupGenerationPublicKeyShareBodyByteLength(
            authorityHandle: number,
            statusPointer: number,
        ): bigint {
            expect(authorityHandle).toBe(41);
            writeStatus(statusPointer, 0);
            return BigInt(selectedSetupGenerationPublicKeyShareBodyByteLength);
        },
        setupGenerationPublicKeyShareBodyOpen(
            authorityHandle: number,
            statusPointer: number,
        ): number {
            expect(authorityHandle).toBe(41);
            expect(publicKeyShareSourceActive).toBe(false);
            publicKeyShareSourceActive = true;
            publicKeyShareSourceNextOffset = 0;
            writeStatus(statusPointer, 0);
            return 74;
        },
        setupGenerationPublicKeyShareSourceByteLength(
            sourceHandle: number,
            statusPointer: number,
        ): bigint {
            expect(sourceHandle).toBe(74);
            expect(publicKeyShareSourceActive).toBe(true);
            writeStatus(statusPointer, 0);
            return (
                input?.reportedPublicKeyShareSourceByteLength ??
                BigInt(selectedSetupGenerationPublicKeyShareBodyByteLength)
            );
        },
        setupGenerationPublicKeyShareBodyRead(
            sourceHandle: number,
            expectedOffset: bigint,
            outputPointer: number,
            outputByteLength: number,
        ): number {
            expect(sourceHandle).toBe(74);
            expect(publicKeyShareSourceActive).toBe(true);
            expect(expectedOffset).toBe(BigInt(publicKeyShareSourceNextOffset));
            const output = new Uint8Array(
                memory.buffer,
                outputPointer,
                outputByteLength,
            );
            for (
                let byteIndex = 0;
                byteIndex < output.byteLength;
                byteIndex += 1
            ) {
                output[byteIndex] =
                    (publicKeyShareSourceNextOffset + byteIndex) & 0xff;
            }
            publicKeyShareSourceNextOffset += outputByteLength;
            if (
                publicKeyShareSourceNextOffset ===
                selectedSetupGenerationPublicKeyShareBodyByteLength
            ) {
                publicKeyShareSourceActive = false;
            }
            return 0;
        },
        setupGenerationPublicKeyShareBodyCancel(sourceHandle: number): number {
            expect(sourceHandle).toBe(74);
            cancelledPublicKeyShareSourceCount += 1;
            publicKeyShareSourceActive = false;
            return input?.cancellationStatus ?? 0;
        },
        setupGenerationRecipientVssPayloadByteLength(
            authorityHandle: number,
            recipientRosterPosition: number,
            statusPointer: number,
        ): bigint {
            expect(authorityHandle).toBe(41);
            expect(recipientRosterPosition).toBe(3);
            writeStatus(statusPointer, 0);
            return BigInt(payload.byteLength);
        },
        setupGenerationRecipientVssPayloadOpen(
            authorityHandle: number,
            recipientRosterPosition: number,
            statusPointer: number,
        ): number {
            expect(authorityHandle).toBe(41);
            expect(recipientRosterPosition).toBe(3);
            expect(sourceActive).toBe(false);
            sourceActive = true;
            sourceNextOffset = 0;
            writeStatus(statusPointer, 0);
            return 73;
        },
        setupGenerationRecipientVssPayloadSourceByteLength(
            sourceHandle: number,
            statusPointer: number,
        ): bigint {
            expect(sourceHandle).toBe(73);
            expect(sourceActive).toBe(true);
            writeStatus(statusPointer, 0);
            return (
                input?.reportedSourceByteLength ?? BigInt(payload.byteLength)
            );
        },
        setupGenerationRecipientVssPayloadSourceRecipientRosterPosition(
            sourceHandle: number,
            statusPointer: number,
        ): number {
            expect(sourceHandle).toBe(73);
            expect(sourceActive).toBe(true);
            writeStatus(statusPointer, 0);
            return 3;
        },
        setupGenerationRecipientVssPayloadRead(
            sourceHandle: number,
            expectedOffset: bigint,
            outputPointer: number,
            outputByteLength: number,
        ): number {
            expect(sourceHandle).toBe(73);
            expect(sourceActive).toBe(true);
            expect(expectedOffset).toBe(BigInt(sourceNextOffset));
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).set(
                payload.subarray(
                    sourceNextOffset,
                    sourceNextOffset + outputByteLength,
                ),
            );
            sourceNextOffset += outputByteLength;
            if (sourceNextOffset === payload.byteLength) {
                sourceActive = false;
            }
            return 0;
        },
        setupGenerationRecipientVssPayloadCancel(sourceHandle: number): number {
            expect(sourceHandle).toBe(73);
            cancelledSourceCount += 1;
            sourceActive = false;
            return input?.cancellationStatus ?? 0;
        },
        wasmExports: {
            sealed_lattice_common_proof_copy_selected_suite_record(
                selectedSuiteHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ): number {
                expect(selectedSuiteHandle).toBe(7);
                expect(outputByteLength).toBe(3);
                new Uint8Array(memory.buffer, outputPointer, 3).set([1, 2, 3]);
                return 0;
            },
            sealed_lattice_common_proof_release_suite(
                selectedSuiteHandle: number,
            ): number {
                expect(selectedSuiteHandle).toBe(7);
                releasedSelectedSuiteCount += 1;
                return selectedSuiteReleaseStatuses.shift() ?? 0;
            },
            sealed_lattice_common_proof_select_suite(
                canonicalSuiteRecordPointer: number,
                canonicalSuiteRecordByteLength: number,
                statusPointer: number,
            ): number {
                expect(
                    new Uint8Array(
                        memory.buffer,
                        canonicalSuiteRecordPointer,
                        canonicalSuiteRecordByteLength,
                    ).slice(),
                ).toEqual(Uint8Array.of(1, 2, 3));
                selectedSuiteCount += 1;
                writeStatus(statusPointer, 0);
                return 7;
            },
            sealed_lattice_common_proof_selected_suite_record_byte_length(
                selectedSuiteHandle: number,
                statusPointer: number,
            ): number {
                expect(selectedSuiteHandle).toBe(7);
                writeStatus(statusPointer, 0);
                return 3;
            },
        },
    } as unknown as CanonicalStreamKernelContext &
        TranscriptCoreKernelCommandRuntime;
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    registerCommonProofKernelContext(kernel, context);
    const workerKernel = Object.freeze({}) as BrowserActionStorageWorkerKernel;
    workerProductionOperationAuthorityRunners.set(workerKernel, {
        async withAuthority(_identifiers, operation): Promise<void> {
            productionAuthorityBorrowCount += 1;
            const authorityLease =
                createClosedWorkerProductionOperationAuthority({
                    authorization: Object.freeze({
                        actionRandomnessContext: Object.freeze({
                            memory: input?.privateAuthorityMemory ?? memory,
                        }) as never,
                        actionRandomnessHandle: 9,
                        kernel,
                        stateReservationCapabilityMemory:
                            input?.privateAuthorityMemory ?? memory,
                        stateReservationCapabilityPointer: 96,
                        stateReservationHandle: 11,
                        stateVerifierSessionHandle: 10,
                    }),
                });
            lastProductionAuthority = authorityLease.authority;
            try {
                const output = await operation(authorityLease.authority);
                expect(output).toBeUndefined();
                if (input?.productionOperationCompletionError !== undefined) {
                    throw input.productionOperationCompletionError;
                }
            } finally {
                authorityLease.revoke();
            }
        },
    });

    return Object.freeze({
        authorityBeginCount: () => authorityBeginCount,
        cancelledPublicKeyShareSourceCount: () =>
            cancelledPublicKeyShareSourceCount,
        cancelledSourceCount: () => cancelledSourceCount,
        context,
        deallocatedByteLengths: () =>
            Object.freeze([...deallocatedByteLengths]),
        deallocatedRangesWereZeroed: () =>
            zeroedDeallocatedRanges.length > 0 &&
            zeroedDeallocatedRanges.every(Boolean),
        kernel,
        productionAuthorityBorrowCount: () => productionAuthorityBorrowCount,
        productionAuthorityWasRevoked: () => {
            if (lastProductionAuthority === undefined) {
                return false;
            }
            try {
                const output =
                    lastProductionAuthority.withExactKernelAuthorization(
                        () => undefined,
                    );
                expect(output).toBeUndefined();
                return false;
            } catch {
                return true;
            }
        },
        releasedAuthorityCount: () => releasedAuthorityCount,
        releasedSelectedSuiteCount: () => releasedSelectedSuiteCount,
        selectedSuiteCount: () => selectedSuiteCount,
        workerKernel,
    });
};

const verifiedTranscriptObjects = (): readonly VerifiedTranscriptObject[] =>
    Object.freeze(
        Array.from({ length: foundationProfile.participantCount }, () =>
            Object.freeze({}),
        ) as unknown as readonly VerifiedTranscriptObject[],
    );

const completeAuthorityInput = (
    mock: MockSetupGenerationContext,
): BrowserOwnedSetupGenerationAuthorityInput =>
    Object.freeze({
        canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
        kernel: mock.kernel,
        orderedPublicRandomnessCommitmentObjects: verifiedTranscriptObjects(),
        orderedPublicRandomnessRevealObjects: verifiedTranscriptObjects(),
        orderedSetupIntentObjects: verifiedTranscriptObjects(),
        productionOperationIdentifiers: Object.freeze({
            actionRandomnessSessionIdentifier: 'action-randomness',
            stateReservationIdentifier: 'state-reservation',
            stateVerifierSessionIdentifier: 'state-verifier',
        }),
        workerKernel: mock.workerKernel,
    });

const openAuthority = (
    mock: MockSetupGenerationContext,
): Promise<BrowserOwnedSetupGenerationAuthority> =>
    openBrowserOwnedSetupGenerationAuthorityInClosedWorker(
        completeAuthorityInput(mock),
    );

beforeEach(() => {
    boundaryMocks.resolvePublicRandomnessBoardAuthorization.mockReset();
    boundaryMocks.resolvePublicRandomnessBoardAuthorization.mockImplementation(
        () => {
            const handleBytes = new Uint8Array(
                foundationProfile.participantCount * 3 * 4,
            );
            const handleView = new DataView(handleBytes.buffer);
            for (
                let handleIndex = 0;
                handleIndex < foundationProfile.participantCount * 3;
                handleIndex += 1
            ) {
                handleView.setUint32(handleIndex * 4, handleIndex + 1, true);
            }
            return Object.freeze({
                capabilityPointer: 32,
                handleBytes,
                sessionHandle: 8,
            });
        },
    );
});

describe('Setup-generation recipient payload custody', () => {
    it('opens from exact same-worker authorities and releases temporary suite custody before use', async () => {
        const mock = createMockSetupGenerationContext();
        const authority = await openAuthority(mock);

        expect(mock.authorityBeginCount()).toBe(1);
        expect(mock.productionAuthorityBorrowCount()).toBe(1);
        expect(mock.productionAuthorityWasRevoked()).toBe(true);
        expect(mock.selectedSuiteCount()).toBe(1);
        expect(mock.releasedSelectedSuiteCount()).toBe(1);
        expect(authority.payloadByteLength(3)).toBe(6);
        const source = authority.openRecipientPayload(3);
        expect(source.byteLength).toBe(6);
        expect(source.recipientRosterPosition).toBe(3);
        expect(() =>
            source.read({ expectedOffset: 1, requestedByteLength: 2 }),
        ).toThrowError(CanonicalStreamRefusalError);
        expect(
            source.read({ expectedOffset: 0, requestedByteLength: 2 }),
        ).toEqual(Uint8Array.of(11, 22));
        expect(
            source.read({ expectedOffset: 2, requestedByteLength: 4 }),
        ).toEqual(Uint8Array.of(33, 44, 55, 66));
        expect(() =>
            source.read({ expectedOffset: 6, requestedByteLength: 1 }),
        ).toThrowError(CanonicalStreamInternalError);

        authority.release();
        expect(mock.releasedAuthorityCount()).toBe(1);
        expect(mock.cancelledSourceCount()).toBe(0);
        expect(mock.deallocatedRangesWereZeroed()).toBe(true);
    });

    it('streams the exact full-Q public-key-share body with monotonic offsets', async () => {
        const mock = createMockSetupGenerationContext();
        const authority = await openAuthority(mock);

        expect(authority.publicKeyShareBodyByteLength()).toBe(13_631_488);
        const source = authority.openPublicKeyShareBody();
        expect(source.byteLength).toBe(13_631_488);
        expect(() =>
            source.read({ expectedOffset: 1, requestedByteLength: 7 }),
        ).toThrowError(CanonicalStreamRefusalError);
        expect(() =>
            source.read({
                expectedOffset: 0,
                requestedByteLength:
                    foundationProfile.streamChunkByteLength + 1,
            }),
        ).toThrowError(CanonicalStreamRefusalError);
        expect(
            source.read({ expectedOffset: 0, requestedByteLength: 7 }),
        ).toEqual(Uint8Array.of(0, 1, 2, 3, 4, 5, 6));
        expect(() =>
            source.read({ expectedOffset: 0, requestedByteLength: 1 }),
        ).toThrowError(CanonicalStreamRefusalError);
        expect(
            source.read({ expectedOffset: 7, requestedByteLength: 5 }),
        ).toEqual(Uint8Array.of(7, 8, 9, 10, 11));

        source.cancel();
        expect(mock.cancelledPublicKeyShareSourceCount()).toBe(1);
        expect(() =>
            source.read({ expectedOffset: 12, requestedByteLength: 1 }),
        ).toThrowError(CanonicalStreamInternalError);
        authority.release();
    });

    it('cancels a public-key-share source whose Rust length is not the exact selected body', async () => {
        const mock = createMockSetupGenerationContext({
            reportedPublicKeyShareSourceByteLength: 13_631_480n,
        });
        const authority = await openAuthority(mock);

        expect(() => authority.openPublicKeyShareBody()).toThrowError(
            CanonicalStreamInternalError,
        );
        expect(mock.cancelledPublicKeyShareSourceCount()).toBe(1);
        authority.release();
    });

    it('invalidates every open child source when its authority is released', async () => {
        const mock = createMockSetupGenerationContext();
        const authority = await openAuthority(mock);
        const source = authority.openRecipientPayload(3);
        const publicKeyShareSource = authority.openPublicKeyShareBody();

        authority.release();

        expect(() => source.cancel()).toThrowError(
            CanonicalStreamInternalError,
        );
        expect(() => publicKeyShareSource.cancel()).toThrowError(
            CanonicalStreamInternalError,
        );
        expect(() => authority.payloadByteLength(3)).toThrowError(
            CanonicalStreamInternalError,
        );
        expect(mock.releasedAuthorityCount()).toBe(1);
    });

    it('cancels a newly opened source whose Rust-reported binding disagrees', async () => {
        const mock = createMockSetupGenerationContext({
            reportedSourceByteLength: 5n,
        });
        const authority = await openAuthority(mock);

        expect(() => authority.openRecipientPayload(3)).toThrowError(
            CanonicalStreamInternalError,
        );
        expect(mock.cancelledSourceCount()).toBe(1);

        authority.release();
    });

    it('reports both a binding failure and a failed source cleanup', async () => {
        const mock = createMockSetupGenerationContext({
            cancellationStatus: 0xffff_ffff,
            reportedSourceByteLength: 5n,
        });
        const authority = await openAuthority(mock);

        expect(() => authority.openRecipientPayload(3)).toThrowError(
            CanonicalStreamCleanupError,
        );
        expect(mock.cancelledSourceCount()).toBe(1);

        authority.release();
    });

    it('rejects an incomplete public-randomness family before borrowing worker or suite custody', async () => {
        const mock = createMockSetupGenerationContext();
        const completeInput = completeAuthorityInput(mock);

        await expect(
            openBrowserOwnedSetupGenerationAuthorityInClosedWorker({
                ...completeInput,
                orderedPublicRandomnessRevealObjects:
                    completeInput.orderedPublicRandomnessRevealObjects.slice(1),
            }),
        ).rejects.toBeInstanceOf(CanonicalStreamRefusalError);
        expect(
            boundaryMocks.resolvePublicRandomnessBoardAuthorization,
        ).not.toHaveBeenCalled();
        expect(mock.productionAuthorityBorrowCount()).toBe(0);
        expect(mock.selectedSuiteCount()).toBe(0);
        expect(mock.releasedAuthorityCount()).toBe(0);
    });

    it('zeroes allocated begin input and releases suite custody when status allocation fails', async () => {
        const mock = createMockSetupGenerationContext({
            allocationFailureOrdinal: 4,
        });

        await expect(openAuthority(mock)).rejects.toBeInstanceOf(
            CanonicalStreamInternalError,
        );
        expect(mock.authorityBeginCount()).toBe(0);
        expect(mock.productionAuthorityWasRevoked()).toBe(true);
        expect(mock.releasedAuthorityCount()).toBe(0);
        expect(mock.releasedSelectedSuiteCount()).toBe(1);
        expect(mock.deallocatedByteLengths()).toContain(30 * 4);
        expect(mock.deallocatedRangesWereZeroed()).toBe(true);
    });

    it('rejects cross-worker private authority and releases temporary suite custody', async () => {
        const mock = createMockSetupGenerationContext({
            privateAuthorityMemory: new WebAssembly.Memory({ initial: 1 }),
        });

        await expect(openAuthority(mock)).rejects.toBeInstanceOf(
            CanonicalStreamInternalError,
        );
        expect(mock.authorityBeginCount()).toBe(0);
        expect(mock.productionAuthorityWasRevoked()).toBe(true);
        expect(mock.releasedAuthorityCount()).toBe(0);
        expect(mock.releasedSelectedSuiteCount()).toBe(1);
    });

    it('releases selected-suite custody after begin refusal and permits an exact retry', async () => {
        const mock = createMockSetupGenerationContext({
            authorityBeginResults: [
                {
                    handle: 0,
                    status: refusalReasonCodes.wrongTypeOrLength,
                },
                { handle: 41, status: 0 },
            ],
        });

        await expect(openAuthority(mock)).rejects.toBeInstanceOf(
            CanonicalStreamRefusalError,
        );
        expect(mock.releasedSelectedSuiteCount()).toBe(1);
        expect(mock.releasedAuthorityCount()).toBe(0);

        const retriedAuthority = await openAuthority(mock);
        expect(mock.authorityBeginCount()).toBe(2);
        expect(mock.selectedSuiteCount()).toBe(2);
        expect(mock.releasedSelectedSuiteCount()).toBe(2);
        retriedAuthority.release();
        expect(mock.releasedAuthorityCount()).toBe(1);
    });

    it('releases a malformed nonzero begin handle before surfacing refusal', async () => {
        const mock = createMockSetupGenerationContext({
            authorityBeginResults: [
                {
                    handle: 41,
                    status: refusalReasonCodes.wrongTypeOrLength,
                },
            ],
        });

        await expect(openAuthority(mock)).rejects.toBeInstanceOf(
            CanonicalStreamRefusalError,
        );
        expect(mock.releasedAuthorityCount()).toBe(1);
        expect(mock.releasedSelectedSuiteCount()).toBe(1);
    });

    it('retries failed begin cleanup without losing the original refusal', async () => {
        const mock = createMockSetupGenerationContext({
            authorityBeginResults: [
                {
                    handle: 41,
                    status: refusalReasonCodes.wrongTypeOrLength,
                },
            ],
            authorityReleaseStatuses: [0xffff_ffff],
        });

        await expect(openAuthority(mock)).rejects.toBeInstanceOf(
            CanonicalStreamCleanupError,
        );
        expect(mock.releasedAuthorityCount()).toBe(2);
        expect(mock.releasedSelectedSuiteCount()).toBe(1);
    });

    it('retries selected-suite release and discards the retained authority before refusing', async () => {
        const mock = createMockSetupGenerationContext({
            selectedSuiteReleaseStatuses: [0xffff_ffff, 0],
        });

        const failure = await openAuthority(mock).catch(
            (error: unknown) => error,
        );
        expect(mock.releasedAuthorityCount()).toBe(1);
        expect(mock.releasedSelectedSuiteCount()).toBe(2);
        expect(failure).toBeInstanceOf(FoundationBootstrapInternalError);
    });

    it('retries authority cleanup when the worker rejects after successful begin', async () => {
        const mock = createMockSetupGenerationContext({
            authorityReleaseStatuses: [0xffff_ffff, 0],
            productionOperationCompletionError: new Error(
                'Synthetic post-begin worker refusal.',
            ),
        });

        await expect(openAuthority(mock)).rejects.toBeInstanceOf(
            CanonicalStreamCleanupError,
        );
        expect(mock.releasedAuthorityCount()).toBe(2);
        expect(mock.releasedSelectedSuiteCount()).toBe(1);
    });
});
