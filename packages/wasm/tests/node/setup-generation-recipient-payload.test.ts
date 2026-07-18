import { describe, expect, it } from 'vitest';

import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    type CanonicalStreamKernelContext,
} from '#packages/wasm/src/canonical-stream-runtime';
import { beginBrowserOwnedSetupGenerationAuthority } from '#packages/wasm/src/setup-generation-recipient-payload';

type MockSetupGenerationContext = Readonly<{
    cancelledSourceCount(): number;
    context: CanonicalStreamKernelContext;
    deallocatedRangesWereZeroed(): boolean;
    releasedAuthorityCount(): number;
}>;

const createMockSetupGenerationContext = (input?: {
    readonly cancellationStatus?: number;
    readonly reportedSourceByteLength?: bigint;
}): MockSetupGenerationContext => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const payload = Uint8Array.of(11, 22, 33, 44, 55, 66);
    let nextAllocationPointer = 512;
    let sourceNextOffset = 0;
    let sourceActive = false;
    let cancelledSourceCount = 0;
    let releasedAuthorityCount = 0;
    let exclusiveOperationActive = false;
    const zeroedDeallocatedRanges: boolean[] = [];

    const writeStatus = (pointer: number, status: number): void => {
        new DataView(memory.buffer).setUint32(pointer, status, true);
    };
    const allocate = (byteLength: number): number => {
        const pointer = nextAllocationPointer;
        nextAllocationPointer += byteLength + 16;
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
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
            writeStatus(statusPointer, 0);
            return 41;
        },
        setupGenerationAuthorityRelease(authorityHandle: number): number {
            expect(authorityHandle).toBe(41);
            releasedAuthorityCount += 1;
            sourceActive = false;
            return 0;
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
    } as unknown as CanonicalStreamKernelContext;

    return Object.freeze({
        cancelledSourceCount: () => cancelledSourceCount,
        context,
        deallocatedRangesWereZeroed: () =>
            zeroedDeallocatedRanges.length > 0 &&
            zeroedDeallocatedRanges.every(Boolean),
        releasedAuthorityCount: () => releasedAuthorityCount,
    });
};

const beginAuthority = (context: CanonicalStreamKernelContext) =>
    beginBrowserOwnedSetupGenerationAuthority({
        actionRandomnessHandle: 9,
        boardVerifierSessionCapabilityPointer: 32,
        boardVerifierSessionHandle: 8,
        context,
        orderedPublicRandomnessObjectHandles: Array.from(
            { length: 30 },
            (_, handleIndex) => handleIndex + 1,
        ),
        selectedSuiteHandle: 7,
        stateVerifierSessionCapabilityPointer: 96,
        stateVerifierSessionHandle: 10,
        verifiedReservationHandle: 11,
    });

describe('Setup-generation recipient payload custody', () => {
    it('reads exact sequential chunks and removes the source after the final byte', () => {
        const mock = createMockSetupGenerationContext();
        const authority = beginAuthority(mock.context);

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

    it('invalidates every open child source when its authority is released', () => {
        const mock = createMockSetupGenerationContext();
        const authority = beginAuthority(mock.context);
        const source = authority.openRecipientPayload(3);

        authority.release();

        expect(() => source.cancel()).toThrowError(
            CanonicalStreamInternalError,
        );
        expect(() => authority.payloadByteLength(3)).toThrowError(
            CanonicalStreamInternalError,
        );
        expect(mock.releasedAuthorityCount()).toBe(1);
    });

    it('cancels a newly opened source whose Rust-reported binding disagrees', () => {
        const mock = createMockSetupGenerationContext({
            reportedSourceByteLength: 5n,
        });
        const authority = beginAuthority(mock.context);

        expect(() => authority.openRecipientPayload(3)).toThrowError(
            CanonicalStreamInternalError,
        );
        expect(mock.cancelledSourceCount()).toBe(1);

        authority.release();
    });

    it('reports both a binding failure and a failed source cleanup', () => {
        const mock = createMockSetupGenerationContext({
            cancellationStatus: 0xffff_ffff,
            reportedSourceByteLength: 5n,
        });
        const authority = beginAuthority(mock.context);

        expect(() => authority.openRecipientPayload(3)).toThrowError(
            CanonicalStreamCleanupError,
        );
        expect(mock.cancelledSourceCount()).toBe(1);

        authority.release();
    });

    it('rejects incomplete public-randomness handle families before calling WASM', () => {
        const mock = createMockSetupGenerationContext();

        expect(() =>
            beginBrowserOwnedSetupGenerationAuthority({
                actionRandomnessHandle: 9,
                boardVerifierSessionCapabilityPointer: 32,
                boardVerifierSessionHandle: 8,
                context: mock.context,
                orderedPublicRandomnessObjectHandles: Array.from(
                    { length: 29 },
                    (_, handleIndex) => handleIndex + 1,
                ),
                selectedSuiteHandle: 7,
                stateVerifierSessionCapabilityPointer: 96,
                stateVerifierSessionHandle: 10,
                verifiedReservationHandle: 11,
            }),
        ).toThrowError(CanonicalStreamRefusalError);
        expect(mock.releasedAuthorityCount()).toBe(0);
    });
});
