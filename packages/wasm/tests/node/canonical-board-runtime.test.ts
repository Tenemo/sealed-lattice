import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    foundationObjectTypes,
    openCanonicalBoardVerifierSession,
    registerCanonicalBoardKernelContext,
    resolveVerifiedTranscriptObjectKernelAuthorization,
    type CanonicalBoardKernelContext,
    type CanonicalBoardVerifierConfiguration,
} from '../../src/canonical-board-runtime.js';
import type { TranscriptCoreKernel } from '../../src/transcript-core-bridge/kernel-types.js';

const configuration = (): CanonicalBoardVerifierConfiguration => ({
    actionContextHash: new Uint8Array(64).fill(0x33),
    canonicalRosterBytes: Uint8Array.of(0xaa, 0xbb),
    ceremonyContextHash: new Uint8Array(64).fill(0x22),
    maximumBallotAttemptsPerParticipant: 4,
    maximumRetainedCanonicalCarrierByteLength: 1_048_576,
    maximumRetainedTranscriptObjects: 32,
    maximumUnorderedCarriersPerBatch: 8,
    suiteIdentifier: new Uint8Array(64).fill(0x11),
});

const requireValid = <Value>(result: {
    readonly isValid: boolean;
    readonly refusalReason?: string;
    readonly value?: Value;
}): Value => {
    if (!result.isValid) {
        throw new Error(result.refusalReason ?? 'verification refused');
    }
    return result.value as Value;
};

type FakeKernel = Readonly<{
    allocations: ReadonlyMap<number, number>;
    cancelledHandles: readonly number[];
    context: CanonicalBoardKernelContext;
    framedCarrierInputs: readonly Uint8Array[];
    kernel: TranscriptCoreKernel;
}>;

const createFakeKernel = (verifyStatus = 0): FakeKernel => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const cancelledHandles: number[] = [];
    const framedCarrierInputs: Uint8Array[] = [];
    let nextPointer = 8;
    const ensureCapacity = (requiredByteLength: number): void => {
        const missingByteLength = requiredByteLength - memory.buffer.byteLength;
        if (missingByteLength > 0) {
            memory.grow(Math.ceil(missingByteLength / 65_536));
        }
    };
    const context: CanonicalBoardKernelContext = {
        allocate: (byteLength) => {
            const pointer = nextPointer;
            nextPointer += byteLength;
            ensureCapacity(nextPointer);
            allocations.set(pointer, byteLength);
            return pointer;
        },
        begin: (
            _configurationPointer,
            _configurationLength,
            _capabilityPointer,
            _capabilityLength,
            statusPointer,
        ) => {
            new DataView(memory.buffer).setUint32(statusPointer, 0, true);
            return 1;
        },
        cachedCarrierLength: (
            _sessionHandle,
            _capabilityPointer,
            _capabilityLength,
            _verifiedObjectHandle,
            statusPointer,
        ) => {
            new DataView(memory.buffer).setUint32(statusPointer, 0, true);
            return 3;
        },
        cancel: (sessionHandle) => {
            cancelledHandles.push(sessionHandle);
            return 0;
        },
        copyCachedCarrier: (
            _sessionHandle,
            _capabilityPointer,
            _capabilityLength,
            _verifiedObjectHandle,
            outputPointer,
            outputLength,
        ) => {
            if (outputLength !== 3) {
                return 5;
            }
            new Uint8Array(memory.buffer).set(
                [0x91, 0x92, 0x93],
                outputPointer,
            );
            return 0;
        },
        deallocate: (pointer, byteLength) => {
            if (allocations.get(pointer) !== byteLength) {
                throw new Error(
                    'test deallocation does not match its allocation',
                );
            }
            allocations.delete(pointer);
        },
        describe: (
            _sessionHandle,
            _capabilityPointer,
            _capabilityLength,
            _verifiedObjectHandle,
            outputPointer,
            outputLength,
        ) => {
            if (outputLength !== 68) {
                return 5;
            }
            const view = new DataView(memory.buffer);
            view.setUint16(outputPointer, 1, true);
            view.setUint16(
                outputPointer + 2,
                foundationObjectTypes.setupIntent,
                true,
            );
            new Uint8Array(memory.buffer).fill(
                0x44,
                outputPointer + 4,
                outputPointer + 68,
            );
            return 0;
        },
        memory,
        release: () => 0,
        runExclusive: (_operationName, operation) => operation(),
        verifyUnordered: (
            _sessionHandle,
            _capabilityPointer,
            _capabilityLength,
            framedCarrierPointer,
            framedCarrierLength,
            outputPointer,
            _outputLength,
            statusPointer,
        ) => {
            framedCarrierInputs.push(
                new Uint8Array(
                    memory.buffer,
                    framedCarrierPointer,
                    framedCarrierLength,
                ).slice(),
            );
            new DataView(memory.buffer).setUint32(
                statusPointer,
                verifyStatus,
                true,
            );
            if (verifyStatus !== 0) {
                return 0;
            }
            const view = new DataView(memory.buffer);
            view.setUint32(outputPointer, 1, true);
            view.setUint32(outputPointer + 4, 7, true);
            return 8;
        },
    };
    const kernel = Object.freeze(Object.create(null)) as TranscriptCoreKernel;
    registerCanonicalBoardKernelContext(kernel, context);
    return {
        allocations,
        cancelledHandles,
        context,
        framedCarrierInputs,
        kernel,
    };
};

describe('canonical board WASM runtime', () => {
    it('selects only canonical bytes and reuses opaque capabilities for semantic replay', () => {
        const fake = createFakeKernel();
        const session = requireValid(
            openCanonicalBoardVerifierSession({
                configuration: configuration(),
                kernel: fake.kernel,
            }),
        );
        const untrustedCarrier = Object.defineProperty(
            {
                canonicalCarrier: Uint8Array.of(0x71, 0x72, 0x73),
                claimedProducer: 'relay-selected',
            },
            'claimedFamily',
            {
                get: () => {
                    throw new Error(
                        'unknown relay metadata must remain unread',
                    );
                },
            },
        );
        const first = requireValid(
            session.verifyUnorderedCarriers([untrustedCarrier]),
        )[0];
        const replay = requireValid(
            session.verifyUnorderedCarriers([untrustedCarrier]),
        )[0];

        expect(replay).toBe(first);
        expect(Object.keys(first as object)).toEqual([]);
        expect(fake.framedCarrierInputs).toEqual([
            Uint8Array.of(1, 0, 0, 0, 3, 0, 0, 0, 0x71, 0x72, 0x73),
            Uint8Array.of(1, 0, 0, 0, 3, 0, 0, 0, 0x71, 0x72, 0x73),
        ]);
        expect(requireValid(session.describe(first))).toEqual({
            objectHash: new Uint8Array(64).fill(0x44),
            objectType: foundationObjectTypes.setupIntent,
        });
        expect(requireValid(session.copyCachedCarrier(first))).toEqual(
            Uint8Array.of(0x91, 0x92, 0x93),
        );
        const kernelAuthorization =
            resolveVerifiedTranscriptObjectKernelAuthorization(
                first,
                fake.kernel,
            );
        expect(kernelAuthorization).toMatchObject({
            capabilityMemory: fake.context.memory,
            objectHandle: 7,
            sessionHandle: 1,
        });
        expect(kernelAuthorization.capabilityPointer).toBeGreaterThan(0);
        expect(() =>
            resolveVerifiedTranscriptObjectKernelAuthorization(
                first,
                Object.freeze(Object.create(null)) as TranscriptCoreKernel,
            ),
        ).toThrow('belongs to another WASM kernel');

        session.release(first);
        expect(session.describe(first)).toEqual({
            isValid: false,
            refusalReason: 'consumedState',
        });
        expect(() =>
            resolveVerifiedTranscriptObjectKernelAuthorization(
                first,
                fake.kernel,
            ),
        ).toThrow('unavailable');
        session.close();
        expect(fake.cancelledHandles).toEqual([1]);
        expect(fake.allocations.size).toBe(0);
    });

    it('returns typed refusals and releases every transient allocation', () => {
        const fake = createFakeKernel(9);
        const session = requireValid(
            openCanonicalBoardVerifierSession({
                configuration: configuration(),
                kernel: fake.kernel,
            }),
        );

        const hostileCarrier = Object.defineProperty({}, 'canonicalCarrier', {
            get: () => {
                throw new Error('relay getter must not escape the boundary');
            },
        });
        expect(
            session.verifyUnorderedCarriers([
                hostileCarrier as { readonly canonicalCarrier: Uint8Array },
            ]),
        ).toEqual({
            isValid: false,
            refusalReason: 'wrongTypeOrLength',
        });
        expect(fake.framedCarrierInputs).toEqual([]);

        expect(
            session.verifyUnorderedCarriers([
                { canonicalCarrier: Uint8Array.of(1, 2, 3) },
            ]),
        ).toEqual({ isValid: false, refusalReason: 'equivocation' });
        expect(fake.allocations.size).toBe(1);
        session.close();
        expect(fake.allocations.size).toBe(0);
    });

    it('refuses an oversized aggregate carrier batch before WASM allocation', () => {
        const fake = createFakeKernel();
        const session = requireValid(
            openCanonicalBoardVerifierSession({
                configuration: configuration(),
                kernel: fake.kernel,
            }),
        );
        const carrierByteLength = Math.floor(
            foundationProfile.maximumCopiedBufferByteLength / 2,
        );

        expect(
            session.verifyUnorderedCarriers([
                {
                    canonicalCarrier: new Uint8Array(carrierByteLength),
                },
                {
                    canonicalCarrier: new Uint8Array(carrierByteLength),
                },
            ]),
        ).toEqual({
            isValid: false,
            refusalReason: 'outsideSupportedProfile',
        });
        expect(fake.framedCarrierInputs).toEqual([]);
        expect(fake.allocations.size).toBe(1);

        session.close();
        expect(fake.allocations.size).toBe(0);
    });
});
