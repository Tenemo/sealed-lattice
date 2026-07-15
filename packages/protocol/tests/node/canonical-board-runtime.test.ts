import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    openCanonicalBoardRuntime,
    type CanonicalBoardRuntimeInput,
    type VerifiedCanonicalBoardSnapshot,
} from '#packages/protocol/src/runtime/canonical-board-runtime';
import type {
    CanonicalBoardVerifierSession,
    FoundationObjectType,
    VerifiedTranscriptObject,
    VerifiedTranscriptObjectDescription,
} from '#packages/wasm/src/canonical-board-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const openCanonicalBoardVerifierSessionMock = vi.hoisted(() => vi.fn());

vi.mock('@sealed-lattice/wasm', () => ({
    openCanonicalBoardVerifierSession: openCanonicalBoardVerifierSessionMock,
}));

const createVerifiedObject = (): VerifiedTranscriptObject =>
    Object.freeze(Object.create(null) as object) as VerifiedTranscriptObject;

type FakeSession = Readonly<{
    close: ReturnType<typeof vi.fn>;
    copyCachedCarrier: ReturnType<typeof vi.fn>;
    describe: ReturnType<typeof vi.fn>;
    session: CanonicalBoardVerifierSession;
    verifyUnorderedCarriers: ReturnType<typeof vi.fn>;
}>;

const createFakeSession = (
    entries: readonly Readonly<{
        cachedCarrier: Uint8Array;
        description: VerifiedTranscriptObjectDescription;
        object: VerifiedTranscriptObject;
    }>[],
): FakeSession => {
    const descriptions = new WeakMap<
        object,
        VerifiedTranscriptObjectDescription
    >();
    const cachedCarriers = new WeakMap<object, Uint8Array>();
    for (const entry of entries) {
        descriptions.set(entry.object, entry.description);
        cachedCarriers.set(entry.object, entry.cachedCarrier);
    }
    let state: 'active' | 'closed' = 'active';
    const close = vi.fn(() => {
        state = 'closed';
    });
    const verifyUnorderedCarriers = vi.fn();
    const describeObject = vi.fn((object: VerifiedTranscriptObject) => {
        const description = descriptions.get(object);
        return description === undefined
            ? {
                  isValid: false as const,
                  refusalReason: 'wrongContext' as const,
              }
            : { isValid: true as const, value: description };
    });
    const copyCachedCarrier = vi.fn((object: VerifiedTranscriptObject) => {
        const carrier = cachedCarriers.get(object);
        return carrier === undefined
            ? {
                  isValid: false as const,
                  refusalReason: 'wrongContext' as const,
              }
            : { isValid: true as const, value: carrier.slice() };
    });
    const session = {
        close,
        copyCachedCarrier,
        describe: describeObject,
        release: vi.fn(),
        state: () => state,
        verifyUnorderedCarriers,
    } as CanonicalBoardVerifierSession;
    return {
        close,
        copyCachedCarrier,
        describe: describeObject,
        session,
        verifyUnorderedCarriers,
    };
};

const objectDescription = (
    byte: number,
    objectType: FoundationObjectType,
): VerifiedTranscriptObjectDescription => ({
    objectHash: new Uint8Array(64).fill(byte),
    objectType,
});

const runtimeInput = (): CanonicalBoardRuntimeInput => ({
    configuration: {
        actionContextHash: new Uint8Array(64).fill(0x33),
        canonicalRosterBytes: Uint8Array.of(1),
        ceremonyContextHash: new Uint8Array(64).fill(0x22),
        maximumBallotAttemptsPerParticipant: 8,
        maximumRetainedCanonicalCarrierByteLength: 1_048_576,
        maximumRetainedTranscriptObjects: 128,
        maximumUnorderedCarriersPerBatch: 32,
        suiteIdentifier: new Uint8Array(64).fill(0x11),
    },
    kernel: Object.freeze(Object.create(null)) as TranscriptCoreKernel,
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

describe('canonical board runtime', () => {
    beforeEach(() => {
        openCanonicalBoardVerifierSessionMock.mockReset();
    });

    it('indexes only verifier-owned capabilities and preserves cached carrier bytes', () => {
        const firstObject = createVerifiedObject();
        const secondObject = createVerifiedObject();
        const firstDescription = objectDescription(0x11, 0x0010);
        const secondDescription = objectDescription(0x22, 0x0001);
        const fake = createFakeSession([
            {
                cachedCarrier: Uint8Array.of(1, 2, 3),
                description: firstDescription,
                object: firstObject,
            },
            {
                cachedCarrier: Uint8Array.of(4, 5, 6),
                description: secondDescription,
                object: secondObject,
            },
        ]);
        fake.verifyUnorderedCarriers.mockReturnValueOnce({
            isValid: true,
            value: Object.freeze([secondObject, firstObject]),
        });
        openCanonicalBoardVerifierSessionMock.mockReturnValue({
            isValid: true,
            value: fake.session,
        });
        const runtime = requireValid(openCanonicalBoardRuntime(runtimeInput()));
        const carriers = [
            {
                canonicalCarrier: Uint8Array.of(9, 8, 7),
                relayArrivalIndex: 999,
            },
        ];

        const snapshot = requireValid(runtime.ingestUnordered(carriers));
        expect(Reflect.ownKeys(snapshot as object)).toEqual([]);
        expect(fake.verifyUnorderedCarriers).toHaveBeenCalledWith(carriers);
        expect(requireValid(runtime.objects(snapshot))).toEqual([
            firstObject,
            secondObject,
        ]);

        firstDescription.objectHash.fill(0xff);
        expect(
            requireValid(
                runtime.findObject(snapshot, new Uint8Array(64).fill(0x11)),
            ),
        ).toBe(firstObject);
        expect(
            requireValid(
                runtime.copyCachedCarrier(
                    snapshot,
                    new Uint8Array(64).fill(0x11),
                ),
            ),
        ).toEqual(Uint8Array.of(1, 2, 3));
    });

    it('keeps an earlier snapshot usable after an atomic batch refusal', () => {
        const object = createVerifiedObject();
        const fake = createFakeSession([
            {
                cachedCarrier: Uint8Array.of(1),
                description: objectDescription(0x44, 0x0070),
                object,
            },
        ]);
        fake.verifyUnorderedCarriers
            .mockReturnValueOnce({
                isValid: true,
                value: Object.freeze([object]),
            })
            .mockReturnValueOnce({
                isValid: false,
                refusalReason: 'equivocation',
            });
        openCanonicalBoardVerifierSessionMock.mockReturnValue({
            isValid: true,
            value: fake.session,
        });
        const runtime = requireValid(openCanonicalBoardRuntime(runtimeInput()));
        const snapshot = requireValid(
            runtime.ingestUnordered([{ canonicalCarrier: Uint8Array.of(1) }]),
        );

        expect(
            runtime.ingestUnordered([{ canonicalCarrier: Uint8Array.of(2) }]),
        ).toEqual({ isValid: false, refusalReason: 'equivocation' });
        expect(requireValid(runtime.objects(snapshot))).toEqual([object]);
    });

    it('keeps successful snapshots immutable as later objects arrive', () => {
        const firstObject = createVerifiedObject();
        const secondObject = createVerifiedObject();
        const fake = createFakeSession([
            {
                cachedCarrier: Uint8Array.of(1),
                description: objectDescription(0x31, 0x0010),
                object: firstObject,
            },
            {
                cachedCarrier: Uint8Array.of(2),
                description: objectDescription(0x21, 0x0001),
                object: secondObject,
            },
        ]);
        fake.verifyUnorderedCarriers
            .mockReturnValueOnce({
                isValid: true,
                value: Object.freeze([firstObject]),
            })
            .mockReturnValueOnce({
                isValid: true,
                value: Object.freeze([secondObject]),
            });
        openCanonicalBoardVerifierSessionMock.mockReturnValue({
            isValid: true,
            value: fake.session,
        });
        const runtime = requireValid(openCanonicalBoardRuntime(runtimeInput()));
        const firstSnapshot = requireValid(
            runtime.ingestUnordered([{ canonicalCarrier: Uint8Array.of(1) }]),
        );
        const secondSnapshot = requireValid(
            runtime.ingestUnordered([{ canonicalCarrier: Uint8Array.of(2) }]),
        );

        expect(requireValid(runtime.objects(firstSnapshot))).toEqual([
            firstObject,
        ]);
        expect(requireValid(runtime.objects(secondSnapshot))).toEqual([
            secondObject,
            firstObject,
        ]);
    });

    it('rejects forged, foreign, missing, and consumed snapshot access', () => {
        const object = createVerifiedObject();
        const firstFake = createFakeSession([
            {
                cachedCarrier: Uint8Array.of(1),
                description: objectDescription(0x55, 0x0020),
                object,
            },
        ]);
        firstFake.verifyUnorderedCarriers.mockReturnValue({
            isValid: true,
            value: Object.freeze([object]),
        });
        const secondFake = createFakeSession([]);
        openCanonicalBoardVerifierSessionMock
            .mockReturnValueOnce({
                isValid: true,
                value: firstFake.session,
            })
            .mockReturnValueOnce({
                isValid: true,
                value: secondFake.session,
            });
        const firstRuntime = requireValid(
            openCanonicalBoardRuntime(runtimeInput()),
        );
        const secondRuntime = requireValid(
            openCanonicalBoardRuntime(runtimeInput()),
        );
        const snapshot = requireValid(
            firstRuntime.ingestUnordered([
                { canonicalCarrier: Uint8Array.of(1) },
            ]),
        );

        expect(secondRuntime.objects(snapshot)).toEqual({
            isValid: false,
            refusalReason: 'wrongContext',
        });
        expect(
            firstRuntime.objects(
                Object.freeze(
                    Object.create(null) as object,
                ) as VerifiedCanonicalBoardSnapshot,
            ),
        ).toEqual({
            isValid: false,
            refusalReason: 'wrongContext',
        });
        expect(
            firstRuntime.objects(
                null as unknown as VerifiedCanonicalBoardSnapshot,
            ),
        ).toEqual({
            isValid: false,
            refusalReason: 'wrongTypeOrLength',
        });
        expect(firstRuntime.findObject(snapshot, Uint8Array.of(1))).toEqual({
            isValid: false,
            refusalReason: 'wrongTypeOrLength',
        });
        expect(
            firstRuntime.findObject(snapshot, new Uint8Array(64).fill(0xaa)),
        ).toEqual({
            isValid: false,
            refusalReason: 'missingPrerequisite',
        });

        firstRuntime.close();
        firstRuntime.close();
        expect(firstFake.close).toHaveBeenCalledTimes(1);
        expect(firstRuntime.objects(snapshot)).toEqual({
            isValid: false,
            refusalReason: 'consumedState',
        });
    });

    it('forwards a verifier-session refusal without minting a runtime', () => {
        openCanonicalBoardVerifierSessionMock.mockReturnValue({
            isValid: false,
            refusalReason: 'unsupportedVersionOrSuite',
        });

        expect(openCanonicalBoardRuntime(runtimeInput())).toEqual({
            isValid: false,
            refusalReason: 'unsupportedVersionOrSuite',
        });
    });
});
