import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    foundationObjectTypes,
    openCanonicalBoardVerifierSession,
    registerCanonicalBoardKernelContext,
    resolveVerifiedTranscriptObjectKernelAuthorization,
    type CanonicalBoardKernelContext,
    type CanonicalBoardContextInput,
} from '../../src/canonical-board-runtime.js';
import { mlDsa65SignatureByteLength } from '../../src/state-verifier-runtime/contracts.js';
import type { TranscriptCoreKernel } from '../../src/transcript-core-bridge/kernel-types.js';

const contextInput = (): CanonicalBoardContextInput => ({
    actionIdentifier: 'action',
    canonicalActionDefinitionBytes: Uint8Array.of(0xa1),
    canonicalBoardPolicyBytes: Uint8Array.of(0xb1),
    canonicalManifestBytes: Uint8Array.of(0xc1),
    canonicalRosterBytes: Uint8Array.of(0xaa, 0xbb),
    canonicalSuiteRecordBytes: Uint8Array.of(0xd1),
    ceremonyIdentifier: 'ceremony',
    expectedActionContextHash: new Uint8Array(64).fill(0x33),
    expectedCeremonyContextHash: new Uint8Array(64).fill(0x22),
    expectedSuiteIdentifier: new Uint8Array(64).fill(0x11),
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
    candidateListCancellations: number[];
    candidateListFinishStatus: { value: number };
    candidateListFinishes: number[];
    candidateListPreparations: readonly (readonly number[])[];
    cancelledHandles: readonly number[];
    context: CanonicalBoardKernelContext;
    framedCarrierInputs: readonly Uint8Array[];
    kernel: TranscriptCoreKernel;
}>;

const createFakeKernel = (verifyStatus = 0): FakeKernel => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const candidateListCancellations: number[] = [];
    const candidateListFinishStatus = { value: 0 };
    const candidateListFinishes: number[] = [];
    const candidateListPreparations: number[][] = [];
    const cancelledHandles: number[] = [];
    const framedCarrierInputs: Uint8Array[] = [];
    let candidateListPublicationState: 'available' | 'prepared' | 'spent' =
        'available';
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
        begin: (...parameters) => {
            const statusPointer = parameters[parameters.length - 1];
            if (statusPointer === undefined) {
                throw new Error('test begin did not receive a status pointer');
            }
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
        cancelBallotCandidateList: (
            _sessionHandle,
            _capabilityPointer,
            _capabilityLength,
            preparedCarrierHandle,
        ) => {
            if (
                candidateListPublicationState !== 'prepared' ||
                preparedCarrierHandle !== 41
            ) {
                return refusalReasonCodes.consumedState;
            }
            candidateListPublicationState = 'available';
            candidateListCancellations.push(preparedCarrierHandle);
            return 0;
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
        finishBallotCandidateList: (
            _sessionHandle,
            _capabilityPointer,
            _capabilityLength,
            preparedCarrierHandle,
            signaturePointer,
            signatureLength,
            outputPointer,
            outputLength,
        ) => {
            if (
                candidateListPublicationState !== 'prepared' ||
                preparedCarrierHandle !== 41
            ) {
                return refusalReasonCodes.consumedState;
            }
            candidateListPublicationState = 'spent';
            candidateListFinishes.push(preparedCarrierHandle);
            if (
                signatureLength !== mlDsa65SignatureByteLength ||
                outputLength !== 5 ||
                new Uint8Array(
                    memory.buffer,
                    signaturePointer,
                    signatureLength,
                ).some((byte) => byte !== 0x5a)
            ) {
                return refusalReasonCodes.wrongTypeOrLength;
            }
            if (candidateListFinishStatus.value !== 0) {
                return candidateListFinishStatus.value;
            }
            new Uint8Array(memory.buffer).set(
                [0xc1, 0xc2, 0xc3, 0xc4, 0xc5],
                outputPointer,
            );
            return 0;
        },
        memory,
        prepareBallotCandidateList: (
            _sessionHandle,
            _capabilityPointer,
            _capabilityLength,
            framedHandlesPointer,
            framedHandlesLength,
            canonicalCarrierLengthOutputPointer,
            signatureMessageOutputPointer,
            signatureMessageOutputLength,
            statusPointer,
        ) => {
            if (candidateListPublicationState !== 'available') {
                new DataView(memory.buffer).setUint32(
                    statusPointer,
                    refusalReasonCodes.consumedState,
                    true,
                );
                return 0;
            }
            const framedHandles = new Uint8Array(
                memory.buffer,
                framedHandlesPointer,
                framedHandlesLength,
            );
            const view = new DataView(
                framedHandles.buffer,
                framedHandles.byteOffset,
                framedHandles.byteLength,
            );
            const handleCount = view.getUint32(0, true);
            if (
                signatureMessageOutputLength !== 64 ||
                framedHandlesLength !== 4 + handleCount * 4
            ) {
                new DataView(memory.buffer).setUint32(
                    statusPointer,
                    refusalReasonCodes.wrongTypeOrLength,
                    true,
                );
                return 0;
            }
            candidateListPreparations.push(
                Array.from({ length: handleCount }, (_, handleIndex) =>
                    view.getUint32(4 + handleIndex * 4, true),
                ),
            );
            candidateListPublicationState = 'prepared';
            new DataView(memory.buffer).setUint32(
                canonicalCarrierLengthOutputPointer,
                5,
                true,
            );
            new Uint8Array(memory.buffer).fill(
                0xa5,
                signatureMessageOutputPointer,
                signatureMessageOutputPointer + 64,
            );
            new DataView(memory.buffer).setUint32(statusPointer, 0, true);
            return 41;
        },
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
        candidateListCancellations,
        candidateListFinishStatus,
        candidateListFinishes,
        candidateListPreparations,
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
                contextInput: contextInput(),
                kernel: fake.kernel,
            }),
        );
        const untrustedCarrier = {
            canonicalCarrier: Uint8Array.of(0x71, 0x72, 0x73),
        };
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
                contextInput: contextInput(),
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

    it('produces one candidate-list carrier from board-owned ballot packages', () => {
        const fake = createFakeKernel();
        const session = requireValid(
            openCanonicalBoardVerifierSession({
                contextInput: contextInput(),
                kernel: fake.kernel,
            }),
        );
        const [ballotPackageObject] = requireValid(
            session.verifyUnorderedCarriers([
                { canonicalCarrier: Uint8Array.of(0x71) },
            ]),
        );
        if (ballotPackageObject === undefined) {
            throw new Error('The fake ballot package was not verified.');
        }
        const observedSignatureMessages: Uint8Array[] = [];
        const signatureOperation = Object.freeze({
            signBallotCandidateListMessage: (
                signatureMessageHash: Uint8Array,
            ) => {
                observedSignatureMessages.push(signatureMessageHash.slice());
                return new Uint8Array(mlDsa65SignatureByteLength).fill(0x5a);
            },
        });

        expect(
            session.produceBallotCandidateListCarrier({
                ballotPackageObjects: [ballotPackageObject],
                signatureOperation,
            }),
        ).toEqual({
            isValid: true,
            value: {
                canonicalBallotCandidateListCarrier: Uint8Array.of(
                    0xc1,
                    0xc2,
                    0xc3,
                    0xc4,
                    0xc5,
                ),
            },
        });
        expect(observedSignatureMessages).toEqual([
            new Uint8Array(64).fill(0xa5),
        ]);
        expect(fake.candidateListPreparations).toEqual([[7]]);
        expect(fake.candidateListFinishes).toEqual([41]);
        expect(fake.candidateListCancellations).toEqual([]);
        expect(
            session.produceBallotCandidateListCarrier({
                ballotPackageObjects: [ballotPackageObject],
                signatureOperation,
            }),
        ).toEqual({
            isValid: false,
            refusalReason: 'consumedState',
        });

        session.close();
        expect(fake.allocations.size).toBe(0);
    });

    it('cancels before finish but spends every exact candidate-list signature attempt', () => {
        const cancelledFake = createFakeKernel();
        const cancelledSession = requireValid(
            openCanonicalBoardVerifierSession({
                contextInput: contextInput(),
                kernel: cancelledFake.kernel,
            }),
        );
        const [cancelledBallotPackageObject] = requireValid(
            cancelledSession.verifyUnorderedCarriers([
                { canonicalCarrier: Uint8Array.of(0x72) },
            ]),
        );
        if (cancelledBallotPackageObject === undefined) {
            throw new Error('The fake ballot package was not verified.');
        }
        expect(
            cancelledSession.produceBallotCandidateListCarrier({
                ballotPackageObjects: [cancelledBallotPackageObject],
                signatureOperation: {
                    signBallotCandidateListMessage: () =>
                        new Uint8Array(mlDsa65SignatureByteLength - 1),
                },
            }),
        ).toEqual({
            isValid: false,
            refusalReason: 'wrongTypeOrLength',
        });
        expect(cancelledFake.candidateListCancellations).toEqual([41]);
        expect(
            cancelledSession.produceBallotCandidateListCarrier({
                ballotPackageObjects: [cancelledBallotPackageObject],
                signatureOperation: {
                    signBallotCandidateListMessage: () =>
                        new Uint8Array(mlDsa65SignatureByteLength).fill(0x5a),
                },
            }).isValid,
        ).toBe(true);
        cancelledSession.close();

        const refusedFake = createFakeKernel();
        refusedFake.candidateListFinishStatus.value =
            refusalReasonCodes.invalidSignature;
        const refusedSession = requireValid(
            openCanonicalBoardVerifierSession({
                contextInput: contextInput(),
                kernel: refusedFake.kernel,
            }),
        );
        const [refusedBallotPackageObject] = requireValid(
            refusedSession.verifyUnorderedCarriers([
                { canonicalCarrier: Uint8Array.of(0x73) },
            ]),
        );
        if (refusedBallotPackageObject === undefined) {
            throw new Error('The fake ballot package was not verified.');
        }
        const exactSignatureOperation = {
            signBallotCandidateListMessage: () =>
                new Uint8Array(mlDsa65SignatureByteLength).fill(0x5a),
        };
        expect(
            refusedSession.produceBallotCandidateListCarrier({
                ballotPackageObjects: [refusedBallotPackageObject],
                signatureOperation: exactSignatureOperation,
            }),
        ).toEqual({
            isValid: false,
            refusalReason: 'invalidSignature',
        });
        expect(refusedFake.candidateListCancellations).toEqual([]);
        expect(
            refusedSession.produceBallotCandidateListCarrier({
                ballotPackageObjects: [refusedBallotPackageObject],
                signatureOperation: exactSignatureOperation,
            }),
        ).toEqual({
            isValid: false,
            refusalReason: 'consumedState',
        });
        refusedSession.close();
    });

    it('refuses an oversized aggregate carrier batch before WASM allocation', () => {
        const fake = createFakeKernel();
        const session = requireValid(
            openCanonicalBoardVerifierSession({
                contextInput: contextInput(),
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
