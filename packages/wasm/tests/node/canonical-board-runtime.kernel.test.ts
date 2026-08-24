import { beforeEach, describe, expect, it } from 'vitest';

import {
    foundationObjectTypes,
    openCanonicalBoardVerifierSession,
    type CanonicalBoardContextInput,
    type CanonicalBoardVerifierSession,
    type VerifiedTranscriptObject,
} from '#packages/wasm/src/canonical-board-runtime';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { createCanonicalBoardContextTestInput } from '#packages/wasm/tests/canonical-board-context-test-vector';
import {
    createStateVerifierTestVector,
    type StateVerifierTestVector,
} from '#packages/wasm/tests/state-verifier-test-vectors';

const openSession = (
    kernel: TranscriptCoreKernel,
    contextInput: CanonicalBoardContextInput,
): CanonicalBoardVerifierSession => {
    const opened = openCanonicalBoardVerifierSession({
        contextInput,
        kernel,
    });
    expect(opened.isValid).toBe(true);
    if (!opened.isValid) {
        throw new Error(opened.refusalReason);
    }
    return opened.value;
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        if (left[byteIndex] !== right[byteIndex]) {
            return false;
        }
    }
    return true;
};

describe('Canonical board real-WASM runtime in Node', () => {
    let kernel: TranscriptCoreKernel;
    let contextInput: CanonicalBoardContextInput;
    let vector: StateVerifierTestVector;

    beforeEach(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
        const initialVector = createStateVerifierTestVector();
        contextInput = createCanonicalBoardContextTestInput(
            kernel,
            initialVector.canonicalRosterBytes,
        );
        vector = createStateVerifierTestVector({
            actionContextHash: contextInput.expectedActionContextHash,
            ceremonyContextHash: contextInput.expectedCeremonyContextHash,
            suiteIdentifier: contextInput.expectedSuiteIdentifier,
        });
        if (
            !bytesEqual(
                vector.canonicalRosterBytes,
                contextInput.canonicalRosterBytes,
            )
        ) {
            throw new Error(
                'The deterministic state vector roster changed while deriving its canonical board context.',
            );
        }
    });

    it('resolves unordered typed state dependencies and preserves the first carrier', () => {
        const session = openSession(kernel, contextInput);
        try {
            const carriers = [
                ...vector.reservationVoteCarriers
                    .slice()
                    .reverse()
                    .map((canonicalCarrier) => ({ canonicalCarrier })),
                {
                    canonicalCarrier: vector.reservation.canonicalIntentCarrier,
                },
            ];
            const verified = session.verifyUnorderedCarriers(carriers);
            expect(verified.isValid).toBe(true);
            if (!verified.isValid) {
                throw new Error(verified.refusalReason);
            }
            expect(verified.value).toHaveLength(8);

            let reservationObject: VerifiedTranscriptObject | undefined;
            for (const object of verified.value) {
                const described = session.describe(object);
                expect(described.isValid).toBe(true);
                if (
                    described.isValid &&
                    described.value.objectType ===
                        foundationObjectTypes.stateReservation &&
                    bytesEqual(
                        described.value.objectHash,
                        vector.reservation.objectHash,
                    )
                ) {
                    reservationObject = object;
                }
            }
            expect(reservationObject).toBeDefined();
            if (reservationObject === undefined) {
                throw new Error('The reservation capability was not returned.');
            }
            expect(session.copyCachedCarrier(reservationObject)).toEqual({
                isValid: true,
                value: vector.reservation.canonicalIntentCarrier,
            });

            expect(
                session.verifyUnorderedCarriers([
                    {
                        canonicalCarrier:
                            vector.conflictingReservation
                                .canonicalIntentCarrier,
                    },
                ]),
            ).toEqual({
                isValid: false,
                refusalReason: 'equivocation',
            });
            const replay = session.verifyUnorderedCarriers([
                {
                    canonicalCarrier: vector.reservation.canonicalIntentCarrier,
                },
            ]);
            expect(replay.isValid).toBe(true);
            if (!replay.isValid) {
                throw new Error(replay.refusalReason);
            }
            expect(replay.value).toEqual([reservationObject]);
        } finally {
            session.close();
        }
    });
});
