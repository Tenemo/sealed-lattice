import { describe, expect, it } from 'vitest';

import {
    canonicalStreamDomains,
    openCanonicalStreamWorkerRuntime,
} from '#packages/wasm/src/canonical-stream-runtime';
import { loadFreshTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    copyVerifiedStateDurableBinding,
    openStateVerifierSession,
    stateCapabilityKinds,
} from '#packages/wasm/src/state-verifier-runtime';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';
import { canonicalStreamChunkBuffers as chunkBuffers } from '#tests/support/canonical-stream-chunk-buffers';

describe('State verifier real-WASM runtime in browsers', () => {
    it('verifies streamed exact output with opaque handles', async () => {
        const vector = createStateVerifierTestVector();
        const kernel = await loadFreshTranscriptCoreKernel();
        const openedSession = openStateVerifierSession({
            configuration: {
                actionContextHash: vector.actionContextHash,
                canonicalRosterBytes: vector.canonicalRosterBytes,
                ceremonyContextHash: vector.ceremonyContextHash,
                suiteIdentifier: vector.suiteIdentifier,
            },
            kernel,
        });
        expect(openedSession.isValid).toBe(true);
        if (!openedSession.isValid) {
            throw new Error(openedSession.refusalReason);
        }
        const session = openedSession.value;
        try {
            const reservation = session.verifyReservation({
                canonicalReservationIntentCarrier:
                    vector.reservation.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.reservation.canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.targetRelease,
                expectedAuthorizationHash: vector.authorizationHash,
                subjectParticipantIdentity: vector.subjectParticipantIdentity,
            });
            expect(reservation.isValid).toBe(true);
            if (!reservation.isValid) {
                throw new Error(reservation.refusalReason);
            }

            const canonicalStreamRuntime = openCanonicalStreamWorkerRuntime({
                kernel,
            });
            const writer = canonicalStreamRuntime.openWriter({
                streamDomain:
                    canonicalStreamDomains.stateTargetReleaseExactOutput,
                totalByteLength: vector.exactOutputBytes.byteLength,
            });
            const outputChunks = chunkBuffers(vector.exactOutputBytes);
            for (const [chunkIndex, chunk] of outputChunks.entries()) {
                writer.absorbChunk(chunkIndex, chunk);
            }
            const openedOutput = session.openOutputVerification({
                canonicalOutputIntentCarrier:
                    vector.output.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.output.canonicalStateCertificate,
                exactOutputDescriptorBytes: writer.finish(),
                verifiedReservation: reservation.value,
            });
            expect(openedOutput.isValid).toBe(true);
            if (!openedOutput.isValid) {
                throw new Error(openedOutput.refusalReason);
            }
            for (const [chunkIndex, chunk] of outputChunks.entries()) {
                expect(
                    openedOutput.value.absorbChunk(chunkIndex, chunk),
                ).toEqual({ isValid: true, value: undefined });
            }
            const output = openedOutput.value.finish();
            expect(output.isValid).toBe(true);
            if (!output.isValid) {
                throw new Error(output.refusalReason);
            }
            const durableOutputBinding = session.durableBindingFor(
                output.value,
            );
            expect(durableOutputBinding.isValid).toBe(true);
            if (!durableOutputBinding.isValid) {
                throw new Error(durableOutputBinding.refusalReason);
            }
            expect(
                copyVerifiedStateDurableBinding(durableOutputBinding.value),
            ).toMatchObject({
                outputIntentObjectHash: vector.output.objectHash,
                reservationIntentObjectHash: vector.reservation.objectHash,
                witnessVoteSequence: 2n,
            });
        } finally {
            session.cancel();
        }
    }, 60_000);
});
