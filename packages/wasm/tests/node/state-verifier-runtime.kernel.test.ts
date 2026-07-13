import { foundationProfile } from '@sealed-lattice/types';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
    canonicalStreamDomains,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    openStateVerifierSession,
    stateCapabilityKinds,
    type StateVerifierSession,
    type StateVerifierSessionInput,
    type VerifiedStateRecovery,
    type VerifiedStateReservation,
} from '#packages/wasm/src/state-verifier-runtime';
import {
    createStateVerifierTestVector,
    type StateVerifierTestVector,
} from '#packages/wasm/tests/state-verifier-test-vectors';

const stateConfiguration = (
    vector: StateVerifierTestVector,
    actionContextHash = vector.actionContextHash,
): StateVerifierSessionInput => ({
    actionContextHash,
    canonicalRosterBytes: vector.canonicalRosterBytes,
    ceremonyContextHash: vector.ceremonyContextHash,
    maximumRecoveryTransitionsPerStateKey: 2,
    suiteIdentifier: vector.suiteIdentifier,
});

const openSession = (
    kernel: TranscriptCoreKernel,
    vector: StateVerifierTestVector,
    configuration = stateConfiguration(vector),
): StateVerifierSession => {
    const opened = openStateVerifierSession({ configuration, kernel });
    expect(opened.isValid).toBe(true);
    if (!opened.isValid) {
        throw new Error(opened.refusalReason);
    }
    return opened.value;
};

const chunkBuffers = (bytes: Uint8Array): readonly ArrayBuffer[] => {
    const chunks: ArrayBuffer[] = [];
    for (
        let offset = 0;
        offset < bytes.byteLength;
        offset += foundationProfile.streamChunkByteLength
    ) {
        chunks.push(
            bytes.slice(
                offset,
                offset + foundationProfile.streamChunkByteLength,
            ).buffer,
        );
    }
    return chunks;
};

const descriptorFor = (
    kernel: TranscriptCoreKernel,
    streamDomain: CanonicalStreamDomain,
    bytes: Uint8Array,
): Uint8Array => {
    const runtime = openCanonicalStreamWorkerRuntime({ kernel });
    const writer = runtime.openWriter({
        streamDomain,
        totalByteLength: bytes.byteLength,
    });
    for (const [chunkIndex, chunk] of chunkBuffers(bytes).entries()) {
        writer.absorbChunk(chunkIndex, chunk);
    }
    return writer.finish();
};

const verifyReservation = (
    session: StateVerifierSession,
    vector: StateVerifierTestVector,
): ReturnType<StateVerifierSession['verifyReservation']> =>
    session.verifyReservation({
        canonicalReservationIntentCarrier:
            vector.reservation.canonicalIntentCarrier,
        canonicalStateCertificate: vector.reservation.canonicalStateCertificate,
        capabilityKind: stateCapabilityKinds.targetRelease,
        expectedAuthorizationHash: vector.authorizationHash,
        subjectParticipantIdentity: vector.subjectParticipantIdentity,
    });

describe('State verifier real-WASM runtime in Node', () => {
    let kernel: TranscriptCoreKernel;
    let vector: StateVerifierTestVector;

    beforeAll(() => {
        vector = createStateVerifierTestVector();
    });

    beforeEach(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('verifies an exact quorum and consumes streamed output without exposing its bytes', () => {
        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'sealed_lattice_state_verifier_begin',
                'sealed_lattice_state_verifier_finish_output',
                'sealed_lattice_state_verifier_verify_recovery',
                'sealed_lattice_state_verifier_verify_reservation',
            ]),
        );
        const session = openSession(kernel, vector);
        try {
            const reservation = verifyReservation(session, vector);
            expect(reservation.isValid).toBe(true);
            if (!reservation.isValid) {
                throw new Error(reservation.refusalReason);
            }

            const openedOutput = session.openOutputVerification({
                canonicalOutputIntentCarrier:
                    vector.output.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.output.canonicalStateCertificate,
                exactOutputDescriptorBytes: descriptorFor(
                    kernel,
                    canonicalStreamDomains.stateTargetReleaseExactOutput,
                    vector.exactOutputBytes,
                ),
                verifiedReservation: reservation.value,
            });
            expect(openedOutput.isValid).toBe(true);
            if (!openedOutput.isValid) {
                throw new Error(openedOutput.refusalReason);
            }
            expect(session.releaseVerifiedObject(reservation.value)).toEqual({
                isValid: false,
                refusalReason: 'consumedState',
            });
            for (const [chunkIndex, chunk] of chunkBuffers(
                vector.exactOutputBytes,
            ).entries()) {
                expect(
                    openedOutput.value.absorbChunk(chunkIndex, chunk),
                ).toEqual({
                    isValid: true,
                    value: undefined,
                });
            }
            const output = openedOutput.value.finish();
            expect(output.isValid).toBe(true);
            if (!output.isValid) {
                throw new Error(output.refusalReason);
            }
            expect(Reflect.ownKeys(output.value)).toEqual([]);
            expect(Object.getPrototypeOf(output.value)).toBeNull();
            expect(session.releaseVerifiedObject(output.value)).toEqual({
                isValid: true,
                value: undefined,
            });
            expect(session.releaseVerifiedObject(output.value)).toEqual({
                isValid: false,
                refusalReason: 'consumedState',
            });
            expect(session.releaseVerifiedObject(reservation.value)).toEqual({
                isValid: true,
                value: undefined,
            });
        } finally {
            session.cancel();
        }
    });

    it('checks every extra witness rather than accepting an early quorum prefix', () => {
        const session = openSession(kernel, vector);
        try {
            const reservation = verifyReservation(session, vector);
            if (!reservation.isValid) {
                throw new Error(reservation.refusalReason);
            }
            const openedOutput = session.openOutputVerification({
                canonicalOutputIntentCarrier:
                    vector.output.canonicalIntentCarrier,
                canonicalStateCertificate: vector.invalidExtraOutputCertificate,
                exactOutputDescriptorBytes: descriptorFor(
                    kernel,
                    canonicalStreamDomains.stateTargetReleaseExactOutput,
                    vector.exactOutputBytes,
                ),
                verifiedReservation: reservation.value,
            });
            if (!openedOutput.isValid) {
                throw new Error(openedOutput.refusalReason);
            }
            for (const [chunkIndex, chunk] of chunkBuffers(
                vector.exactOutputBytes,
            ).entries()) {
                expect(
                    openedOutput.value.absorbChunk(chunkIndex, chunk).isValid,
                ).toBe(true);
            }
            expect(openedOutput.value.finish()).toEqual({
                isValid: false,
                refusalReason: 'invalidSignature',
            });
        } finally {
            session.cancel();
        }
    });

    it('binds reservations to the configured suite, ceremony, and action context', () => {
        const wrongActionContextHash = Uint8Array.from(
            vector.actionContextHash,
        );
        wrongActionContextHash[0] ^= 1;
        const session = openSession(
            kernel,
            vector,
            stateConfiguration(vector, wrongActionContextHash),
        );
        try {
            expect(verifyReservation(session, vector)).toEqual({
                isValid: false,
                refusalReason: 'wrongContext',
            });
        } finally {
            session.cancel();
        }
    });

    it('rejects forged, wrong-kind, cross-session, and wrong-domain substitutions', async () => {
        const session = openSession(kernel, vector);
        const otherKernel = await loadFreshTranscriptCoreKernel();
        const otherSession = openSession(otherKernel, vector);
        try {
            const reservation = verifyReservation(session, vector);
            if (!reservation.isValid) {
                throw new Error(reservation.refusalReason);
            }
            const recovery = session.verifyRecovery({
                canonicalRecoveryTransitionCarrier:
                    vector.recoveryFirst.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.recoveryFirst.canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.finalitySignature,
                subjectParticipantIdentity: vector.subjectParticipantIdentity,
            });
            if (!recovery.isValid) {
                throw new Error(recovery.refusalReason);
            }
            const descriptor = descriptorFor(
                kernel,
                canonicalStreamDomains.stateTargetReleaseExactOutput,
                vector.exactOutputBytes,
            );
            const outputInput = {
                canonicalOutputIntentCarrier:
                    vector.output.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.output.canonicalStateCertificate,
                exactOutputDescriptorBytes: descriptor,
            } as const;

            expect(
                session.openOutputVerification({
                    ...outputInput,
                    verifiedReservation:
                        recovery.value as unknown as VerifiedStateReservation,
                }),
            ).toEqual({
                isValid: false,
                refusalReason: 'wrongTypeOrLength',
            });
            expect(
                session.openOutputVerification({
                    ...outputInput,
                    verifiedReservation: Object.freeze(
                        Object.create(null),
                    ) as VerifiedStateReservation,
                }),
            ).toEqual({
                isValid: false,
                refusalReason: 'wrongTypeOrLength',
            });
            expect(
                otherSession.openOutputVerification({
                    ...outputInput,
                    verifiedReservation: reservation.value,
                }),
            ).toEqual({
                isValid: false,
                refusalReason: 'wrongContext',
            });

            const wrongDomainOutput = session.openOutputVerification({
                ...outputInput,
                exactOutputDescriptorBytes: descriptorFor(
                    kernel,
                    canonicalStreamDomains.stateFinalitySignatureExactOutput,
                    vector.exactOutputBytes,
                ),
                verifiedReservation: reservation.value,
            });
            if (!wrongDomainOutput.isValid) {
                throw new Error(wrongDomainOutput.refusalReason);
            }
            expect(
                wrongDomainOutput.value.absorbChunk(
                    0,
                    chunkBuffers(vector.exactOutputBytes)[0],
                ),
            ).toEqual({
                isValid: false,
                refusalReason: 'wrongHashOrRoot',
            });
        } finally {
            otherSession.cancel();
            session.cancel();
        }
    });

    it('chains recovery handles and rejects cross-kind predecessor substitution', () => {
        const session = openSession(kernel, vector);
        try {
            const firstRecovery = session.verifyRecovery({
                canonicalRecoveryTransitionCarrier:
                    vector.recoveryFirst.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.recoveryFirst.canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.finalitySignature,
                subjectParticipantIdentity: vector.subjectParticipantIdentity,
            });
            expect(firstRecovery.isValid).toBe(true);
            if (!firstRecovery.isValid) {
                throw new Error(firstRecovery.refusalReason);
            }
            const secondRecovery = session.verifyRecovery({
                canonicalRecoveryTransitionCarrier:
                    vector.recoverySecond.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.recoverySecond.canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.finalitySignature,
                subjectParticipantIdentity: vector.subjectParticipantIdentity,
                verifiedPredecessorRecovery: firstRecovery.value,
            });
            expect(secondRecovery.isValid).toBe(true);
            if (!secondRecovery.isValid) {
                throw new Error(secondRecovery.refusalReason);
            }

            const reservation = verifyReservation(session, vector);
            if (!reservation.isValid) {
                throw new Error(reservation.refusalReason);
            }
            expect(
                session.verifyRecovery({
                    canonicalRecoveryTransitionCarrier:
                        vector.recoverySecond.canonicalIntentCarrier,
                    canonicalStateCertificate:
                        vector.recoverySecond.canonicalStateCertificate,
                    capabilityKind: stateCapabilityKinds.finalitySignature,
                    subjectParticipantIdentity:
                        vector.subjectParticipantIdentity,
                    verifiedPredecessorRecovery:
                        reservation.value as unknown as VerifiedStateRecovery,
                }),
            ).toEqual({
                isValid: false,
                refusalReason: 'wrongTypeOrLength',
            });
        } finally {
            session.cancel();
        }
    });

    it('binds the output intent to every exact streamed byte', () => {
        const session = openSession(kernel, vector);
        try {
            const reservation = verifyReservation(session, vector);
            if (!reservation.isValid) {
                throw new Error(reservation.refusalReason);
            }
            const changedOutputBytes = Uint8Array.from(vector.exactOutputBytes);
            changedOutputBytes[changedOutputBytes.byteLength - 1] ^= 1;
            const openedOutput = session.openOutputVerification({
                canonicalOutputIntentCarrier:
                    vector.output.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.output.canonicalStateCertificate,
                exactOutputDescriptorBytes: descriptorFor(
                    kernel,
                    canonicalStreamDomains.stateTargetReleaseExactOutput,
                    changedOutputBytes,
                ),
                verifiedReservation: reservation.value,
            });
            if (!openedOutput.isValid) {
                throw new Error(openedOutput.refusalReason);
            }
            for (const [chunkIndex, chunk] of chunkBuffers(
                changedOutputBytes,
            ).entries()) {
                expect(
                    openedOutput.value.absorbChunk(chunkIndex, chunk).isValid,
                ).toBe(true);
            }
            expect(openedOutput.value.finish()).toEqual({
                isValid: false,
                refusalReason: 'wrongHashOrRoot',
            });
        } finally {
            session.cancel();
        }
    });

    it('accepts setup reservations but refuses an exact-output lease for them', () => {
        const session = openSession(kernel, vector);
        try {
            const reservation = session.verifyReservation({
                canonicalReservationIntentCarrier:
                    vector.reservationOnly.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.reservationOnly.canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.setupActionRandomnessRoot,
                expectedAuthorizationHash: vector.authorizationHash,
                subjectParticipantIdentity: vector.subjectParticipantIdentity,
            });
            expect(reservation.isValid).toBe(true);
            if (!reservation.isValid) {
                throw new Error(reservation.refusalReason);
            }

            expect(
                session.openOutputVerification({
                    canonicalOutputIntentCarrier:
                        vector.output.canonicalIntentCarrier,
                    canonicalStateCertificate:
                        vector.output.canonicalStateCertificate,
                    exactOutputDescriptorBytes: descriptorFor(
                        kernel,
                        canonicalStreamDomains.stateTargetReleaseExactOutput,
                        vector.exactOutputBytes,
                    ),
                    verifiedReservation: reservation.value,
                }),
            ).toEqual({
                isValid: false,
                refusalReason: 'wrongTypeOrLength',
            });
        } finally {
            session.cancel();
        }
    });
});
