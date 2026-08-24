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
    copyVerifiedStateDurableBinding,
    openStateVerifierSession,
    stateCapabilityKinds,
    stateWitnessVoteKinds,
    type StateVerifierSession,
    type StateVerifierSessionInput,
    type VerifiedStateReservation,
    type VerifiedStateReservationIntent,
    type VerifiedStateDurableBinding,
} from '#packages/wasm/src/state-verifier-runtime';
import {
    createStateVerifierTestVector,
    type StateVerifierTestVector,
} from '#packages/wasm/tests/state-verifier-test-vectors';
import { canonicalStreamChunkBuffers as chunkBuffers } from '#tests/support/canonical-stream-chunk-buffers';

const maximumRetainedVerifiedStateObjectCount = 512;

const stateConfiguration = (
    vector: StateVerifierTestVector,
    actionContextHash = vector.actionContextHash,
): StateVerifierSessionInput => ({
    actionContextHash,
    canonicalRosterBytes: vector.canonicalRosterBytes,
    ceremonyContextHash: vector.ceremonyContextHash,
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

    it('preserves the exact closed state capability registry', () => {
        expect(stateCapabilityKinds).toEqual({
            finalitySignature: 2,
            targetRelease: 3,
            setupActionRandomnessRoot: 4,
            setupTerminalPackage: 8,
        });
    });

    it('projects verifier-derived durable bindings without exposing forgeable fields', () => {
        const session = openSession(kernel, vector);
        try {
            const reservationIntent = session.verifyReservationIntent({
                canonicalReservationIntentCarrier:
                    vector.reservation.canonicalIntentCarrier,
                capabilityKind: stateCapabilityKinds.targetRelease,
                expectedAuthorizationHash: vector.authorizationHash,
                subjectParticipantIdentity: vector.subjectParticipantIdentity,
            });
            expect(reservationIntent.isValid).toBe(true);
            if (!reservationIntent.isValid) {
                throw new Error(reservationIntent.refusalReason);
            }
            const durableBinding = session.durableBindingFor(
                reservationIntent.value,
            );
            expect(durableBinding.isValid).toBe(true);
            if (!durableBinding.isValid) {
                throw new Error(durableBinding.refusalReason);
            }
            const description = copyVerifiedStateDurableBinding(
                durableBinding.value,
            );
            expect(description).toMatchObject({
                capabilityKind: stateCapabilityKinds.targetRelease,
                intentObjectHash: vector.reservation.objectHash,
                reservationIntentObjectHash: vector.reservation.objectHash,
                subjectParticipantIdentity: vector.subjectParticipantIdentity,
                voteKind: stateWitnessVoteKinds.reservation,
                witnessVoteSequence: 1n,
            });
            expect(description.suiteIdentifier).toEqual(vector.suiteIdentifier);
            description.stateKey.fill(0);
            expect(
                copyVerifiedStateDurableBinding(durableBinding.value).stateKey,
            ).not.toEqual(description.stateKey);
            expect(() =>
                copyVerifiedStateDurableBinding(
                    Object.freeze(
                        Object.create(null),
                    ) as VerifiedStateDurableBinding,
                ),
            ).toThrow('was not issued by the WASM state verifier');
            expect(
                session.releaseVerifiedObject(reservationIntent.value),
            ).toEqual({ isValid: true, value: undefined });
            expect(session.durableBindingFor(reservationIntent.value)).toEqual({
                isValid: false,
                refusalReason: 'consumedState',
            });
        } finally {
            session.cancel();
        }
    });

    it('verifies an exact quorum and consumes streamed output without exposing its bytes', () => {
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

    it('disposes abandoned output leases and state sessions idempotently', () => {
        const session = openSession(kernel, vector);
        const reservation = verifyReservation(session, vector);
        if (!reservation.isValid) {
            throw new Error(reservation.refusalReason);
        }
        const openedOutput = session.openOutputVerification({
            canonicalOutputIntentCarrier: vector.output.canonicalIntentCarrier,
            canonicalStateCertificate: vector.output.canonicalStateCertificate,
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

        openedOutput.value.dispose();
        expect(openedOutput.value.state()).toBe('cancelled');
        expect(() => openedOutput.value.dispose()).not.toThrow();
        expect(session.releaseVerifiedObject(reservation.value)).toEqual({
            isValid: true,
            value: undefined,
        });

        session.dispose();
        expect(session.state()).toBe('cancelled');
        expect(() => session.dispose()).not.toThrow();

        const replacementSession = openSession(kernel, vector);
        replacementSession.dispose();
        expect(replacementSession.state()).toBe('cancelled');
    });

    it('consumes the canonical stream when state-output capacity preflight refuses', () => {
        const session = openSession(kernel, vector);
        try {
            const reservation = verifyReservation(session, vector);
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
            if (!openedOutput.isValid) {
                throw new Error(openedOutput.refusalReason);
            }
            for (const [chunkIndex, chunk] of chunkBuffers(
                vector.exactOutputBytes,
            ).entries()) {
                expect(
                    openedOutput.value.absorbChunk(chunkIndex, chunk),
                ).toEqual({ isValid: true, value: undefined });
            }

            const retainedIntents: VerifiedStateReservationIntent[] = [];
            for (
                let retainedObjectIndex = 1;
                retainedObjectIndex < maximumRetainedVerifiedStateObjectCount;
                retainedObjectIndex += 1
            ) {
                const intent = session.verifyReservationIntent({
                    canonicalReservationIntentCarrier:
                        vector.reservation.canonicalIntentCarrier,
                    capabilityKind: stateCapabilityKinds.targetRelease,
                    expectedAuthorizationHash: vector.authorizationHash,
                    subjectParticipantIdentity:
                        vector.subjectParticipantIdentity,
                });
                expect(intent.isValid).toBe(true);
                if (!intent.isValid) {
                    throw new Error(intent.refusalReason);
                }
                retainedIntents.push(intent.value);
            }

            expect(openedOutput.value.finish()).toEqual({
                isValid: false,
                refusalReason: 'outsideSupportedProfile',
            });
            expect(openedOutput.value.state()).toBe('failed');
            expect(openedOutput.value.finish()).toEqual({
                isValid: false,
                refusalReason: 'consumedState',
            });

            const retryDescriptor = descriptorFor(
                kernel,
                canonicalStreamDomains.stateTargetReleaseExactOutput,
                vector.exactOutputBytes,
            );
            const releasableIntent = retainedIntents.pop();
            if (releasableIntent === undefined) {
                throw new Error('The capacity setup retained no state intent.');
            }
            expect(session.releaseVerifiedObject(releasableIntent)).toEqual({
                isValid: true,
                value: undefined,
            });

            const retriedOutput = session.openOutputVerification({
                canonicalOutputIntentCarrier:
                    vector.output.canonicalIntentCarrier,
                canonicalStateCertificate:
                    vector.output.canonicalStateCertificate,
                exactOutputDescriptorBytes: retryDescriptor,
                verifiedReservation: reservation.value,
            });
            if (!retriedOutput.isValid) {
                throw new Error(retriedOutput.refusalReason);
            }
            for (const [chunkIndex, chunk] of chunkBuffers(
                vector.exactOutputBytes,
            ).entries()) {
                expect(
                    retriedOutput.value.absorbChunk(chunkIndex, chunk),
                ).toEqual({ isValid: true, value: undefined });
            }
            expect(retriedOutput.value.finish().isValid).toBe(true);
            expect(retriedOutput.value.state()).toBe('completed');
        } finally {
            session.dispose();
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
            expect(openedOutput.value.state()).toBe('failed');
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

    it('rejects forged, cross-session, and wrong-domain substitutions', async () => {
        const session = openSession(kernel, vector);
        const otherKernel = await loadFreshTranscriptCoreKernel();
        const otherSession = openSession(otherKernel, vector);
        try {
            const reservation = verifyReservation(session, vector);
            if (!reservation.isValid) {
                throw new Error(reservation.refusalReason);
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

    it('binds the output intent to every exact streamed byte', () => {
        const changedOutputVector = createStateVerifierTestVector({
            targetReleaseOutputSeedByte: 0xd3,
        });
        expect(changedOutputVector.reservation.objectHash).toEqual(
            vector.reservation.objectHash,
        );
        expect(changedOutputVector.exactOutputBytes).not.toEqual(
            vector.exactOutputBytes,
        );
        const session = openSession(kernel, vector);
        try {
            const reservation = verifyReservation(session, vector);
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
                    changedOutputVector.exactOutputBytes,
                ),
                verifiedReservation: reservation.value,
            });
            if (!openedOutput.isValid) {
                throw new Error(openedOutput.refusalReason);
            }
            for (const [chunkIndex, chunk] of chunkBuffers(
                changedOutputVector.exactOutputBytes,
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
        for (const reservationOnly of vector.reservationOnly) {
            const session = openSession(kernel, vector);
            try {
                const reservation = session.verifyReservation({
                    canonicalReservationIntentCarrier:
                        reservationOnly.certifiedIntent.canonicalIntentCarrier,
                    canonicalStateCertificate:
                        reservationOnly.certifiedIntent
                            .canonicalStateCertificate,
                    capabilityKind: reservationOnly.capabilityKind,
                    expectedAuthorizationHash: vector.authorizationHash,
                    subjectParticipantIdentity:
                        vector.subjectParticipantIdentity,
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
        }
    });
});
