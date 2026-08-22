import { readFileSync } from 'node:fs';

import {
    foundationProfile,
    stateCapabilityKinds,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';

import { createBrowserLocalSigningOperations } from '#packages/crypto/tests/support/browser-local-key-operations';
import {
    createCanonicalCarrierMailboxKeyPairFixtures,
    createCanonicalCarrierSigningKeyPairFixtures,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    foundationObjectTypes,
    openCanonicalBoardVerifierSession,
    type CanonicalBoardVerifierSession,
    type FoundationObjectType,
    type VerifiedTranscriptObject,
} from '#packages/wasm/src/canonical-board-runtime';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
    type ClosedWorkerSetupMailboxRandomnessOperations,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    closeWorkerActionRandomness,
    createAndSealWorkerActionRandomness,
    openClosedWorkerSetupMailboxRandomness,
} from '#packages/wasm/src/local-storage-root-worker-kernel';
import type { ClosedWorkerProductionOperationIdentifiers } from '#packages/wasm/src/local-storage-root-worker-kernel/authorities';
import { createCanonicalBoardContextTestInput } from '#packages/wasm/tests/canonical-board-context-test-vector';
import {
    createStateVerifierTestVector,
    deriveSetupActionRandomnessAuthorization,
} from '#packages/wasm/tests/state-verifier-test-vectors';

const compactCandidateSuiteRecordUrl = new URL(
    './compact-candidate-suite-record.hex',
    import.meta.url,
);

const loadCompactCandidateSuiteRecord = (): Uint8Array<ArrayBuffer> => {
    const hexadecimalBytes = readFileSync(
        compactCandidateSuiteRecordUrl,
        'utf8',
    ).trim();
    if (
        hexadecimalBytes.length === 0 ||
        hexadecimalBytes.length % 2 !== 0 ||
        !/^[0-9a-f]+$/u.test(hexadecimalBytes)
    ) {
        throw new Error(
            'The retained compact candidate suite record is not canonical lowercase hexadecimal.',
        );
    }
    return Uint8Array.from(
        hexadecimalBytes.match(/.{2}/gu) ?? [],
        (hexadecimalByte) => Number.parseInt(hexadecimalByte, 16),
    );
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

const failureMessage = (failure: unknown): string =>
    failure instanceof Error
        ? `${failure.name}: ${failure.message}`
        : 'non-error failure';

class CompactPublicKeyProductionFixtureCleanupError extends Error {
    public override readonly name =
        'CompactPublicKeyProductionFixtureCleanupError';

    public constructor(
        public readonly cleanupFailures: readonly unknown[],
        public readonly operationFailure?: unknown,
    ) {
        super(
            operationFailure === undefined
                ? `The compact public-key production fixture could not release every participant authority: ${cleanupFailures.map(failureMessage).join('; ')}.`
                : `The compact public-key production fixture failed (${failureMessage(operationFailure)}) and could not release every participant authority: ${cleanupFailures.map(failureMessage).join('; ')}.`,
        );
    }
}

const combineCleanupFailures = (
    operationFailure: unknown,
    cleanupFailures: readonly unknown[],
): never => {
    throw new CompactPublicKeyProductionFixtureCleanupError(
        Object.freeze([...cleanupFailures]),
        operationFailure,
    );
};

type CompactPublicKeyParticipantFixture = Readonly<{
    close(): Promise<void>;
    productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    setupRandomness: ClosedWorkerSetupMailboxRandomnessOperations;
    workerKernel: BrowserActionStorageWorkerKernel;
}>;

const openParticipantFixture = async (input: {
    actionContextHash: Uint8Array;
    ceremonyContextHash: Uint8Array;
    kernel: TranscriptCoreKernel;
    mailboxEncapsulationKey: Uint8Array;
    rosterPosition: number;
    signingOperations: ReturnType<typeof createBrowserLocalSigningOperations>;
    suiteIdentifier: Uint8Array;
}): Promise<CompactPublicKeyParticipantFixture> => {
    const baseStateVector = createStateVerifierTestVector({
        actionContextHash: input.actionContextHash,
        ceremonyContextHash: input.ceremonyContextHash,
        subjectRosterPosition: input.rosterPosition,
        suiteIdentifier: input.suiteIdentifier,
    });
    const workerKernel = createWasmBrowserActionStorageWorkerKernel({
        kernel: input.kernel,
    });
    let actionRandomnessSessionIdentifier: string | undefined;
    let stateVerifierSessionIdentifier: string | undefined;
    let setupRandomness:
        | ClosedWorkerSetupMailboxRandomnessOperations
        | undefined;
    let storageRootActive = false;
    try {
        const stagedStorageRoot =
            await workerKernel.createAndStageDeviceWrappingState({
                binding: {
                    actionContextHash: input.actionContextHash,
                    ceremonyContextHash: input.ceremonyContextHash,
                    participantId: baseStateVector.subjectParticipantIdentity,
                    suiteId: input.suiteIdentifier,
                },
            });
        try {
            await workerKernel.commitStagedActionStorageRoot();
            storageRootActive = true;
        } finally {
            stagedStorageRoot.storageRootCommitment.fill(0);
            stagedStorageRoot.wrappedStorageRoot.fill(0);
        }

        const actionRandomness = await createAndSealWorkerActionRandomness(
            workerKernel,
            { recordVersion: 0n },
        );
        actionRandomnessSessionIdentifier =
            actionRandomness.actionRandomnessSessionIdentifier;
        const stateVector = createStateVerifierTestVector({
            actionContextHash: input.actionContextHash,
            ceremonyContextHash: input.ceremonyContextHash,
            setupActionRandomnessAuthorizationHash:
                deriveSetupActionRandomnessAuthorization(
                    baseStateVector,
                    actionRandomness.actionRandomnessCommitment,
                ),
            subjectRosterPosition: input.rosterPosition,
            suiteIdentifier: input.suiteIdentifier,
        });
        const openedStateVerifierSession =
            await workerKernel.openActionStateVerifierSession({
                canonicalRosterBytes: stateVector.canonicalRosterBytes,
            });
        if (!openedStateVerifierSession.isValid) {
            throw new Error(
                `Participant ${String(input.rosterPosition)} state-verifier session was refused: ${openedStateVerifierSession.refusalReason}.`,
            );
        }
        stateVerifierSessionIdentifier = openedStateVerifierSession.value;
        const setupReservation = stateVector.reservationOnly.find(
            ({ capabilityKind }) =>
                capabilityKind ===
                stateCapabilityKinds.setupActionRandomnessRoot,
        );
        if (setupReservation === undefined) {
            throw new Error(
                `Participant ${String(input.rosterPosition)} has no setup action-randomness reservation.`,
            );
        }
        const verifiedReservation =
            await workerKernel.verifyActionRandomnessReservation({
                actionRandomnessSessionIdentifier,
                canonicalReservationIntentCarrier:
                    setupReservation.certifiedIntent.canonicalIntentCarrier,
                canonicalStateCertificate:
                    setupReservation.certifiedIntent.canonicalStateCertificate,
                stateVerifierSessionIdentifier,
            });
        if (!verifiedReservation.isValid) {
            throw new Error(
                `Participant ${String(input.rosterPosition)} setup reservation was refused: ${verifiedReservation.refusalReason}.`,
            );
        }
        setupRandomness = await openClosedWorkerSetupMailboxRandomness(
            workerKernel,
            {
                actionRandomnessSessionIdentifier,
                signing: input.signingOperations,
                sourceMailboxEncapsulationKey: input.mailboxEncapsulationKey,
                stateReservationIdentifier: verifiedReservation.value,
            },
        );
        let closed = false;
        return Object.freeze({
            close: async (): Promise<void> => {
                if (closed) {
                    return;
                }
                closed = true;
                const cleanupFailures: unknown[] = [];
                try {
                    setupRandomness?.revoke();
                } catch (error) {
                    cleanupFailures.push(error);
                }
                if (stateVerifierSessionIdentifier !== undefined) {
                    try {
                        await workerKernel.closeActionStateVerifierSession(
                            stateVerifierSessionIdentifier,
                        );
                    } catch (error) {
                        cleanupFailures.push(error);
                    }
                }
                if (actionRandomnessSessionIdentifier !== undefined) {
                    try {
                        await closeWorkerActionRandomness(
                            workerKernel,
                            actionRandomnessSessionIdentifier,
                        );
                    } catch (error) {
                        cleanupFailures.push(error);
                    }
                }
                if (storageRootActive) {
                    try {
                        await workerKernel.destroyActiveActionStorageRoot();
                    } catch (error) {
                        cleanupFailures.push(error);
                    }
                }
                input.signingOperations.revoke();
                if (cleanupFailures.length > 0) {
                    throw new CompactPublicKeyProductionFixtureCleanupError(
                        Object.freeze([...cleanupFailures]),
                    );
                }
            },
            productionOperationIdentifiers: Object.freeze({
                actionRandomnessSessionIdentifier,
                stateReservationIdentifier: verifiedReservation.value,
                stateVerifierSessionIdentifier,
            }),
            setupRandomness,
            workerKernel,
        });
    } catch (operationFailure) {
        const cleanupFailures: unknown[] = [];
        try {
            setupRandomness?.revoke();
        } catch (error) {
            cleanupFailures.push(error);
        }
        if (stateVerifierSessionIdentifier !== undefined) {
            try {
                await workerKernel.closeActionStateVerifierSession(
                    stateVerifierSessionIdentifier,
                );
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (actionRandomnessSessionIdentifier !== undefined) {
            try {
                await closeWorkerActionRandomness(
                    workerKernel,
                    actionRandomnessSessionIdentifier,
                );
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (storageRootActive) {
            try {
                await workerKernel.destroyActiveActionStorageRoot();
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        input.signingOperations.revoke();
        if (cleanupFailures.length > 0) {
            combineCleanupFailures(operationFailure, cleanupFailures);
        }
        throw operationFailure;
    }
};

const verifyAndOrderCarrierFamily = (
    boardVerifierSession: CanonicalBoardVerifierSession,
    canonicalCarriers: readonly Uint8Array[],
    expectedObjectType: FoundationObjectType,
): readonly VerifiedTranscriptObject[] => {
    const verification = boardVerifierSession.verifyUnorderedCarriers(
        canonicalCarriers.map((canonicalCarrier) => ({ canonicalCarrier })),
    );
    if (!verification.isValid) {
        throw new Error(
            `The canonical board refused a compact public-key prerequisite family: ${verification.refusalReason}.`,
        );
    }
    if (verification.value.length !== canonicalCarriers.length) {
        throw new Error(
            'The canonical board returned the wrong compact public-key prerequisite count.',
        );
    }
    const unclaimedObjects = new Set(verification.value);
    const orderedObjects = canonicalCarriers.map((canonicalCarrier) => {
        for (const verifiedObject of unclaimedObjects) {
            const copiedCarrier =
                boardVerifierSession.copyCachedCarrier(verifiedObject);
            if (!copiedCarrier.isValid) {
                throw new Error(
                    `The canonical board could not copy a verified prerequisite: ${copiedCarrier.refusalReason}.`,
                );
            }
            const matches = bytesEqual(copiedCarrier.value, canonicalCarrier);
            copiedCarrier.value.fill(0);
            if (!matches) {
                continue;
            }
            const description = boardVerifierSession.describe(verifiedObject);
            if (!description.isValid) {
                throw new Error(
                    `The canonical board could not describe a verified prerequisite: ${description.refusalReason}.`,
                );
            }
            if (description.value.objectType !== expectedObjectType) {
                throw new Error(
                    'The canonical board returned a prerequisite of the wrong object type.',
                );
            }
            unclaimedObjects.delete(verifiedObject);
            return verifiedObject;
        }
        throw new Error(
            'The canonical board omitted one exact compact public-key prerequisite carrier.',
        );
    });
    if (unclaimedObjects.size !== 0) {
        throw new Error(
            'The canonical board returned an unowned compact public-key prerequisite.',
        );
    }
    return Object.freeze(orderedObjects);
};

type CompactPublicKeyProductionGenerationFixture = Readonly<{
    canonicalSuiteRecordBytes: Uint8Array<ArrayBuffer>;
    close(): Promise<void>;
    kernel: TranscriptCoreKernel;
    orderedPublicRandomnessCommitmentObjects: readonly VerifiedTranscriptObject[];
    orderedPublicRandomnessRevealObjects: readonly VerifiedTranscriptObject[];
    orderedSetupIntentObjects: readonly VerifiedTranscriptObject[];
    productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    setupIntentObject: VerifiedTranscriptObject;
    workerKernel: BrowserActionStorageWorkerKernel;
}>;

type CompactPublicKeyParticipantClientFixture = Readonly<{
    boardVerifierSession: CanonicalBoardVerifierSession;
    kernel: TranscriptCoreKernel;
    participant: CompactPublicKeyParticipantFixture;
}>;

/**
 * Constructs the exact ten-member setup prerequisite chain in ten isolated
 * scalar WASM instances. Carrier bytes cross clients only through canonical
 * board verification; private randomness and state authority remain owned by
 * the producing participant instance.
 */
export const openCompactPublicKeyProductionGenerationFixture =
    async (): Promise<CompactPublicKeyProductionGenerationFixture> => {
        const kernel = await loadFreshTranscriptCoreKernel();
        const initialStateVector = createStateVerifierTestVector();
        const canonicalSuiteRecordBytes: Uint8Array<ArrayBuffer> =
            loadCompactCandidateSuiteRecord();
        const boardContext = createCanonicalBoardContextTestInput(
            kernel,
            initialStateVector.canonicalRosterBytes,
            canonicalSuiteRecordBytes,
        );
        const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
            foundationProfile.participantCount,
        );
        const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
            foundationProfile.participantCount,
        );
        const participantClients: CompactPublicKeyParticipantClientFixture[] =
            [];
        try {
            for (
                let rosterPosition = 0;
                rosterPosition < foundationProfile.participantCount;
                rosterPosition += 1
            ) {
                const signingKeyPair = signingKeyPairs[rosterPosition];
                const mailboxKeyPair = mailboxKeyPairs[rosterPosition];
                if (
                    signingKeyPair === undefined ||
                    mailboxKeyPair === undefined
                ) {
                    throw new Error(
                        `The deterministic participant key fixture omitted roster position ${String(rosterPosition)}.`,
                    );
                }
                const participantKernel =
                    rosterPosition === 0
                        ? kernel
                        : await loadFreshTranscriptCoreKernel();
                const participantBoardContext =
                    createCanonicalBoardContextTestInput(
                        participantKernel,
                        initialStateVector.canonicalRosterBytes,
                        canonicalSuiteRecordBytes,
                    );
                if (
                    !bytesEqual(
                        participantBoardContext.expectedSuiteIdentifier,
                        boardContext.expectedSuiteIdentifier,
                    ) ||
                    !bytesEqual(
                        participantBoardContext.expectedCeremonyContextHash,
                        boardContext.expectedCeremonyContextHash,
                    ) ||
                    !bytesEqual(
                        participantBoardContext.expectedActionContextHash,
                        boardContext.expectedActionContextHash,
                    )
                ) {
                    throw new Error(
                        `Participant ${String(rosterPosition)} reconstructed a different canonical board context.`,
                    );
                }
                const openedBoardSession = openCanonicalBoardVerifierSession({
                    contextInput: participantBoardContext,
                    kernel: participantKernel,
                });
                if (!openedBoardSession.isValid) {
                    throw new Error(
                        `Participant ${String(rosterPosition)} canonical board was refused: ${openedBoardSession.refusalReason}.`,
                    );
                }
                try {
                    const participant = await openParticipantFixture({
                        actionContextHash:
                            boardContext.expectedActionContextHash,
                        ceremonyContextHash:
                            boardContext.expectedCeremonyContextHash,
                        kernel: participantKernel,
                        mailboxEncapsulationKey: mailboxKeyPair.publicKey,
                        rosterPosition,
                        signingOperations:
                            createBrowserLocalSigningOperations(signingKeyPair),
                        suiteIdentifier: boardContext.expectedSuiteIdentifier,
                    });
                    participantClients.push(
                        Object.freeze({
                            boardVerifierSession: openedBoardSession.value,
                            kernel: participantKernel,
                            participant,
                        }),
                    );
                } catch (error) {
                    openedBoardSession.value.close();
                    throw error;
                }
            }
            for (const signingKeyPair of signingKeyPairs) {
                signingKeyPair.secretKey.fill(0);
            }
            for (const mailboxKeyPair of mailboxKeyPairs) {
                mailboxKeyPair.secretKey.fill(0);
            }

            const setupIntentCarriers = participantClients.map(
                ({ participant }) =>
                    participant.setupRandomness.produceSetupIntentCarrier(),
            );
            const orderedSetupIntentObjectsByClient = participantClients.map(
                ({ boardVerifierSession }) =>
                    verifyAndOrderCarrierFamily(
                        boardVerifierSession,
                        setupIntentCarriers,
                        foundationObjectTypes.setupIntent,
                    ),
            );
            const publicRandomnessCommitmentCarriers = participantClients.map(
                ({ participant }, rosterPosition) => {
                    const orderedSetupIntentObjects =
                        orderedSetupIntentObjectsByClient[rosterPosition];
                    if (orderedSetupIntentObjects === undefined) {
                        throw new Error(
                            `Participant ${String(rosterPosition)} has no verified setup-intent catalog.`,
                        );
                    }
                    return participant.setupRandomness.producePublicRandomnessCommitmentCarrier(
                        { orderedSetupIntentObjects },
                    );
                },
            );
            const orderedPublicRandomnessCommitmentObjectsByClient =
                participantClients.map(({ boardVerifierSession }) =>
                    verifyAndOrderCarrierFamily(
                        boardVerifierSession,
                        publicRandomnessCommitmentCarriers,
                        foundationObjectTypes.publicRandomnessCommitment,
                    ),
                );
            const publicRandomnessRevealCarriers = participantClients.map(
                ({ participant }, rosterPosition) => {
                    const orderedSetupIntentObjects =
                        orderedSetupIntentObjectsByClient[rosterPosition];
                    const orderedPublicRandomnessCommitmentObjects =
                        orderedPublicRandomnessCommitmentObjectsByClient[
                            rosterPosition
                        ];
                    const setupIntentObject =
                        orderedSetupIntentObjects?.[rosterPosition];
                    const publicRandomnessCommitmentObject =
                        orderedPublicRandomnessCommitmentObjects?.[
                            rosterPosition
                        ];
                    if (
                        setupIntentObject === undefined ||
                        publicRandomnessCommitmentObject === undefined
                    ) {
                        throw new Error(
                            `The ordered public-randomness catalog omitted roster position ${String(rosterPosition)}.`,
                        );
                    }
                    return participant.setupRandomness.producePublicRandomnessRevealCarrier(
                        {
                            publicRandomnessCommitmentObject,
                            setupIntentObject,
                        },
                    );
                },
            );
            const subjectClient = participantClients[0];
            const orderedSetupIntentObjects =
                orderedSetupIntentObjectsByClient[0];
            const orderedPublicRandomnessCommitmentObjects =
                orderedPublicRandomnessCommitmentObjectsByClient[0];
            if (
                subjectClient === undefined ||
                orderedSetupIntentObjects === undefined ||
                orderedPublicRandomnessCommitmentObjects === undefined
            ) {
                throw new Error(
                    'The compact public-key fixture has no subject participant catalog.',
                );
            }
            const orderedPublicRandomnessRevealObjects =
                verifyAndOrderCarrierFamily(
                    subjectClient.boardVerifierSession,
                    publicRandomnessRevealCarriers,
                    foundationObjectTypes.publicRandomnessReveal,
                );
            const subjectParticipant = subjectClient.participant;
            const setupIntentObject = orderedSetupIntentObjects[0];
            if (setupIntentObject === undefined) {
                throw new Error(
                    'The compact public-key fixture has no subject participant.',
                );
            }
            let closed = false;
            return Object.freeze({
                canonicalSuiteRecordBytes,
                close: async (): Promise<void> => {
                    if (closed) {
                        return;
                    }
                    closed = true;
                    const cleanupFailures: unknown[] = [];
                    for (const client of participantClients.slice().reverse()) {
                        try {
                            client.boardVerifierSession.close();
                        } catch (error) {
                            cleanupFailures.push(error);
                        }
                        try {
                            await client.participant.close();
                        } catch (error) {
                            cleanupFailures.push(error);
                        }
                    }
                    if (cleanupFailures.length > 0) {
                        throw new CompactPublicKeyProductionFixtureCleanupError(
                            Object.freeze([...cleanupFailures]),
                        );
                    }
                },
                kernel,
                orderedPublicRandomnessCommitmentObjects,
                orderedPublicRandomnessRevealObjects,
                orderedSetupIntentObjects,
                productionOperationIdentifiers:
                    subjectParticipant.productionOperationIdentifiers,
                setupIntentObject,
                workerKernel: subjectParticipant.workerKernel,
            });
        } catch (operationFailure) {
            const cleanupFailures: unknown[] = [];
            for (const client of participantClients.slice().reverse()) {
                try {
                    client.boardVerifierSession.close();
                } catch (error) {
                    cleanupFailures.push(error);
                }
                try {
                    await client.participant.close();
                } catch (error) {
                    cleanupFailures.push(error);
                }
            }
            for (const signingKeyPair of signingKeyPairs) {
                signingKeyPair.secretKey.fill(0);
            }
            for (const mailboxKeyPair of mailboxKeyPairs) {
                mailboxKeyPair.secretKey.fill(0);
            }
            if (cleanupFailures.length > 0) {
                combineCleanupFailures(operationFailure, cleanupFailures);
            }
            throw operationFailure;
        }
    };
