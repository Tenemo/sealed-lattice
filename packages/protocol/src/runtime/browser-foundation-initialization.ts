import {
    BrowserActionStorageCustodyError,
    foundationProfile,
    type BrowserActionStorageRootBinding,
    type BrowserFoundationInitializationPreparationInput,
    type BrowserFoundationInitializationWitnessInput,
    type BrowserFoundationWitnessProvisioningBinding,
    type WorkerBrowserFoundationInitializationPreparationInput,
    type WorkerPreparedBrowserFoundationInitialization,
} from '@sealed-lattice/types';

import type { PreparedBrowserFoundationInitialization } from './browser-action-storage-custody.js';

const foundationHashByteLength = 64;
const opaqueWorkerIdentifierPattern = /^[0-9a-f]{64}$/u;

type BrowserFoundationInitializationCommitMaterial = Readonly<{
    custodyBinding: BrowserActionStorageRootBinding;
    preparationInput: WorkerBrowserFoundationInitializationPreparationInput;
    workerPreparation: WorkerPreparedBrowserFoundationInitialization;
}>;

const preparedInitializationRecords = new WeakMap<
    object,
    BrowserFoundationInitializationCommitMaterial
>();

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

const copyExactBytes = (value: unknown, label: string): Uint8Array => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength !== foundationHashByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must contain exactly ${String(foundationHashByteLength)} bytes.`,
        );
    }
    return value.slice();
};

const copyEnvelope = (value: unknown, label: string): Uint8Array => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength === 0 ||
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be a nonempty Uint8Array within the browser copied-buffer limit.`,
        );
    }
    return value.slice();
};

const copyBinding = (
    binding: BrowserActionStorageRootBinding,
): BrowserActionStorageRootBinding =>
    Object.freeze({
        actionContextHash: copyExactBytes(
            binding?.actionContextHash,
            'Action-context hash',
        ),
        ceremonyContextHash: copyExactBytes(
            binding?.ceremonyContextHash,
            'Ceremony-context hash',
        ),
        participantId: copyExactBytes(
            binding?.participantId,
            'Participant identity',
        ),
        suiteId: copyExactBytes(binding?.suiteId, 'Suite identifier'),
    });

const copyWitnessInput = (
    value: BrowserFoundationInitializationWitnessInput,
    bindingIndex: number,
): BrowserFoundationInitializationWitnessInput =>
    Object.freeze({
        subjectParticipantIdentity: copyExactBytes(
            value?.subjectParticipantIdentity,
            `Witness binding ${String(bindingIndex)} subject participant identity`,
        ),
        witnessParticipantIdentity: copyExactBytes(
            value?.witnessParticipantIdentity,
            `Witness binding ${String(bindingIndex)} witness participant identity`,
        ),
    });

export const copyBrowserFoundationInitializationPreparationInput = (
    input: BrowserFoundationInitializationPreparationInput,
): BrowserFoundationInitializationPreparationInput => {
    if (
        typeof input !== 'object' ||
        input === null ||
        !Array.isArray(input.orderedWitnessBindings) ||
        input.orderedWitnessBindings.length !==
            foundationProfile.participantCount - 1 ||
        typeof input.actionRandomnessRecordContext !== 'object' ||
        input.actionRandomnessRecordContext === null ||
        input.actionRandomnessRecordContext.recordVersion !== 0n ||
        input.actionRandomnessRecordContext.predecessorRecordHash !== undefined
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `Fresh foundation initialization requires action-randomness version zero and exactly ${String(foundationProfile.participantCount - 1)} witness bindings.`,
        );
    }
    return Object.freeze({
        actionRandomnessRecordContext: Object.freeze({ recordVersion: 0n }),
        orderedWitnessBindings: Object.freeze(
            input.orderedWitnessBindings.map(copyWitnessInput),
        ),
        runtimeBuildManifestHash: copyExactBytes(
            input.runtimeBuildManifestHash,
            'Runtime build-manifest hash',
        ),
    });
};

const copyWorkerWitnessBinding = (
    value: BrowserFoundationWitnessProvisioningBinding,
    bindingIndex: number,
): BrowserFoundationWitnessProvisioningBinding =>
    copyWitnessInput(value, bindingIndex);

export const copyWorkerBrowserFoundationInitializationPreparationInput = (
    input: WorkerBrowserFoundationInitializationPreparationInput,
): WorkerBrowserFoundationInitializationPreparationInput => {
    const copiedPublicInput =
        copyBrowserFoundationInitializationPreparationInput(input);
    return Object.freeze({
        ...copiedPublicInput,
        orderedWitnessBindings: Object.freeze(
            input.orderedWitnessBindings.map(copyWorkerWitnessBinding),
        ),
    });
};

const copyWorkerPreparation = (
    value: WorkerPreparedBrowserFoundationInitialization,
): WorkerPreparedBrowserFoundationInitialization => {
    if (
        typeof value !== 'object' ||
        value === null ||
        typeof value.actionRandomness !== 'object' ||
        value.actionRandomness === null ||
        typeof value.actionRandomness.actionRandomnessSessionIdentifier !==
            'string' ||
        !opaqueWorkerIdentifierPattern.test(
            value.actionRandomness.actionRandomnessSessionIdentifier,
        ) ||
        !Array.isArray(value.witnessStateRecords) ||
        value.witnessStateRecords.length !==
            foundationProfile.participantCount - 1
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The worker returned malformed foundation-initialization material.',
        );
    }
    const seenPositions = new Set<number>();
    const localRecordIdentifierKeys = new Set<string>();
    const actionRandomnessLocalRecordIdentifier = copyExactBytes(
        value.actionRandomness.localRecordIdentifier,
        'Worker action-randomness local-record identifier',
    );
    localRecordIdentifierKeys.add(
        Array.from(actionRandomnessLocalRecordIdentifier, (byte) =>
            byte.toString(16).padStart(2, '0'),
        ).join(''),
    );
    const witnessStateRecords = (value.witnessStateRecords as unknown[]).map(
        (untrustedRecord, recordIndex) => {
            if (
                typeof untrustedRecord !== 'object' ||
                untrustedRecord === null
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker returned unordered foundation witness records.',
                );
            }
            const record = untrustedRecord as Record<string, unknown>;
            if (
                record.roleIndex !== recordIndex ||
                seenPositions.has(recordIndex)
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker returned unordered foundation witness records.',
                );
            }
            seenPositions.add(recordIndex);
            const localRecordIdentifier = copyExactBytes(
                record.localRecordIdentifier,
                `Worker witness local-record identifier ${String(recordIndex)}`,
            );
            const localRecordIdentifierKey = Array.from(
                localRecordIdentifier,
                (byte) => byte.toString(16).padStart(2, '0'),
            ).join('');
            if (localRecordIdentifierKeys.has(localRecordIdentifierKey)) {
                localRecordIdentifier.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The worker returned colliding foundation local-record identifiers.',
                );
            }
            localRecordIdentifierKeys.add(localRecordIdentifierKey);
            return Object.freeze({
                authorizedEmptyPlaintext: copyEnvelope(
                    record.authorizedEmptyPlaintext,
                    `Worker witness authorized-empty plaintext ${String(recordIndex)}`,
                ),
                canonicalEnvelope: copyEnvelope(
                    record.canonicalEnvelope,
                    `Worker witness envelope ${String(recordIndex)}`,
                ),
                envelopeHash: copyExactBytes(
                    record.envelopeHash,
                    `Worker witness envelope hash ${String(recordIndex)}`,
                ),
                localRecordIdentifier,
                roleIndex: recordIndex,
                stateKey: copyExactBytes(
                    record.stateKey,
                    `Worker witness state key ${String(recordIndex)}`,
                ),
            });
        },
    );
    return Object.freeze({
        actionRandomness: Object.freeze({
            actionRandomnessCommitment: copyExactBytes(
                value.actionRandomness.actionRandomnessCommitment,
                'Worker action-randomness commitment',
            ),
            actionRandomnessSessionIdentifier:
                value.actionRandomness.actionRandomnessSessionIdentifier,
            canonicalEnvelope: copyEnvelope(
                value.actionRandomness.canonicalEnvelope,
                'Worker action-randomness envelope',
            ),
            envelopeHash: copyExactBytes(
                value.actionRandomness.envelopeHash,
                'Worker action-randomness envelope hash',
            ),
            localRecordIdentifier: actionRandomnessLocalRecordIdentifier,
        }),
        witnessStateRecords: Object.freeze(witnessStateRecords),
    });
};

export const destroyWorkerPreparedBrowserFoundationInitialization = (
    preparation: WorkerPreparedBrowserFoundationInitialization,
): void => {
    preparation.actionRandomness.actionRandomnessCommitment.fill(0);
    preparation.actionRandomness.canonicalEnvelope.fill(0);
    preparation.actionRandomness.envelopeHash.fill(0);
    preparation.actionRandomness.localRecordIdentifier.fill(0);
    for (const record of preparation.witnessStateRecords) {
        record.authorizedEmptyPlaintext.fill(0);
        record.canonicalEnvelope.fill(0);
        record.envelopeHash.fill(0);
        record.localRecordIdentifier.fill(0);
        record.stateKey.fill(0);
    }
};

export const createPreparedBrowserFoundationInitialization = (input: {
    custodyBinding: BrowserActionStorageRootBinding;
    preparationInput: WorkerBrowserFoundationInitializationPreparationInput;
    workerPreparation: WorkerPreparedBrowserFoundationInitialization;
}): PreparedBrowserFoundationInitialization => {
    const custodyBinding = copyBinding(input.custodyBinding);
    const preparationInput =
        copyWorkerBrowserFoundationInitializationPreparationInput(
            input.preparationInput,
        );
    for (const [
        bindingIndex,
        witnessBinding,
    ] of preparationInput.orderedWitnessBindings.entries()) {
        if (
            !bytesEqual(
                witnessBinding.witnessParticipantIdentity,
                custodyBinding.participantId,
            ) ||
            bytesEqual(
                witnessBinding.subjectParticipantIdentity,
                custodyBinding.participantId,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                `Witness binding ${String(bindingIndex)} is not a distinct subject witnessed by the custody participant.`,
            );
        }
    }
    const workerPreparation = copyWorkerPreparation(input.workerPreparation);
    const prepared = Object.freeze(
        {},
    ) as PreparedBrowserFoundationInitialization;
    preparedInitializationRecords.set(prepared, {
        custodyBinding,
        preparationInput,
        workerPreparation,
    });
    return prepared;
};

export const takePreparedBrowserFoundationInitializationForAuthenticatedCommit =
    (
        prepared: PreparedBrowserFoundationInitialization,
    ): BrowserFoundationInitializationCommitMaterial => {
        const record = preparedInitializationRecords.get(prepared);
        if (record === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The prepared foundation initialization is unavailable or already consumed.',
            );
        }
        preparedInitializationRecords.delete(prepared);
        return record;
    };
