import {
    BrowserActionStorageCustodyError,
    refusalReasonCodes,
    stateCapabilityKinds,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserOpenedActionRandomnessSession,
    type BrowserSealedActionRandomnessSession,
    type BrowserTargetReleaseAttemptInput,
    type RefusalReason,
    type StateCapabilityKind,
    type VerificationResult,
} from '@sealed-lattice/types';

const foundationHashByteLength = 64;
const attemptIdentifierByteLength = 32;
const maximumCanonicalMaterialByteLength = 1_572_864;
const opaqueWorkerIdentifierPattern = /^[0-9a-f]{64}$/u;

const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return false;
    }
    const prototype = Reflect.getPrototypeOf(value);

    return prototype === Object.prototype || prototype === null;
};

const copyBytes = (
    value: unknown,
    label: string,
    exactByteLength?: number,
): Uint8Array => {
    if (
        !(value instanceof Uint8Array) ||
        (exactByteLength === undefined
            ? value.byteLength === 0 ||
              value.byteLength > maximumCanonicalMaterialByteLength
            : value.byteLength !== exactByteLength)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            exactByteLength === undefined
                ? `${label} has an unsupported length.`
                : `${label} must contain exactly ${exactByteLength} bytes.`,
        );
    }

    return value.slice();
};

const copyUnsignedInteger = (
    value: unknown,
    maximum: number,
    label: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > maximum
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} is outside its supported unsigned integer range.`,
        );
    }

    return value;
};

const copyUnsigned64 = (value: unknown, label: string): bigint => {
    if (
        typeof value !== 'bigint' ||
        value < 0n ||
        value > 0xffff_ffff_ffff_ffffn
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be an unsigned 64-bit integer.`,
        );
    }

    return value;
};

const copyCapabilityKind = (value: unknown): StateCapabilityKind => {
    if (
        typeof value !== 'number' ||
        !Object.values(stateCapabilityKinds).includes(
            value as StateCapabilityKind,
        )
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The state capability kind is unassigned.',
        );
    }

    return value as StateCapabilityKind;
};

export const copyOpaqueWorkerIdentifier = (
    value: unknown,
    label: string,
): string => {
    if (
        typeof value !== 'string' ||
        !opaqueWorkerIdentifierPattern.test(value)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} is malformed.`,
        );
    }

    return value;
};

export const copyActionStateVerifierSessionInput = (
    value: unknown,
): BrowserActionStateVerifierSessionInput => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action state-verifier session input is malformed.',
        );
    }

    return Object.freeze({
        canonicalRosterBytes: copyBytes(
            value.canonicalRosterBytes,
            'Canonical roster bytes',
        ),
    });
};

export const copyActionStateReservationVerificationInput = (
    value: unknown,
): BrowserActionStateReservationVerificationInput => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action state-reservation verification input is malformed.',
        );
    }

    return Object.freeze({
        canonicalReservationIntentCarrier: copyBytes(
            value.canonicalReservationIntentCarrier,
            'Canonical state-reservation intent carrier',
        ),
        canonicalStateCertificate: copyBytes(
            value.canonicalStateCertificate,
            'Canonical state certificate',
        ),
        capabilityKind: copyCapabilityKind(value.capabilityKind),
        expectedAuthorizationHash: copyBytes(
            value.expectedAuthorizationHash,
            'Expected state authorization hash',
            foundationHashByteLength,
        ),
        stateVerifierSessionIdentifier: copyOpaqueWorkerIdentifier(
            value.stateVerifierSessionIdentifier,
            'State-verifier session identifier',
        ),
        subjectParticipantIdentity: copyBytes(
            value.subjectParticipantIdentity,
            'State subject participant identity',
            foundationHashByteLength,
        ),
    });
};

export const copyActionRandomnessReservationVerificationInput = (
    value: unknown,
): BrowserActionRandomnessReservationVerificationInput => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action-randomness reservation verification input is malformed.',
        );
    }

    return Object.freeze({
        actionRandomnessSessionIdentifier: copyOpaqueWorkerIdentifier(
            value.actionRandomnessSessionIdentifier,
            'Action-randomness session identifier',
        ),
        canonicalReservationIntentCarrier: copyBytes(
            value.canonicalReservationIntentCarrier,
            'Canonical action-randomness reservation intent carrier',
        ),
        canonicalStateCertificate: copyBytes(
            value.canonicalStateCertificate,
            'Canonical state certificate',
        ),
        stateVerifierSessionIdentifier: copyOpaqueWorkerIdentifier(
            value.stateVerifierSessionIdentifier,
            'State-verifier session identifier',
        ),
    });
};

const copyActionRandomnessRecordContext = (
    value: unknown,
): BrowserActionRandomnessRecordContext => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action-randomness record context is malformed.',
        );
    }
    const recordVersion = copyUnsigned64(
        value.recordVersion,
        'Action-randomness record version',
    );
    const predecessorRecordHash =
        value.predecessorRecordHash === undefined
            ? undefined
            : copyBytes(
                  value.predecessorRecordHash,
                  'Action-randomness predecessor record hash',
                  foundationHashByteLength,
              );
    if ((recordVersion === 0n) !== (predecessorRecordHash === undefined)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Action-randomness predecessor presence must match the record version.',
        );
    }

    return Object.freeze({
        predecessorRecordHash,
        recordVersion,
    });
};

export const copyCreateAndSealActionRandomnessInput = (
    value: unknown,
): BrowserActionRandomnessRecordContext => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The create-and-seal action-randomness input is malformed.',
        );
    }

    return copyActionRandomnessRecordContext(value);
};

export const copyOpenSealedActionRandomnessInput = (
    value: unknown,
): BrowserActionRandomnessRecordContext &
    Readonly<{
        actionRandomnessCommitment: Uint8Array;
        canonicalEnvelope: Uint8Array;
    }> => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The sealed action-randomness opening input is malformed.',
        );
    }

    return Object.freeze({
        ...copyActionRandomnessRecordContext(value),
        actionRandomnessCommitment: copyBytes(
            value.actionRandomnessCommitment,
            'Action-randomness commitment',
            foundationHashByteLength,
        ),
        canonicalEnvelope: copyBytes(
            value.canonicalEnvelope,
            'Sealed action-randomness envelope',
        ),
    });
};

export const copyTargetReleaseAttemptInput = (
    value: unknown,
): BrowserTargetReleaseAttemptInput => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The target-release attempt input is malformed.',
        );
    }

    return Object.freeze({
        actionRandomnessSessionIdentifier: copyOpaqueWorkerIdentifier(
            value.actionRandomnessSessionIdentifier,
            'Action-randomness session identifier',
        ),
        rosterPosition: copyUnsignedInteger(
            value.rosterPosition,
            0xffff,
            'Target-release roster position',
        ),
        stateReservationIdentifier: copyOpaqueWorkerIdentifier(
            value.stateReservationIdentifier,
            'State-reservation identifier',
        ),
    });
};

export const copyWorkerIdentifierVerificationResult = (
    value: unknown,
): VerificationResult<string> => {
    if (!isPlainRecord(value) || typeof value.isValid !== 'boolean') {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed verification result.',
        );
    }
    if (value.isValid) {
        return Object.freeze({
            isValid: true,
            value: copyOpaqueWorkerIdentifier(
                value.value,
                'Worker-issued identifier',
            ),
        });
    }
    if (
        typeof value.refusalReason !== 'string' ||
        !Object.prototype.hasOwnProperty.call(
            refusalReasonCodes,
            value.refusalReason,
        )
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned an unassigned refusal reason.',
        );
    }

    return Object.freeze({
        isValid: false,
        refusalReason: value.refusalReason as RefusalReason,
    });
};

export const copySealedActionRandomnessSession = (
    value: unknown,
): BrowserSealedActionRandomnessSession => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned malformed sealed action-randomness metadata.',
        );
    }

    return Object.freeze({
        actionRandomnessCommitment: copyBytes(
            value.actionRandomnessCommitment,
            'Action-randomness commitment',
            foundationHashByteLength,
        ),
        actionRandomnessSessionIdentifier: copyOpaqueWorkerIdentifier(
            value.actionRandomnessSessionIdentifier,
            'Action-randomness session identifier',
        ),
        canonicalEnvelope: copyBytes(
            value.canonicalEnvelope,
            'Sealed action-randomness envelope',
        ),
    });
};

export const copyOpenedActionRandomnessSession = (
    value: unknown,
): BrowserOpenedActionRandomnessSession => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned malformed opened action-randomness metadata.',
        );
    }

    return Object.freeze({
        actionRandomnessCommitment: copyBytes(
            value.actionRandomnessCommitment,
            'Action-randomness commitment',
            foundationHashByteLength,
        ),
        actionRandomnessSessionIdentifier: copyOpaqueWorkerIdentifier(
            value.actionRandomnessSessionIdentifier,
            'Action-randomness session identifier',
        ),
    });
};

export const copyActionProofAttemptBinding = (
    value: unknown,
): BrowserActionProofAttemptBinding => {
    if (!isPlainRecord(value)) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned malformed proof-attempt metadata.',
        );
    }

    return Object.freeze({
        applicationSlotHash: copyBytes(
            value.applicationSlotHash,
            'Application-slot hash',
            foundationHashByteLength,
        ),
        attemptIdentifier: copyBytes(
            value.attemptIdentifier,
            'Proof attempt identifier',
            attemptIdentifierByteLength,
        ),
    });
};
