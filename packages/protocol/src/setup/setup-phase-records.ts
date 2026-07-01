import {
    canonicalJson,
    deriveCanonicalObjectHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    CanonicalSignedRootObject,
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    type JsonRecord,
} from './common-fields.js';
import type {
    CollectiveBgvSetupContext,
    ProtocolRootSigner,
} from './vss-share-verification-records.js';

export type SetupPhaseDescription = {
    readonly phaseId: string;
    readonly phaseNumber: number;
};

export type SetupPhaseParticipantObjectInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly phaseId: string;
    readonly phaseNumber: number;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly privateVssMailboxPublicKeyHash?: ProtocolHash;
    readonly privateVssMailboxPublicKeyBytesHash?: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
};

export type SetupPhaseParticipantObject = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPhaseParticipantObject';
        readonly objectVersion: 1;
        readonly phaseId: string;
        readonly phaseNumber: number;
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly signingPublicKeyHash: ProtocolHash;
        readonly privateVssMailboxPublicKeyHash?: ProtocolHash;
        readonly privateVssMailboxPublicKeyBytesHash?: ProtocolHash;
        readonly phaseObjectRoot: ProtocolHash;
        readonly phaseObjectByteLength: number;
        readonly phaseSignatureContextHash: ProtocolHash;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type SetupPhaseRecord = Readonly<
    JsonRecord & {
        readonly phaseId: string;
        readonly phaseNumber: number;
        readonly previousPhaseRoot: ProtocolHash | null;
        readonly participantPhaseObjects: readonly SetupPhaseParticipantObject[];
        readonly phaseRoot: ProtocolHash;
    }
>;

type SetupPhasePayload = Readonly<{
    readonly objectType: 'SetupPhaseParticipantObject';
    readonly objectVersion: 1;
    readonly phaseId: string;
    readonly phaseNumber: number;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly signerRole: 'Trustee';
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly privateVssMailboxPublicKeyHash?: ProtocolHash;
    readonly privateVssMailboxPublicKeyBytesHash?: ProtocolHash;
}>;

const textEncoder = new TextEncoder();

const canonicalByteLength = (value: unknown): number =>
    textEncoder.encode(canonicalJson(value)).byteLength;

const phasePayload = (
    input: Omit<SetupPhaseParticipantObjectInput, 'signRoot'>,
): SetupPhasePayload => {
    const payload = {
        objectType: 'SetupPhaseParticipantObject',
        objectVersion: 1,
        phaseId: input.phaseId,
        phaseNumber: input.phaseNumber,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        signerRole: 'Trustee',
        trusteeIdentity: input.trusteeIdentity,
        rosterPosition: input.rosterPosition,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        signingPublicKeyHash: input.signingPublicKeyHash,
    } satisfies SetupPhasePayload;

    return {
        ...payload,
        ...(input.privateVssMailboxPublicKeyHash === undefined
            ? {}
            : {
                  privateVssMailboxPublicKeyHash:
                      input.privateVssMailboxPublicKeyHash,
              }),
        ...(input.privateVssMailboxPublicKeyBytesHash === undefined
            ? {}
            : {
                  privateVssMailboxPublicKeyBytesHash:
                      input.privateVssMailboxPublicKeyBytesHash,
              }),
    };
};

const phaseSignatureContextHash = (
    input: Omit<SetupPhaseParticipantObjectInput, 'signRoot'>,
    phaseObjectRoot: ProtocolHash,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'SetupPhaseSignatureContext',
        phaseId: input.phaseId,
        phaseNumber: input.phaseNumber,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        trusteeIdentity: input.trusteeIdentity,
        rosterPosition: input.rosterPosition,
        phaseObjectRoot,
    });

const verifyGeneratedSignatureEnvelope = (
    signatureEnvelope: ProtocolSignatureEnvelope,
    signedRoot: CanonicalSignedRootObject,
    signingPublicKeyHash: ProtocolHash,
): void => {
    const result = verifySignedObjectSignature(signatureEnvelope, {
        objectType: signedRoot.objectType,
        objectVersion: signedRoot.objectVersion,
        signerRole: signedRoot.signerRole,
        signerIdentity: signedRoot.signerIdentity,
        ceremonyId: signedRoot.ceremonyId,
        publicKeyHash: signingPublicKeyHash,
        manifestHash: signedRoot.manifestHash,
        objectRoot: signedRoot.objectRoot,
        chunkMerkleRoot: signedRoot.chunkMerkleRoot,
        boardHeadHash: signedRoot.boardHeadHash,
        contextHash: signedRoot.contextHash,
        byteLength: signedRoot.byteLength,
        recoveryEpoch: signedRoot.recoveryEpoch,
        deviceEpoch: signedRoot.deviceEpoch,
    });
    if (!result.isValid) {
        const refusedObject = result.refusedObjects[0];
        throw new Error(
            refusedObject === undefined
                ? 'Setup phase participant signature envelope failed verification.'
                : `Setup phase participant signature envelope failed verification: ${refusedObject.code}: ${refusedObject.message}`,
        );
    }
    if (signatureEnvelope.signatureHash !== result.acceptedHashes[0]) {
        throw new Error(
            'Setup phase participant signature envelope hash does not match the verified signature hash.',
        );
    }
};

const sortedByRosterPosition = (
    participantPhaseObjects: readonly SetupPhaseParticipantObject[],
): SetupPhaseParticipantObject[] =>
    [...participantPhaseObjects].sort(
        (left, right) => left.rosterPosition - right.rosterPosition,
    );

const assertDistinctRosterPositions = (
    participantPhaseObjects: readonly SetupPhaseParticipantObject[],
): void => {
    const seenRosterPositions = new Set<number>();
    for (const participantPhaseObject of participantPhaseObjects) {
        if (seenRosterPositions.has(participantPhaseObject.rosterPosition)) {
            throw new Error(
                'Setup phase participant objects must have distinct roster positions.',
            );
        }
        seenRosterPositions.add(participantPhaseObject.rosterPosition);
    }
};

export const createSetupPhaseParticipantObject = async (
    input: SetupPhaseParticipantObjectInput,
): Promise<SetupPhaseParticipantObject> => {
    assertNonEmptyString(input.phaseId, 'phaseId');
    assertPositiveSafeInteger(input.phaseNumber, 'phaseNumber');
    assertNonEmptyString(input.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(input.rosterPosition, 'rosterPosition');
    assertNonNegativeSafeInteger(input.recoveryEpoch, 'recoveryEpoch');
    assertNonNegativeSafeInteger(input.deviceEpoch, 'deviceEpoch');
    if (
        input.phaseId === 'setupIntent' &&
        (input.privateVssMailboxPublicKeyHash === undefined ||
            input.privateVssMailboxPublicKeyBytesHash === undefined)
    ) {
        throw new Error(
            'setupIntent participant objects must bind private VSS mailbox public-key hashes.',
        );
    }

    const payload = phasePayload(input);
    const phaseObjectRoot = deriveCanonicalObjectHash(payload);
    const phaseObjectByteLength = canonicalByteLength(payload);
    const phaseSignatureContext = phaseSignatureContextHash(
        input,
        phaseObjectRoot,
    );
    const signedRoot = {
        objectType: 'SetupPhaseParticipantObject',
        objectVersion: 1,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        boardHeadHash: null,
        objectRoot: phaseObjectRoot,
        chunkMerkleRoot: null,
        byteLength: phaseObjectByteLength,
        signerRole: 'Trustee',
        signerIdentity: input.trusteeIdentity,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        contextHash: phaseSignatureContext,
    } as const satisfies CanonicalSignedRootObject;
    const signatureEnvelope = await input.signRoot(signedRoot);
    verifyGeneratedSignatureEnvelope(
        signatureEnvelope,
        signedRoot,
        input.signingPublicKeyHash,
    );

    return {
        ...payload,
        phaseObjectRoot,
        phaseObjectByteLength,
        phaseSignatureContextHash: phaseSignatureContext,
        signatureEnvelopeHash: signatureEnvelope.signatureHash,
        signatureEnvelope,
    } satisfies SetupPhaseParticipantObject;
};

export const createSetupPhaseRecord = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly phaseId: string;
    readonly phaseNumber: number;
    readonly previousPhaseRoot: ProtocolHash | null;
    readonly participantPhaseObjects: readonly SetupPhaseParticipantObject[];
}): SetupPhaseRecord => {
    assertNonEmptyString(input.phaseId, 'phaseId');
    assertPositiveSafeInteger(input.phaseNumber, 'phaseNumber');
    const participantPhaseObjects = sortedByRosterPosition(
        input.participantPhaseObjects,
    );
    assertDistinctRosterPositions(participantPhaseObjects);
    const phaseRecordWithoutRoot = {
        phaseId: input.phaseId,
        phaseNumber: input.phaseNumber,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        previousPhaseRoot: input.previousPhaseRoot,
        participantPhaseObjects,
    } as const satisfies JsonRecord;

    return {
        ...phaseRecordWithoutRoot,
        phaseRoot: deriveCanonicalObjectHash({
            objectType: 'SetupPhaseRecord',
            ...phaseRecordWithoutRoot,
        }),
    } satisfies SetupPhaseRecord;
};
