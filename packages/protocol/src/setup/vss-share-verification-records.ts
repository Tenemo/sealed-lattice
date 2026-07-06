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
    assertContextMatches,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    type JsonRecord,
} from './common-fields.js';
import type { PrivateVssEnvelopeCommitment } from './private-vss-mailbox-delivery.js';

export type CollectiveBgvSetupContext = Readonly<
    JsonRecord & {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
        readonly setupEpoch: string;
    }
>;

export type PrivateVssEnvelopeVerificationReference = Readonly<
    PrivateVssEnvelopeCommitment & {
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    }
>;

export type ProtocolRootSigner = (
    signedRoot: CanonicalSignedRootObject,
) => ProtocolSignatureEnvelope | Promise<ProtocolSignatureEnvelope>;

export type VssShareAcceptanceRecordInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly envelopeReference: PrivateVssEnvelopeVerificationReference;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
};

export type VssShareComplaintRecordInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly envelopeReference: PrivateVssEnvelopeVerificationReference;
    readonly complaintEvidenceRoot: ProtocolHash;
    readonly complaintReasonCode: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
};

export type PrivateVssLocalVerificationFailure = Readonly<{
    readonly isValid: false;
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }>[];
}>;

export type VssShareComplaintFromLocalVerificationInput = Omit<
    VssShareComplaintRecordInput,
    'complaintEvidenceRoot' | 'complaintReasonCode'
> & {
    readonly localVerification: PrivateVssLocalVerificationFailure;
};

export type VssShareAcceptanceRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssShareAcceptance';
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly localVerificationRoot: ProtocolHash;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly signingPublicKeyHash: ProtocolHash;
        readonly acceptanceRoot: ProtocolHash;
        readonly acceptanceByteLength: number;
        readonly acceptanceContextHash: ProtocolHash;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type VssShareComplaintRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssShareComplaint';
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly complaintEvidenceRoot: ProtocolHash;
        readonly complaintReasonCode: string;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly signingPublicKeyHash: ProtocolHash;
        readonly complaintRoot: ProtocolHash;
        readonly complaintByteLength: number;
        readonly complaintContextHash: ProtocolHash;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type VssShareAcceptanceSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssShareAcceptanceSet';
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly acceptanceRecords: readonly VssShareAcceptanceRecord[];
        readonly vssShareAcceptanceRoot: ProtocolHash;
    }
>;

export type VssComplaintSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssComplaintSet';
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly complaintRecords: readonly VssShareComplaintRecord[];
        readonly vssComplaintRoot: ProtocolHash;
    }
>;

type VssShareVerificationPayloadFields = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly privateEnvelopeHash: ProtocolHash;
}>;

const textEncoder = new TextEncoder();

const canonicalByteLength = (value: unknown): number =>
    textEncoder.encode(canonicalJson(value)).byteLength;

const signatureFailureMessage = (
    recordLabel: string,
    refusedObject: { readonly code: string; readonly message: string },
): string =>
    `${recordLabel} signature envelope failed verification: ${refusedObject.code}: ${refusedObject.message}`;

const verifyGeneratedSignatureEnvelope = (
    recordLabel: string,
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
                ? `${recordLabel} signature envelope failed verification.`
                : signatureFailureMessage(recordLabel, refusedObject),
        );
    }
    if (signatureEnvelope.signatureHash !== result.acceptedHashes[0]) {
        throw new Error(
            `${recordLabel} signature envelope hash does not match the verified signature hash.`,
        );
    }
};

const shareVerificationPayloadFields = (
    setupContext: CollectiveBgvSetupContext,
    privateVssEnvelopeCommitmentRoot: ProtocolHash,
    envelopeReference: PrivateVssEnvelopeVerificationReference,
): VssShareVerificationPayloadFields => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupParametersHash: setupContext.setupParametersHash,
    setupEpoch: setupContext.setupEpoch,
    sourceTrusteeIdentity: envelopeReference.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition: envelopeReference.sourceTrusteeRosterPosition,
    recipientIdentity: envelopeReference.recipientIdentity,
    recipientRosterPosition: envelopeReference.recipientRosterPosition,
    sourceTrusteeCommitmentRoot: envelopeReference.sourceTrusteeCommitmentRoot,
    privateVssEnvelopeCommitmentRoot,
    privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
});

const sortedBySourceTrusteeThenRecipient = <
    RecordValue extends {
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientRosterPosition: number;
    },
>(
    records: readonly RecordValue[],
): RecordValue[] =>
    [...records].sort((left, right) => {
        const sourceTrusteeOrder =
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition;

        return sourceTrusteeOrder === 0
            ? left.recipientRosterPosition - right.recipientRosterPosition
            : sourceTrusteeOrder;
    });

const assertDistinctSourceTrusteeRecipientPairs = (
    records: readonly {
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientRosterPosition: number;
    }[],
    recordLabel: string,
): void => {
    const seenPairs = new Set<string>();
    for (const record of records) {
        const pairKey = `${String(record.sourceTrusteeRosterPosition)}:${String(
            record.recipientRosterPosition,
        )}`;
        if (seenPairs.has(pairKey)) {
            throw new Error(
                `${recordLabel} records must have distinct source-trustee-recipient pairs.`,
            );
        }
        seenPairs.add(pairKey);
    }
};

export const createVssShareAcceptanceRecord = async (
    input: VssShareAcceptanceRecordInput,
): Promise<VssShareAcceptanceRecord> => {
    assertContextMatches(
        input.setupContext,
        input.envelopeReference,
        'envelopeReference',
    );
    assertNonNegativeSafeInteger(input.recoveryEpoch, 'recoveryEpoch');
    assertNonNegativeSafeInteger(input.deviceEpoch, 'deviceEpoch');

    const acceptancePayload = {
        objectType: 'VssShareAcceptance',
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        localVerificationRoot: input.envelopeReference.localVerificationRoot,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        signingPublicKeyHash: input.signingPublicKeyHash,
    } as const satisfies JsonRecord;
    const acceptanceRoot = deriveCanonicalObjectHash(acceptancePayload);
    const acceptanceByteLength = canonicalByteLength(acceptancePayload);
    // The signature-context hash carries its own objectType discriminator, which
    // domain-separates it from the object root under the shared canonical-object hash.
    const acceptanceContextHash = deriveCanonicalObjectHash({
        objectType: 'VssShareAcceptanceSignatureContext',
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        localVerificationRoot: input.envelopeReference.localVerificationRoot,
        acceptanceRoot,
    });
    const signedRoot = {
        objectType: 'VssShareAcceptance',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        boardHeadHash: null,
        objectRoot: acceptanceRoot,
        chunkMerkleRoot: null,
        byteLength: acceptanceByteLength,
        signerRole: 'Trustee',
        signerIdentity: input.envelopeReference.recipientIdentity,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        contextHash: acceptanceContextHash,
    } as const satisfies CanonicalSignedRootObject;
    const signatureEnvelope = await input.signRoot(signedRoot);
    verifyGeneratedSignatureEnvelope(
        'VSS share acceptance',
        signatureEnvelope,
        signedRoot,
        input.signingPublicKeyHash,
    );

    return {
        ...acceptancePayload,
        acceptanceRoot,
        acceptanceByteLength,
        acceptanceContextHash,
        signatureEnvelopeHash: signatureEnvelope.signatureHash,
        signatureEnvelope,
    } satisfies VssShareAcceptanceRecord;
};

export const createVssShareAcceptanceSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly acceptanceRecords: readonly VssShareAcceptanceRecord[];
}): VssShareAcceptanceSet => {
    const acceptanceRecords = sortedBySourceTrusteeThenRecipient(
        input.acceptanceRecords,
    );
    assertDistinctSourceTrusteeRecipientPairs(
        acceptanceRecords,
        'VSS share acceptance',
    );
    const acceptanceSetWithoutRoot = {
        objectType: 'VssShareAcceptanceSet',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        privateVssEnvelopeCommitmentRoot:
            input.privateVssEnvelopeCommitmentRoot,
        acceptanceRecords,
    } as const satisfies JsonRecord;

    return {
        ...acceptanceSetWithoutRoot,
        vssShareAcceptanceRoot: deriveCanonicalObjectHash(
            acceptanceSetWithoutRoot,
        ),
    } satisfies VssShareAcceptanceSet;
};

export const createVssShareComplaintRecord = async (
    input: VssShareComplaintRecordInput,
): Promise<VssShareComplaintRecord> => {
    assertContextMatches(
        input.setupContext,
        input.envelopeReference,
        'envelopeReference',
    );
    assertNonEmptyString(input.complaintReasonCode, 'complaintReasonCode');
    assertNonNegativeSafeInteger(input.recoveryEpoch, 'recoveryEpoch');
    assertNonNegativeSafeInteger(input.deviceEpoch, 'deviceEpoch');

    const complaintPayload = {
        objectType: 'VssShareComplaint',
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        complaintEvidenceRoot: input.complaintEvidenceRoot,
        complaintReasonCode: input.complaintReasonCode,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        signingPublicKeyHash: input.signingPublicKeyHash,
    } as const satisfies JsonRecord;
    const complaintRoot = deriveCanonicalObjectHash(complaintPayload);
    const complaintByteLength = canonicalByteLength(complaintPayload);
    const complaintContextHash = deriveCanonicalObjectHash({
        objectType: 'VssShareComplaintSignatureContext',
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        complaintEvidenceRoot: input.complaintEvidenceRoot,
        complaintReasonCode: input.complaintReasonCode,
        complaintRoot,
    });
    const signedRoot = {
        objectType: 'VssShareComplaint',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        boardHeadHash: null,
        objectRoot: complaintRoot,
        chunkMerkleRoot: null,
        byteLength: complaintByteLength,
        signerRole: 'Trustee',
        signerIdentity: input.envelopeReference.recipientIdentity,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        contextHash: complaintContextHash,
    } as const satisfies CanonicalSignedRootObject;
    const signatureEnvelope = await input.signRoot(signedRoot);
    verifyGeneratedSignatureEnvelope(
        'VSS share complaint',
        signatureEnvelope,
        signedRoot,
        input.signingPublicKeyHash,
    );

    return {
        ...complaintPayload,
        complaintRoot,
        complaintByteLength,
        complaintContextHash,
        signatureEnvelopeHash: signatureEnvelope.signatureHash,
        signatureEnvelope,
    } satisfies VssShareComplaintRecord;
};

export const createVssShareComplaintRecordFromLocalVerification = async (
    input: VssShareComplaintFromLocalVerificationInput,
): Promise<VssShareComplaintRecord> => {
    assertContextMatches(
        input.setupContext,
        input.envelopeReference,
        'envelopeReference',
    );
    const firstRefusal = input.localVerification.refusedObjects[0];
    if (firstRefusal === undefined) {
        throw new Error(
            'localVerification refusedObjects must include the local verification failure.',
        );
    }
    assertNonEmptyString(
        firstRefusal.reasonCode,
        'localVerification.reasonCode',
    );
    assertNonEmptyString(firstRefusal.message, 'localVerification.message');
    if (
        input.localVerification.privateEnvelopeHash !== null &&
        input.localVerification.privateEnvelopeHash !==
            input.envelopeReference.privateEnvelopeHash
    ) {
        throw new Error(
            'localVerification.privateEnvelopeHash must match the private envelope reference when present.',
        );
    }

    const evidencePayload = {
        objectType: 'VssShareComplaintEvidence',
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        privateEnvelopeHashFromLocalVerification:
            input.localVerification.privateEnvelopeHash,
        localVerificationRoot: input.localVerification.localVerificationRoot,
        refusedObjects: input.localVerification.refusedObjects.map(
            (refusedObject) => ({
                reasonCode: refusedObject.reasonCode,
                message: refusedObject.message,
                ...(refusedObject.objectPath === undefined
                    ? {}
                    : { objectPath: refusedObject.objectPath }),
            }),
        ),
    } as const satisfies JsonRecord;

    return createVssShareComplaintRecord({
        ...input,
        complaintEvidenceRoot: deriveCanonicalObjectHash(evidencePayload),
        complaintReasonCode: firstRefusal.reasonCode,
    });
};

export const createVssComplaintSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly complaintRecords: readonly VssShareComplaintRecord[];
}): VssComplaintSet => {
    const complaintRecords = sortedBySourceTrusteeThenRecipient(
        input.complaintRecords,
    );
    assertDistinctSourceTrusteeRecipientPairs(
        complaintRecords,
        'VSS complaint',
    );
    const complaintSetWithoutRoot = {
        objectType: 'VssComplaintSet',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        privateVssEnvelopeCommitmentRoot:
            input.privateVssEnvelopeCommitmentRoot,
        complaintRecords,
    } as const satisfies JsonRecord;

    return {
        ...complaintSetWithoutRoot,
        vssComplaintRoot: deriveCanonicalObjectHash(complaintSetWithoutRoot),
    } satisfies VssComplaintSet;
};
