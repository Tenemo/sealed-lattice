import {
    canonicalJson,
    deriveProtocolHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    CanonicalSignedRootObject,
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import type { PrivateVssEnvelopeCommitment } from './private-vss-mailbox-delivery.js';

type JsonRecord = Record<string, unknown>;

export type CollectiveBgvSetupContext = Readonly<
    JsonRecord & {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
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
    readonly ok: false;
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
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly localVerificationRoot: ProtocolHash;
        readonly verificationStatus: 'accepted';
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
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly complaintEvidenceRoot: ProtocolHash;
        readonly complaintReasonCode: string;
        readonly complaintStatus: 'valid-complaint-aborts-setup';
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
        readonly objectVersion: 1;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly acceptanceRecords: readonly VssShareAcceptanceRecord[];
        readonly vssShareAcceptanceRoot: ProtocolHash;
    }
>;

export type VssComplaintSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssComplaintSet';
        readonly objectVersion: 1;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly complaintRecords: readonly VssShareComplaintRecord[];
        readonly vssComplaintRoot: ProtocolHash;
    }
>;

type VssShareVerificationPayloadFields = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupProfileHash: ProtocolHash;
    readonly qShareHash: ProtocolHash;
    readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
    readonly commitmentProfileHash: ProtocolHash;
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

const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const assertEnvelopeMatchesContext = (
    setupContext: CollectiveBgvSetupContext,
    envelopeReference: PrivateVssEnvelopeVerificationReference,
): void => {
    for (const fieldName of contextFieldNames) {
        if (envelopeReference[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `envelopeReference.${fieldName} must match setupContext.${fieldName}.`,
            );
        }
    }
};

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
    if (!result.ok) {
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
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
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
    assertEnvelopeMatchesContext(input.setupContext, input.envelopeReference);
    assertNonNegativeSafeInteger(input.recoveryEpoch, 'recoveryEpoch');
    assertNonNegativeSafeInteger(input.deviceEpoch, 'deviceEpoch');

    const acceptancePayload = {
        objectType: 'VssShareAcceptance',
        objectVersion: 1,
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        localVerificationRoot: input.envelopeReference.localVerificationRoot,
        verificationStatus: 'accepted',
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        signingPublicKeyHash: input.signingPublicKeyHash,
    } as const satisfies JsonRecord;
    const acceptanceRoot = deriveProtocolHash(
        'VssShareAcceptanceRoot',
        acceptancePayload,
    );
    const acceptanceByteLength = canonicalByteLength(acceptancePayload);
    const acceptanceContextHash = deriveProtocolHash('VssShareAcceptanceRoot', {
        purpose: 'vss-share-acceptance-signature-context',
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
        objectVersion: 1,
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
        objectVersion: 1,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        privateVssEnvelopeCommitmentRoot:
            input.privateVssEnvelopeCommitmentRoot,
        acceptanceRecords,
    } as const satisfies JsonRecord;

    return {
        ...acceptanceSetWithoutRoot,
        vssShareAcceptanceRoot: deriveProtocolHash(
            'VssShareAcceptanceRoot',
            acceptanceSetWithoutRoot,
        ),
    } satisfies VssShareAcceptanceSet;
};

export const createVssShareComplaintRecord = async (
    input: VssShareComplaintRecordInput,
): Promise<VssShareComplaintRecord> => {
    assertEnvelopeMatchesContext(input.setupContext, input.envelopeReference);
    assertNonEmptyString(input.complaintReasonCode, 'complaintReasonCode');
    assertNonNegativeSafeInteger(input.recoveryEpoch, 'recoveryEpoch');
    assertNonNegativeSafeInteger(input.deviceEpoch, 'deviceEpoch');

    const complaintPayload = {
        objectType: 'VssShareComplaint',
        objectVersion: 1,
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        complaintEvidenceRoot: input.complaintEvidenceRoot,
        complaintReasonCode: input.complaintReasonCode,
        complaintStatus: 'valid-complaint-aborts-setup',
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        signingPublicKeyHash: input.signingPublicKeyHash,
    } as const satisfies JsonRecord;
    const complaintRoot = deriveProtocolHash(
        'VssComplaintRoot',
        complaintPayload,
    );
    const complaintByteLength = canonicalByteLength(complaintPayload);
    const complaintContextHash = deriveProtocolHash('VssComplaintRoot', {
        purpose: 'vss-share-complaint-signature-context',
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
        objectVersion: 1,
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
    assertEnvelopeMatchesContext(input.setupContext, input.envelopeReference);
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
        objectVersion: 1,
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        verificationStatus: 'failed-local-private-vss-opening',
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
        complaintEvidenceRoot: deriveProtocolHash(
            'VssComplaintRoot',
            evidencePayload,
        ),
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
        objectVersion: 1,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        privateVssEnvelopeCommitmentRoot:
            input.privateVssEnvelopeCommitmentRoot,
        complaintRecords,
    } as const satisfies JsonRecord;

    return {
        ...complaintSetWithoutRoot,
        vssComplaintRoot: deriveProtocolHash(
            'VssComplaintRoot',
            complaintSetWithoutRoot,
        ),
    } satisfies VssComplaintSet;
};
