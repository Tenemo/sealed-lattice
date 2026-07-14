import {
    deriveCanonicalObjectHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    CanonicalSignedRootObject,
    ProtocolHash,
    ProtocolSignatureEnvelope,
    RefusalReason,
    VerificationResult,
} from '@sealed-lattice/types';

import {
    deriveCollectiveBgvSetupContextHash,
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
        readonly participantCount: number;
    }
>;

export type PrivateVssEnvelopeVerificationReference = Readonly<
    PrivateVssEnvelopeCommitment & {
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    }
>;

export type ProtocolRootSigner = (
    signedRoot: CanonicalSignedRootObject,
) => ProtocolSignatureEnvelope | Promise<ProtocolSignatureEnvelope>;

type VssShareAcceptanceRecordInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly envelopeReference: PrivateVssEnvelopeVerificationReference;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signRoot: ProtocolRootSigner;
};

type VssShareComplaintRecordInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly envelopeReference: PrivateVssEnvelopeVerificationReference;
    readonly complaintEvidenceRoot: ProtocolHash;
    readonly complaintReasonCode: RefusalReason;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signRoot: ProtocolRootSigner;
};

export type PrivateVssLocalVerificationFailure = Extract<
    VerificationResult<never>,
    { readonly isValid: false }
>;

type VssShareComplaintFromLocalVerificationInput = Omit<
    VssShareComplaintRecordInput,
    'complaintEvidenceRoot' | 'complaintReasonCode'
> & {
    readonly localVerification: PrivateVssLocalVerificationFailure;
};

export type VssShareAcceptanceRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssShareAcceptance';
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientRosterPosition: number;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type VssShareComplaintRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssShareComplaint';
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientRosterPosition: number;
        readonly complaintEvidenceRoot: ProtocolHash;
        readonly complaintReasonCode: RefusalReason;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type VssShareAcceptanceSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssShareAcceptanceSet';
        readonly acceptanceRecords: readonly VssShareAcceptanceRecord[];
    }
>;

export type VssComplaintSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssComplaintSet';
        readonly complaintRecords: readonly VssShareComplaintRecord[];
    }
>;

type VssShareVerificationPayloadFields = Readonly<{
    readonly setupContextHash: ProtocolHash;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly privateEnvelopeHash: ProtocolHash;
}>;

const verifyGeneratedSignatureEnvelope = (
    recordLabel: string,
    signatureEnvelope: ProtocolSignatureEnvelope,
    signedRoot: CanonicalSignedRootObject,
): void => {
    const result = verifySignedObjectSignature(signatureEnvelope, {
        ...signedRoot,
        publicKeyHash: signatureEnvelope.publicKeyHash,
    });
    if (!result.isValid) {
        throw new Error(
            `${recordLabel} signature envelope failed verification: ${result.refusalReason}.`,
        );
    }
};

const shareVerificationPayloadFields = (
    setupContext: CollectiveBgvSetupContext,
    privateVssEnvelopeCommitmentRoot: ProtocolHash,
    envelopeReference: PrivateVssEnvelopeVerificationReference,
): VssShareVerificationPayloadFields => ({
    setupContextHash: deriveCollectiveBgvSetupContextHash(setupContext),
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
    } as const satisfies JsonRecord;
    const acceptanceRoot = deriveCanonicalObjectHash(acceptancePayload);
    const acceptanceContextHash = deriveCanonicalObjectHash({
        objectType: 'VssShareAcceptanceSignatureContext',
        payloadRoot: acceptanceRoot,
    });
    const signedRoot = {
        objectType: 'VssShareAcceptance',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        objectRoot: acceptanceRoot,
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
    );

    return {
        objectType: acceptancePayload.objectType,
        sourceTrusteeRosterPosition:
            acceptancePayload.sourceTrusteeRosterPosition,
        recipientRosterPosition: acceptancePayload.recipientRosterPosition,
        signatureEnvelope,
    } satisfies VssShareAcceptanceRecord;
};

export const createVssShareAcceptanceSet = (input: {
    readonly acceptanceRecords: readonly VssShareAcceptanceRecord[];
}): VssShareAcceptanceSet => {
    const acceptanceRecords = sortedBySourceTrusteeThenRecipient(
        input.acceptanceRecords,
    );
    assertDistinctSourceTrusteeRecipientPairs(
        acceptanceRecords,
        'VSS share acceptance',
    );
    return {
        objectType: 'VssShareAcceptanceSet',
        acceptanceRecords,
    } satisfies VssShareAcceptanceSet;
};

export const createVssShareComplaintRecord = async (
    input: VssShareComplaintRecordInput,
): Promise<VssShareComplaintRecord> => {
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
    } as const satisfies JsonRecord;
    const complaintRoot = deriveCanonicalObjectHash(complaintPayload);
    const complaintContextHash = deriveCanonicalObjectHash({
        objectType: 'VssShareComplaintSignatureContext',
        payloadRoot: complaintRoot,
    });
    const signedRoot = {
        objectType: 'VssShareComplaint',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        objectRoot: complaintRoot,
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
    );

    return {
        objectType: complaintPayload.objectType,
        sourceTrusteeRosterPosition:
            complaintPayload.sourceTrusteeRosterPosition,
        recipientRosterPosition: complaintPayload.recipientRosterPosition,
        complaintEvidenceRoot: complaintPayload.complaintEvidenceRoot,
        complaintReasonCode: complaintPayload.complaintReasonCode,
        signatureEnvelope,
    } satisfies VssShareComplaintRecord;
};

export const createVssShareComplaintRecordFromLocalVerification = async (
    input: VssShareComplaintFromLocalVerificationInput,
): Promise<VssShareComplaintRecord> => {
    const evidencePayload = {
        objectType: 'VssShareComplaintEvidence',
        ...shareVerificationPayloadFields(
            input.setupContext,
            input.privateVssEnvelopeCommitmentRoot,
            input.envelopeReference,
        ),
        refusalReason: input.localVerification.refusalReason,
    } as const satisfies JsonRecord;

    return createVssShareComplaintRecord({
        ...input,
        complaintEvidenceRoot: deriveCanonicalObjectHash(evidencePayload),
        complaintReasonCode: input.localVerification.refusalReason,
    });
};
