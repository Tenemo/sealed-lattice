import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import {
    type CanonicalSignedRootObject,
    type ProtocolHash,
    type ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import {
    deriveCollectiveBgvSetupContextHash,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    type JsonRecord,
} from './common-fields.js';
import type { PrivateVssEnvelopeCommitment } from './private-vss-envelope-commitment.js';
import type { CollectiveBgvSetupIntent } from './setup-intent.js';
import type { VssPublicCoefficientCommitmentSet } from './vss-commitments/commitment-sets.js';

export type CollectiveBgvSetupContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly participantCount: number;
}>;

export type PrivateVssEnvelopeVerificationReference =
    PrivateVssEnvelopeCommitment;

export type ProtocolRootSigner = (
    signedRoot: CanonicalSignedRootObject,
) => ProtocolSignatureEnvelope | Promise<ProtocolSignatureEnvelope>;

type VssShareResponseRecordInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly setupIntent: CollectiveBgvSetupIntent;
    readonly vssPublicCoefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly envelopeReference: PrivateVssEnvelopeVerificationReference;
    readonly signRoot: ProtocolRootSigner;
};

export type VssShareAcceptanceRecord = Readonly<{
    readonly objectType: 'VssShareAcceptance';
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly signatureEnvelope: ProtocolSignatureEnvelope;
}>;

export type VssShareComplaintRecord = Readonly<{
    readonly objectType: 'VssShareComplaint';
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly signatureEnvelope: ProtocolSignatureEnvelope;
}>;

export type VssShareAcceptanceSet = Readonly<{
    readonly objectType: 'VssShareAcceptanceSet';
    readonly acceptanceRecords: readonly VssShareAcceptanceRecord[];
}>;

export type VssComplaintSet = Readonly<{
    readonly objectType: 'VssComplaintSet';
    readonly complaintRecords: readonly VssShareComplaintRecord[];
}>;

type VssShareVerificationPayloadFields = Readonly<{
    readonly setupContextHash: ProtocolHash;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly privateEnvelopeHash: ProtocolHash;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
}>;

const shareVerificationPayloadFields = (
    input: VssShareResponseRecordInput,
): VssShareVerificationPayloadFields => {
    const { envelopeReference } = input;
    assertNonNegativeSafeInteger(
        envelopeReference.sourceTrusteeRosterPosition,
        'envelopeReference.sourceTrusteeRosterPosition',
    );
    assertNonNegativeSafeInteger(
        envelopeReference.recipientRosterPosition,
        'envelopeReference.recipientRosterPosition',
    );
    if (input.setupIntent.objectType !== 'CollectiveBgvSetupIntent') {
        throw new TypeError(
            'setupIntent.objectType must be CollectiveBgvSetupIntent.',
        );
    }
    const recipientRegistration =
        input.setupIntent.trusteeRegistrations[
            envelopeReference.recipientRosterPosition
        ];
    if (
        recipientRegistration?.objectType !==
            'CollectiveBgvSetupIntentTrusteeRegistration' ||
        recipientRegistration.trusteeIdentity !==
            envelopeReference.recipientIdentity
    ) {
        throw new Error(
            'setupIntent must contain the envelope recipient registration at the recipient roster position.',
        );
    }
    assertNonNegativeSafeInteger(
        recipientRegistration.recoveryEpoch,
        'recipientRegistration.recoveryEpoch',
    );
    assertNonNegativeSafeInteger(
        recipientRegistration.deviceEpoch,
        'recipientRegistration.deviceEpoch',
    );

    const sourceCommitment =
        input.vssPublicCoefficientCommitmentSet.sourceTrusteeRecords[
            envelopeReference.sourceTrusteeRosterPosition
        ];
    if (
        sourceCommitment?.sourceTrusteeIdentity !==
        envelopeReference.sourceTrusteeIdentity
    ) {
        throw new Error(
            'vssPublicCoefficientCommitmentSet must contain the envelope source trustee at the source roster position.',
        );
    }
    assertProtocolHash(
        input.privateVssEnvelopeCommitmentRoot,
        'privateVssEnvelopeCommitmentRoot',
    );

    return {
        setupContextHash: deriveCollectiveBgvSetupContextHash(
            input.setupContext,
        ),
        sourceTrusteeIdentity: envelopeReference.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition:
            envelopeReference.sourceTrusteeRosterPosition,
        recipientIdentity: envelopeReference.recipientIdentity,
        recipientRosterPosition: envelopeReference.recipientRosterPosition,
        sourceTrusteeCommitmentRoot:
            deriveCanonicalObjectHash(sourceCommitment),
        privateVssEnvelopeCommitmentRoot:
            input.privateVssEnvelopeCommitmentRoot,
        privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
        recoveryEpoch: recipientRegistration.recoveryEpoch,
        deviceEpoch: recipientRegistration.deviceEpoch,
    };
};

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
    input: VssShareResponseRecordInput,
): Promise<VssShareAcceptanceRecord> => {
    const acceptancePayload = {
        objectType: 'VssShareAcceptance',
        ...shareVerificationPayloadFields(input),
    } as const satisfies JsonRecord;
    const acceptanceRoot = deriveCanonicalObjectHash(acceptancePayload);
    const signedRoot = {
        objectType: 'VssShareAcceptance',
        objectRoot: acceptanceRoot,
    } as const satisfies CanonicalSignedRootObject;
    const signatureEnvelope = await input.signRoot(signedRoot);

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
    input: VssShareResponseRecordInput,
): Promise<VssShareComplaintRecord> => {
    const complaintPayload = {
        objectType: 'VssShareComplaint',
        ...shareVerificationPayloadFields(input),
    } as const satisfies JsonRecord;
    const complaintRoot = deriveCanonicalObjectHash(complaintPayload);
    const signedRoot = {
        objectType: 'VssShareComplaint',
        objectRoot: complaintRoot,
    } as const satisfies CanonicalSignedRootObject;
    const signatureEnvelope = await input.signRoot(signedRoot);

    return {
        objectType: complaintPayload.objectType,
        sourceTrusteeRosterPosition:
            complaintPayload.sourceTrusteeRosterPosition,
        recipientRosterPosition: complaintPayload.recipientRosterPosition,
        signatureEnvelope,
    } satisfies VssShareComplaintRecord;
};
