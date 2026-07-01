import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { LocalTrusteeSetupStateCommitment } from './local-trustee-setup-state.js';
import type {
    PublicKeyShareProofRecord,
    PublicKeyShareRecord,
} from './public-key-share-records.js';
import type { SetupPhaseParticipantObject } from './setup-phase-records.js';
import type { VssSourceTrusteeCoefficientCommitmentRecord } from './vss-coefficient-commitments.js';
import type {
    CollectiveBgvSetupContext,
    PrivateVssEnvelopeVerificationReference,
    VssShareAcceptanceRecord,
    VssShareComplaintRecord,
} from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export type SetupContributionAssemblyInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupPhaseParticipantObjects: readonly SetupPhaseParticipantObject[];
    readonly commonRandomnessCommitRoot?: ProtocolHash;
    readonly commonRandomnessRevealRoot?: ProtocolHash;
    readonly vssSourceTrusteeRecord?: VssSourceTrusteeCoefficientCommitmentRecord;
    readonly privateVssEnvelopeReferences?: readonly PrivateVssEnvelopeVerificationReference[];
    readonly vssShareAcceptanceRecords?: readonly VssShareAcceptanceRecord[];
    readonly vssShareComplaintRecords?: readonly VssShareComplaintRecord[];
    readonly localStateCommitment?: LocalTrusteeSetupStateCommitment;
    readonly publicKeyShareRecord?: PublicKeyShareRecord;
    readonly publicKeyShareProofRecord?: PublicKeyShareProofRecord;
}>;

export type SetupContributionAssembly = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupContributionAssembly';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly phaseObjectRoots: readonly ProtocolHash[];
        readonly commonRandomnessCommitRoot: ProtocolHash | null;
        readonly commonRandomnessRevealRoot: ProtocolHash | null;
        readonly vssSourceTrusteeCommitmentRoot: ProtocolHash | null;
        readonly privateVssEnvelopeReferences: readonly {
            readonly recipientIdentity: string;
            readonly recipientRosterPosition: number;
            readonly privateEnvelopeCommitmentRoot: ProtocolHash;
            readonly encryptedEnvelopeHash: ProtocolHash;
            readonly privateEnvelopeHash: ProtocolHash;
            readonly localVerificationRoot: ProtocolHash;
        }[];
        readonly issuedVssAcceptanceRoots: readonly ProtocolHash[];
        readonly issuedVssComplaintRoots: readonly ProtocolHash[];
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash | null;
        readonly aggregateThresholdShareRoot: ProtocolHash | null;
        readonly localStateRoot: ProtocolHash | null;
        readonly localStateDeletionReceiptRoot: ProtocolHash | null;
        readonly publicKeyShareRoot: ProtocolHash | null;
        readonly publicKeyShareProofRoot: ProtocolHash | null;
        readonly setupContributionRoot: ProtocolHash;
    }
>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;

const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupParametersHash',
    'setupEpoch',
] as const;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

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

const setupContextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<CollectiveBgvSetupContext, (typeof contextFieldNames)[number]> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupParametersHash: setupContext.setupParametersHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    objectPath: string,
): void => {
    for (const fieldName of contextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${objectPath}.${fieldName} must match setupContext.${fieldName}.`,
            );
        }
    }
};

const assertTrusteeMatches = (
    input: Pick<
        SetupContributionAssemblyInput,
        'trusteeIdentity' | 'trusteeRosterPosition'
    >,
    value: Readonly<Record<string, unknown>>,
    identityFieldName: string,
    rosterPositionFieldName: string,
    objectPath: string,
): void => {
    if (value[identityFieldName] !== input.trusteeIdentity) {
        throw new Error(
            `${objectPath}.${identityFieldName} must match trusteeIdentity.`,
        );
    }
    if (value[rosterPositionFieldName] !== input.trusteeRosterPosition) {
        throw new Error(
            `${objectPath}.${rosterPositionFieldName} must match trusteeRosterPosition.`,
        );
    }
};

const phaseObjectRoots = (
    input: SetupContributionAssemblyInput,
): readonly ProtocolHash[] =>
    [...input.setupPhaseParticipantObjects]
        .sort((left, right) => left.phaseNumber - right.phaseNumber)
        .map((phaseObject, phaseObjectIndex) => {
            const objectPath = `setupPhaseParticipantObjects.${String(phaseObjectIndex)}`;
            if (phaseObject.trusteeIdentity !== input.trusteeIdentity) {
                throw new Error(
                    `${objectPath}.trusteeIdentity must match trusteeIdentity.`,
                );
            }
            if (phaseObject.rosterPosition !== input.trusteeRosterPosition) {
                throw new Error(
                    `${objectPath}.rosterPosition must match trusteeRosterPosition.`,
                );
            }
            if (phaseObject.ceremonyId !== input.setupContext.ceremonyId) {
                throw new Error(
                    `${objectPath}.ceremonyId must match setupContext.ceremonyId.`,
                );
            }
            assertProtocolHash(
                phaseObject.phaseObjectRoot,
                `${objectPath}.phaseObjectRoot`,
            );

            return phaseObject.phaseObjectRoot;
        });

const privateVssEnvelopeRootReferences = (
    input: SetupContributionAssemblyInput,
): SetupContributionAssembly['privateVssEnvelopeReferences'] =>
    [...(input.privateVssEnvelopeReferences ?? [])]
        .sort(
            (left, right) =>
                left.recipientRosterPosition - right.recipientRosterPosition,
        )
        .map((reference, referenceIndex) => {
            const objectPath = `privateVssEnvelopeReferences.${String(referenceIndex)}`;
            assertContextMatches(input.setupContext, reference, objectPath);
            assertTrusteeMatches(
                input,
                reference,
                'sourceTrusteeIdentity',
                'sourceTrusteeRosterPosition',
                objectPath,
            );
            assertProtocolHash(
                reference.privateEnvelopeCommitmentRoot,
                `${objectPath}.privateEnvelopeCommitmentRoot`,
            );
            assertProtocolHash(
                reference.encryptedEnvelopeHash,
                `${objectPath}.encryptedEnvelopeHash`,
            );
            assertProtocolHash(
                reference.privateEnvelopeHash,
                `${objectPath}.privateEnvelopeHash`,
            );
            assertProtocolHash(
                reference.localVerificationRoot,
                `${objectPath}.localVerificationRoot`,
            );

            return {
                recipientIdentity: reference.recipientIdentity,
                recipientRosterPosition: reference.recipientRosterPosition,
                privateEnvelopeCommitmentRoot:
                    reference.privateEnvelopeCommitmentRoot,
                encryptedEnvelopeHash: reference.encryptedEnvelopeHash,
                privateEnvelopeHash: reference.privateEnvelopeHash,
                localVerificationRoot: reference.localVerificationRoot,
            };
        });

const issuedAcceptanceRoots = (
    input: SetupContributionAssemblyInput,
): readonly ProtocolHash[] =>
    [...(input.vssShareAcceptanceRecords ?? [])]
        .sort(
            (left, right) =>
                left.sourceTrusteeRosterPosition -
                right.sourceTrusteeRosterPosition,
        )
        .map((acceptance, acceptanceIndex) => {
            const objectPath = `vssShareAcceptanceRecords.${String(acceptanceIndex)}`;
            assertContextMatches(input.setupContext, acceptance, objectPath);
            assertTrusteeMatches(
                input,
                acceptance,
                'recipientIdentity',
                'recipientRosterPosition',
                objectPath,
            );
            assertProtocolHash(
                acceptance.acceptanceRoot,
                `${objectPath}.acceptanceRoot`,
            );

            return acceptance.acceptanceRoot;
        });

const issuedComplaintRoots = (
    input: SetupContributionAssemblyInput,
): readonly ProtocolHash[] =>
    [...(input.vssShareComplaintRecords ?? [])]
        .sort(
            (left, right) =>
                left.sourceTrusteeRosterPosition -
                right.sourceTrusteeRosterPosition,
        )
        .map((complaint, complaintIndex) => {
            const objectPath = `vssShareComplaintRecords.${String(complaintIndex)}`;
            assertContextMatches(input.setupContext, complaint, objectPath);
            assertTrusteeMatches(
                input,
                complaint,
                'recipientIdentity',
                'recipientRosterPosition',
                objectPath,
            );
            assertProtocolHash(
                complaint.complaintRoot,
                `${objectPath}.complaintRoot`,
            );

            return complaint.complaintRoot;
        });

export const createSetupContributionAssembly = (
    input: SetupContributionAssemblyInput,
): SetupContributionAssembly => {
    assertNonEmptyString(input.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        input.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    for (const fieldName of contextFieldNames) {
        const value = input.setupContext[fieldName];
        if (typeof value !== 'string' || value.length === 0) {
            throw new TypeError(`setupContext.${fieldName} must be non-empty.`);
        }
    }
    if (input.commonRandomnessCommitRoot !== undefined) {
        assertProtocolHash(
            input.commonRandomnessCommitRoot,
            'commonRandomnessCommitRoot',
        );
    }
    if (input.commonRandomnessRevealRoot !== undefined) {
        assertProtocolHash(
            input.commonRandomnessRevealRoot,
            'commonRandomnessRevealRoot',
        );
    }
    const vssSourceTrusteeCommitmentRoot =
        input.vssSourceTrusteeRecord === undefined
            ? null
            : input.vssSourceTrusteeRecord.sourceTrusteeCommitmentRoot;
    if (input.vssSourceTrusteeRecord !== undefined) {
        assertContextMatches(
            input.setupContext,
            input.vssSourceTrusteeRecord,
            'vssSourceTrusteeRecord',
        );
        assertTrusteeMatches(
            input,
            input.vssSourceTrusteeRecord,
            'sourceTrusteeIdentity',
            'sourceTrusteeRosterPosition',
            'vssSourceTrusteeRecord',
        );
        assertProtocolHash(
            input.vssSourceTrusteeRecord.sourceTrusteeCommitmentRoot,
            'vssSourceTrusteeCommitmentRoot',
        );
    }
    if (input.localStateCommitment !== undefined) {
        assertContextMatches(
            input.setupContext,
            input.localStateCommitment,
            'localStateCommitment',
        );
        assertTrusteeMatches(
            input,
            input.localStateCommitment,
            'trusteeIdentity',
            'trusteeRosterPosition',
            'localStateCommitment',
        );
    }
    if (input.publicKeyShareRecord !== undefined) {
        assertContextMatches(
            input.setupContext,
            input.publicKeyShareRecord,
            'publicKeyShareRecord',
        );
        assertTrusteeMatches(
            input,
            input.publicKeyShareRecord,
            'trusteeIdentity',
            'trusteeRosterPosition',
            'publicKeyShareRecord',
        );
    }
    if (input.publicKeyShareProofRecord !== undefined) {
        assertContextMatches(
            input.setupContext,
            input.publicKeyShareProofRecord,
            'publicKeyShareProofRecord',
        );
        assertTrusteeMatches(
            input,
            input.publicKeyShareProofRecord,
            'trusteeIdentity',
            'trusteeRosterPosition',
            'publicKeyShareProofRecord',
        );
    }

    const assemblyWithoutRoot = {
        objectType: 'SetupContributionAssembly',
        objectVersion: 1,
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        phaseObjectRoots: phaseObjectRoots(input),
        commonRandomnessCommitRoot: input.commonRandomnessCommitRoot ?? null,
        commonRandomnessRevealRoot: input.commonRandomnessRevealRoot ?? null,
        vssSourceTrusteeCommitmentRoot,
        privateVssEnvelopeReferences: privateVssEnvelopeRootReferences(input),
        issuedVssAcceptanceRoots: issuedAcceptanceRoots(input),
        issuedVssComplaintRoots: issuedComplaintRoots(input),
        thresholdShareCommitmentRecipientRoot:
            input.localStateCommitment?.thresholdShareCommitmentRecipientRoot ??
            null,
        aggregateThresholdShareRoot:
            input.localStateCommitment?.aggregateThresholdShareRoot ?? null,
        localStateRoot: input.localStateCommitment?.localStateRoot ?? null,
        localStateDeletionReceiptRoot:
            input.localStateCommitment?.deletionReceiptRoot ?? null,
        publicKeyShareRoot:
            input.publicKeyShareRecord?.publicKeyShareRoot ?? null,
        publicKeyShareProofRoot:
            input.publicKeyShareProofRecord?.publicKeyShareProofRoot ?? null,
    } as const satisfies Omit<
        SetupContributionAssembly,
        'setupContributionRoot'
    >;

    return {
        ...assemblyWithoutRoot,
        setupContributionRoot: deriveCanonicalObjectHash(assemblyWithoutRoot),
    } satisfies SetupContributionAssembly;
};
