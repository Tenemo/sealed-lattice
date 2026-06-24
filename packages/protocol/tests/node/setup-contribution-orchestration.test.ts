import { describe, expect, it } from 'vitest';

import {
    createSetupContributionAssembly,
    type LocalTrusteeSetupStateCommitment,
    type PrivateVssEnvelopeVerificationReference,
    type SetupPhaseParticipantObject,
    type VssSourceTrusteeCoefficientCommitmentRecord,
    type VssShareAcceptanceRecord,
    type VssShareComplaintRecord,
} from '#packages/protocol/src/index';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash('setup-contribution-orchestration');

const setupContext = makeSetupContext(fixtureHash, 'carry-aware');

const contextFields = {
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
} as const;

const phaseObject = (phaseNumber: number): SetupPhaseParticipantObject =>
    ({
        objectType: 'SetupPhaseParticipantObject',
        objectVersion: 1,
        phaseId: `phase-${String(phaseNumber)}`,
        phaseNumber,
        trusteeIdentity: 'trustee-3',
        rosterPosition: 3,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        signingPublicKeyHash: fixtureHash(`signing-key-${String(phaseNumber)}`),
        phaseObjectRoot: fixtureHash(`phase-root-${String(phaseNumber)}`),
        phaseObjectByteLength: 100 + phaseNumber,
        phaseSignatureContextHash: fixtureHash(
            `phase-context-${String(phaseNumber)}`,
        ),
        signatureEnvelopeHash: fixtureHash(
            `phase-signature-${String(phaseNumber)}`,
        ),
        signatureEnvelope: {
            signatureHash: fixtureHash(`signature-${String(phaseNumber)}`),
        },
        ceremonyId: setupContext.ceremonyId,
    }) as unknown as SetupPhaseParticipantObject;

const sourceTrusteeRecord = {
    objectType: 'VssSourceTrusteeCoefficientCommitments',
    objectVersion: 1,
    ...contextFields,
    sourceTrusteeIdentity: 'trustee-3',
    sourceTrusteeRosterPosition: 3,
    publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
    coefficientCommitments: [],
    sourceTrusteeCommitmentRoot: fixtureHash('source-trustee-root'),
} as unknown as VssSourceTrusteeCoefficientCommitmentRecord;

const envelopeReference = {
    objectType: 'PrivateVssEnvelopeCommitment',
    objectVersion: 1,
    ...contextFields,
    sourceTrusteeIdentity: 'trustee-3',
    sourceTrusteeRosterPosition: 3,
    recipientIdentity: 'trustee-4',
    recipientRosterPosition: 4,
    privateEnvelopeCommitmentRoot: fixtureHash('private-envelope-commitment'),
    encryptedEnvelopeHash: fixtureHash('encrypted-envelope'),
    privateEnvelopeHash: fixtureHash('private-envelope'),
    localVerificationRoot: fixtureHash('local-verification'),
} as unknown as PrivateVssEnvelopeVerificationReference;

const acceptanceRecord = {
    objectType: 'VssShareAcceptance',
    objectVersion: 1,
    ...contextFields,
    sourceTrusteeIdentity: 'trustee-1',
    sourceTrusteeRosterPosition: 1,
    recipientIdentity: 'trustee-3',
    recipientRosterPosition: 3,
    privateVssEnvelopeCommitmentRoot: fixtureHash('private-vss-envelope-set'),
    privateEnvelopeHash: fixtureHash('accepted-envelope'),
    localVerificationRoot: fixtureHash('accepted-local-verification'),
    acceptanceRoot: fixtureHash('acceptance-root'),
} as unknown as VssShareAcceptanceRecord;

const complaintRecord = {
    objectType: 'VssShareComplaint',
    objectVersion: 1,
    ...contextFields,
    sourceTrusteeIdentity: 'trustee-2',
    sourceTrusteeRosterPosition: 2,
    recipientIdentity: 'trustee-3',
    recipientRosterPosition: 3,
    privateVssEnvelopeCommitmentRoot: fixtureHash('private-vss-envelope-set'),
    privateEnvelopeHash: fixtureHash('complaint-envelope'),
    complaintEvidenceRoot: fixtureHash('complaint-evidence'),
    complaintReasonCode: 'private-vss-opening-verification-failed',
    complaintRoot: fixtureHash('complaint-root'),
} as unknown as VssShareComplaintRecord;

const localStateCommitment = {
    objectType: 'LocalTrusteeSetupStateCommitment',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    ...contextFields,
    trusteeIdentity: 'trustee-3',
    trusteeRosterPosition: 3,
    trusteePoint: 4,
    thresholdShareCommitmentRecipientRoot: fixtureHash('threshold-recipient'),
    aggregateThresholdShareRoot: fixtureHash('aggregate-share'),
    issuedVssAcceptanceRoot: fixtureHash('issued-acceptance'),
    issuedVssComplaintRoots: [],
    deletionReceiptRoot: fixtureHash('deletion-receipt'),
    deletionReceipt: {},
    exportPolicy: 'roots-only-no-raw-share-or-opening-export',
    storageProfile: 'encrypted-local-device-state-required',
    localStateRoot: fixtureHash('local-state'),
} as unknown as LocalTrusteeSetupStateCommitment;

describe('setup contribution orchestration', () => {
    it('assembles a roots-only participant setup contribution', () => {
        const assembly = createSetupContributionAssembly({
            setupContext,
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            setupPhaseParticipantObjects: [phaseObject(2), phaseObject(1)],
            commonRandomnessCommitRoot: fixtureHash('common-commit'),
            commonRandomnessRevealRoot: fixtureHash('common-reveal'),
            vssSourceTrusteeRecord: sourceTrusteeRecord,
            privateVssEnvelopeReferences: [envelopeReference],
            vssShareAcceptanceRecords: [acceptanceRecord],
            vssShareComplaintRecords: [complaintRecord],
            localStateCommitment,
        });

        expect(assembly).toMatchObject({
            objectType: 'SetupContributionAssembly',
            setupProfileId: 'CollectiveBgvSetup-v1',
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            vssSourceTrusteeCommitmentRoot:
                sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
            thresholdShareCommitmentRecipientRoot:
                localStateCommitment.thresholdShareCommitmentRecipientRoot,
            aggregateThresholdShareRoot:
                localStateCommitment.aggregateThresholdShareRoot,
            localStateRoot: localStateCommitment.localStateRoot,
        });
        expect(assembly.phaseObjectRoots).toEqual([
            fixtureHash('phase-root-1'),
            fixtureHash('phase-root-2'),
        ]);
        expect(assembly.issuedVssComplaintRoots).toEqual([
            fixtureHash('complaint-root'),
        ]);
        expect(assembly.setupContributionRoot).toHaveLength(128);
    });

    it('rejects contribution records bound to a different trustee', () => {
        expect(() =>
            createSetupContributionAssembly({
                setupContext,
                trusteeIdentity: 'trustee-3',
                trusteeRosterPosition: 3,
                setupPhaseParticipantObjects: [phaseObject(1)],
                vssShareAcceptanceRecords: [
                    {
                        ...acceptanceRecord,
                        recipientRosterPosition: 4,
                    },
                ],
            }),
        ).toThrow(/recipientRosterPosition/u);
    });
});
