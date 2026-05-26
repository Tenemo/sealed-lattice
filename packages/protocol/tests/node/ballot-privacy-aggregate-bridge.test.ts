import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import {
    encryptedAggregateBridgeProfileId,
    type ActionContext,
    type AggregateDerivationComponent,
    type AggregateContribution,
    type BridgeProofRecord,
    type ProtocolDigest,
    type ProtocolSignatureEnvelope,
    type RecoveryEpochMapEntry,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '../../src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    createAggregateContributionFromBridgeProofRecord,
    createAggregateReadyRecord,
    deriveAggregateContributionDigest,
    deriveBridgeProofProfileDigest,
    deriveBridgeProofRecordDigest,
    deriveBridgeProofStatementDigest,
    deriveBridgeProofTargetContractDigest,
    selectFirstValidAggregateContributions,
    verifyAggregateContributionStructure,
} from '../../src/ballot-privacy/index.js';
import { deriveInterpolationCoefficientReport } from '../../src/plaintext-oracle/index.js';

const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest('ActionContextDigest', { label });

const sampledPublicRelationCheckPolicy = {
    acceptedForBridgeProofVerification: false,
    diagnosticOnly: true,
    fullBridgeProofRequired: true,
    objectType: 'M9BridgeSampledRelationCheckPolicy',
    objectVersion: 1,
    relationCheckSource: 'first-data-prime-diagnostic',
    sampledOnlyBridgeVerificationAccepted: false,
    sampledRelationCheckCount: 1,
} as const;

const sampledPublicRelationChecks = [
    {
        componentOneCoefficient: 11,
        componentZeroCoefficient: 7,
        modulus: 140_737_487_306_753,
        position: 0,
        relationMatches: true,
    },
] as const;

const sampledPublicRelationCheckPolicyDigest = deriveProtocolDigest(
    'BridgeProofRecordDigest',
    {
        policy: sampledPublicRelationCheckPolicy,
        purpose: 'm9-sampled-public-relation-check-policy-v1',
    },
);

const baseFields = {
    aggregateInputEncodingProfileDigest: digest('aggregate-input-encoding'),
    aggregateSelectionPolicyDigest: digest('aggregate-selection-policy'),
    ballotScoreEncodingProfileDigest: digest('ballot-score-encoding'),
    ballotSetDigest: digest('ballot-set'),
    ballotShareLayoutProfileDigest: digest('ballot-share-layout'),
    bgvBatchEncoderDigest: digest('bgv-batch-encoder'),
    bgvProfileDigest: digest('bgv-profile'),
    bgvPublicKeyRoot: digest('bgv-public-key-root'),
    bridgeLayoutDigest: digest('bridge-layout'),
    bridgeWitnessPrivacyProfileDigest: digest('bridge-witness-privacy'),
    canonicalCiphertextConventionDigest: digest('ciphertext-convention'),
    ceremonyId: 'ceremony-1',
    closeRecordDigest: digest('close-record'),
    collectivePublicKeyRoot: digest('collective-public-key-root'),
    encodedAggregateLayoutDigest: digest('encoded-aggregate-layout'),
    encodedShareVectorLayoutDigest: digest('encoded-share-vector-layout'),
    encryptedAggregateBridgeDigest: digest('encrypted-aggregate-bridge'),
    encryptedAggregateInputLayoutDigest: digest(
        'encrypted-aggregate-input-layout',
    ),
    encryptedAggregateReconstructionDigest: digest(
        'encrypted-aggregate-reconstruction',
    ),
    encryptedAggregateTargetBasisDataRoot: digest(
        'encrypted-aggregate-target-basis-data',
    ),
    heParamDigest: digest('he-param'),
    manifestDigest: digest('manifest'),
    pollSpecDigest: digest('poll-spec'),
    postVotingClosedContextDigest: digest('post-voting-closed-context'),
    rosterDigest: digest('roster'),
    rustBgvBackendProfileDigest: digest('rust-bgv-backend-profile'),
    shareCommitmentMessageBoundCertDigest: digest(
        'share-commitment-message-bound-cert',
    ),
    thresholdProfileDigest: digest('threshold-profile'),
    topKEvaluatorInputLayoutDigest: digest('top-k-evaluator-input-layout'),
    votingClosedBoardHeadDigest: digest('voting-closed-board-head'),
} as const;

type ContributionFixtureInput = {
    readonly boardPosition?: number;
    readonly boardSequence?: number;
    readonly contextDigest?: ProtocolDigest;
    readonly deviceEpoch?: number;
    readonly encryptedAggregateShareCiphertextRoot?: ProtocolDigest;
    readonly proofStatus?: BridgeProofRecord['bridgeProofVerificationStatus'];
    readonly recoveryEpoch?: number;
    readonly rosterPosition: number;
};

const createActionContext = (input: {
    readonly actionSequence: number;
    readonly boardSequence: number;
    readonly contextDigest: ProtocolDigest;
    readonly deviceEpoch: number;
    readonly recoveryEpoch: number;
    readonly rosterExternalAcceptanceDigest: ProtocolDigest;
    readonly signerIdentity: string;
}): ActionContext => ({
    acceptedRecoveryEpochUpdateDigest: null,
    actionContextDigest: deriveProtocolDigest('ActionContextDigest', {
        actionSequence: input.actionSequence,
        boardSequence: input.boardSequence,
        contextDigest: input.contextDigest,
        signerIdentity: input.signerIdentity,
    }),
    actionSequence: input.actionSequence,
    boardHeadDigest: baseFields.votingClosedBoardHeadDigest,
    boardSequence: input.boardSequence,
    ceremonyId: baseFields.ceremonyId,
    contextDigest: input.contextDigest,
    deviceEpoch: input.deviceEpoch,
    electionManifestDigest: baseFields.manifestDigest,
    recoveryEpoch: input.recoveryEpoch,
    recoveryPolicyDigest: digest('recovery-policy'),
    rosterExternalAcceptanceDigest: input.rosterExternalAcceptanceDigest,
    signerIdentity: input.signerIdentity,
});

const createSignatureEnvelope = (input: {
    readonly contextDigest: ProtocolDigest;
    readonly deviceEpoch: number;
    readonly recoveryEpoch: number;
    readonly signerIdentity: string;
}): ProtocolSignatureEnvelope => ({
    profile: {
        algorithm: 'ML-DSA-65',
        contextString: 'sealed-lattice-test',
        contextStringByteLength: 'sealed-lattice-test'.length,
        errataStatus: 'test-fixture',
        fips204Version: 'FIPS 204',
        mode: 'PureMLDSA',
        providerBuildDigest: digest('provider-build'),
        providerName: 'fixture-provider',
        providerVersion: '0.0.0',
    },
    publicKeyBytesHex: '00'.repeat(32),
    publicKeyDigest: digest(`public-key-${input.signerIdentity}`),
    signatureBytesHex: '11'.repeat(64),
    signatureDigest: digest(`signature-${input.signerIdentity}`),
    signedRoot: {
        boardHeadDigest: baseFields.votingClosedBoardHeadDigest,
        byteLength: 0,
        ceremonyId: baseFields.ceremonyId,
        chunkMerkleRoot: null,
        contextDigest: input.contextDigest,
        deviceEpoch: input.deviceEpoch,
        manifestDigest: baseFields.manifestDigest,
        objectRoot: digest(`signed-root-${input.signerIdentity}`),
        objectType: 'AggregateContribution',
        objectVersion: 1,
        recoveryEpoch: input.recoveryEpoch,
        signerIdentity: input.signerIdentity,
        signerRole: 'Trustee',
    },
});

const createAggregateContributionFixture = (
    input: ContributionFixtureInput,
): AggregateContribution => {
    const contributorIdentity = `trustee-${input.rosterPosition}`;
    const contributorRosterExternalAcceptanceDigest = digest(
        `acceptance-${input.rosterPosition}`,
    );
    const boardSequence = input.boardSequence ?? input.rosterPosition;
    const boardPosition = input.boardPosition ?? input.rosterPosition;
    const recoveryEpoch = input.recoveryEpoch ?? 0;
    const deviceEpoch = input.deviceEpoch ?? 0;
    const actionSequence = input.rosterPosition;
    const postVotingClosedContextDigest =
        input.contextDigest ?? baseFields.postVotingClosedContextDigest;
    const bridgeProofProfileDigest = deriveBridgeProofProfileDigest({
        bgvEncryptionProofSubrelation: 'SealedLatticeBoundedEncryptionRelation',
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        proofBackend: 'SealedLatticeBridgeRelation',
    });
    const aggregateDerivationComponentDigest = digest(
        `aggregate-derivation-${input.rosterPosition}`,
    );
    const aggregateShareCommitmentDigest = digest(
        `aggregate-share-commitment-${input.rosterPosition}`,
    );
    const encryptedAggregateShareCiphertextRoot =
        input.encryptedAggregateShareCiphertextRoot ??
        digest(`aggregate-share-ciphertext-${input.rosterPosition}`);
    const bridgeProofTargetContractDigest =
        deriveBridgeProofTargetContractDigest({
            aggregateQuotientCoordinateCount: 220,
            aggregateReducedCoordinateCount: 220,
        });
    const actionContext = createActionContext({
        actionSequence,
        boardSequence,
        contextDigest: postVotingClosedContextDigest,
        deviceEpoch,
        recoveryEpoch,
        rosterExternalAcceptanceDigest:
            contributorRosterExternalAcceptanceDigest,
        signerIdentity: contributorIdentity,
    });
    const proofStatementDigest = deriveBridgeProofStatementDigest({
        aggregateDerivationComponentDigest,
        aggregateInputEncodingProfileDigest:
            baseFields.aggregateInputEncodingProfileDigest,
        aggregateQuotientCoordinateCount: 220,
        aggregateReducedCoordinateCount: 220,
        aggregateSelectionPolicyDigest:
            baseFields.aggregateSelectionPolicyDigest,
        aggregateShareCommitmentDigest,
        aggregateToPlaintextBindingStatus:
            'AggregateToPlaintextBindingProofPending',
        ballotScoreEncodingProfileDigest:
            baseFields.ballotScoreEncodingProfileDigest,
        ballotSetDigest: baseFields.ballotSetDigest,
        ballotShareLayoutProfileDigest:
            baseFields.ballotShareLayoutProfileDigest,
        basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
        bgvBatchEncoderDigest: baseFields.bgvBatchEncoderDigest,
        bgvEncryptionProofStatus: 'BoundedEncryptionProofPending',
        bgvProfileDigest: baseFields.bgvProfileDigest,
        bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
        bridgeLayoutDigest: baseFields.encryptedAggregateInputLayoutDigest,
        bridgeProofTargetContractDigest,
        bridgeWitnessPrivacyProfileDigest:
            baseFields.bridgeWitnessPrivacyProfileDigest,
        canonicalByteLength: 180_781,
        canonicalBytesHash512: '4'.repeat(128),
        canonicalCiphertextConventionDigest:
            baseFields.canonicalCiphertextConventionDigest,
        ceremonyId: baseFields.ceremonyId,
        ciphertextRoot: digest(`bridge-ciphertext-${input.rosterPosition}`),
        coefficientDomainCanonical: true,
        coefficientCount: 32_768,
        collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
        contributorActionContextDigest: actionContext.actionContextDigest,
        contributorIdentity,
        contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: input.rosterPosition,
        encodedAggregateLayoutDigest: baseFields.encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            baseFields.encodedShareVectorLayoutDigest,
        encryptedAggregateBridgeDigest:
            baseFields.encryptedAggregateBridgeDigest,
        encryptedAggregateInputLayoutDigest:
            baseFields.encryptedAggregateInputLayoutDigest,
        encryptedAggregateReconstructionDigest:
            baseFields.encryptedAggregateReconstructionDigest,
        encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisDataRoot:
            baseFields.encryptedAggregateTargetBasisDataRoot,
        heParamDigest: baseFields.heParamDigest,
        hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze',
        level: 15,
        manifestDigest: baseFields.manifestDigest,
        plaintextRoot: digest(`bridge-plaintext-${input.rosterPosition}`),
        pollSpecDigest: baseFields.pollSpecDigest,
        postVotingClosedContextDigest,
        proofProfileDigest: bridgeProofProfileDigest,
        rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyProofPending',
        rosterDigest: baseFields.rosterDigest,
        rustBgvBackendProfileDigest: baseFields.rustBgvBackendProfileDigest,
        sampledPublicRelationCheckPolicyDigest,
        sampledOnlyBridgeVerificationAccepted: false,
        shareCommitmentMessageBoundCertDigest:
            baseFields.shareCommitmentMessageBoundCertDigest,
        sharedWitnessBindingRequired: true,
        sharedWitnessBindingStatus: 'SharedWitnessBindingProofPending',
        slotCount: 32_768,
        thresholdProfileDigest: baseFields.thresholdProfileDigest,
        topKEvaluatorInputLayoutDigest:
            baseFields.topKEvaluatorInputLayoutDigest,
        votingClosedBoardHeadDigest: baseFields.votingClosedBoardHeadDigest,
    });
    const bridgeProofRecordPayload: Omit<
        BridgeProofRecord,
        'bridgeProofRecordDigest'
    > = {
        ...baseFields,
        aggregateDerivationComponentDigest,
        aggregateShareCommitmentDigest,
        bgvEncryptionProofSubrelation: 'SealedLatticeBoundedEncryptionRelation',
        bridgeProofProfileDigest,
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        bridgeProofTargetContractDigest,
        bridgeProofVerificationStatus:
            input.proofStatus ?? 'BridgeProofRelationChecked',
        contributorIdentity,
        contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: input.rosterPosition,
        encryptedAggregateShareCiphertextRoot,
        objectType: 'BridgeProofRecord',
        objectVersion: 1,
        postVotingClosedContextDigest,
        proofBackend: 'SealedLatticeBridgeRelation',
        proofBytesDigest: digest(`bridge-proof-bytes-${input.rosterPosition}`),
        proofEncodingProfileDigest: digest('bridge-proof-encoding'),
        proofParameterSetDigest: digest('bridge-proof-parameters'),
        proofRoot: digest(`bridge-proof-root-${input.rosterPosition}`),
        proofSizeBytes: 128,
        proofStatementDigest,
        publicRandomnessDigest: digest(
            `bridge-proof-randomness-${input.rosterPosition}`,
        ),
    };
    const bridgeProofRecord = {
        ...bridgeProofRecordPayload,
        bridgeProofRecordDigest: deriveBridgeProofRecordDigest(
            bridgeProofRecordPayload,
        ),
    };
    const contributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionDigest'
    > = {
        ...baseFields,
        actionContext,
        actionSequence,
        aggregateDerivationComponentDigest,
        aggregateShareCommitmentDigest,
        boardPosition,
        boardSequence,
        bridgeProofProfileDigest,
        bridgeProofRecord,
        bridgeProofRecordDigest: bridgeProofRecord.bridgeProofRecordDigest,
        contributorIdentity,
        contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: input.rosterPosition,
        deviceEpoch,
        encryptedAggregateShareCiphertextRoot,
        objectType: 'AggregateContribution',
        objectVersion: 1,
        postVotingClosedContextDigest,
        recoveryEpoch,
        signature: createSignatureEnvelope({
            contextDigest: postVotingClosedContextDigest,
            deviceEpoch,
            recoveryEpoch,
            signerIdentity: contributorIdentity,
        }),
    };

    return {
        ...contributionPayload,
        aggregateContributionDigest:
            deriveAggregateContributionDigest(contributionPayload),
    };
};

const createAggregateDerivationComponentFixture = (input: {
    readonly aggregateDerivationComponentDigest: ProtocolDigest;
    readonly aggregateShareCommitmentDigest: ProtocolDigest;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceDigest: ProtocolDigest;
    readonly contributorRosterPosition: number;
}): AggregateDerivationComponent =>
    ({
        aggregateCommitment: {
            aggregateShareCommitmentDigest:
                input.aggregateShareCommitmentDigest,
            commitmentBodyDigest: digest('commitment-body'),
            commitmentPolynomialVector: [['0']],
            contributorIdentity: input.contributorIdentity,
            contributorRosterPosition: input.contributorRosterPosition,
            manifestDigest: baseFields.manifestDigest,
            objectType: 'AggregateShareCommitment',
            objectVersion: 1,
            pollSpecDigest: baseFields.pollSpecDigest,
            rosterDigest: baseFields.rosterDigest,
            shareCommitmentProfileDigest: digest('share-commitment-profile'),
            shareVectorWidth: 22,
        },
        aggregateDerivationComponentDigest:
            input.aggregateDerivationComponentDigest,
        objectType: 'AggregateDerivationComponent',
        objectVersion: 1,
        shareCommitmentMessageBoundCert: {
            commitmentMessageBound: '1000000',
            fieldModulus: 65537,
            maximumAggregateInteger: 655_360,
            maximumCanonicalTurnout: 10,
            noWraparoundCondition: {
                maximumAggregateIntegerLessThanCommitmentMessageBound: true,
                openingRandomnessAggregateBoundMatchesTurnout: true,
            },
            objectType: 'ShareCommitmentMessageBoundCert',
            objectVersion: 1,
            openingRandomnessAggregateBound: 10,
            openingRandomnessSingleBound: 1,
            perBallotShareRepresentativeRange: [0, 65536],
            profileDigest: digest('bound-cert-profile'),
            profileId: 'fixture-bound-cert',
            quotientBoundForAggregateReduction: 10,
            shareCommitmentMessageBoundCertDigest:
                baseFields.shareCommitmentMessageBoundCertDigest,
            shareCommitmentProfileDigest: digest('share-commitment-profile'),
            shareVectorWidth: 22,
        },
        statement: {
            aggregateCommitmentDigest: input.aggregateShareCommitmentDigest,
            aggregateDerivationStatementDigest: digest(
                'aggregate-derivation-statement',
            ),
            aggregateInputEncodingProfileDigest:
                baseFields.aggregateInputEncodingProfileDigest,
            aggregateShareCommitmentDigest:
                input.aggregateShareCommitmentDigest,
            ballotScoreEncodingProfileDigest:
                baseFields.ballotScoreEncodingProfileDigest,
            ballotSetDigest: baseFields.ballotSetDigest,
            ballotShareLayoutProfileDigest:
                baseFields.ballotShareLayoutProfileDigest,
            canonicalTurnout: 1,
            ceremonyId: baseFields.ceremonyId,
            challengeDomainDigest: digest('challenge-domain'),
            closeRecordDigest: baseFields.closeRecordDigest,
            contributorActionContextDigest: digest('action-context'),
            contributorIdentity: input.contributorIdentity,
            contributorRosterExternalAcceptanceDigest:
                input.contributorRosterExternalAcceptanceDigest,
            contributorRosterPosition: input.contributorRosterPosition,
            encodedAggregateLayoutDigest:
                baseFields.encodedAggregateLayoutDigest,
            encodedShareVectorLayoutDigest:
                baseFields.encodedShareVectorLayoutDigest,
            manifestDigest: baseFields.manifestDigest,
            objectType: 'AggregateDerivationStatement',
            objectVersion: 1,
            optionCount: 2,
            packageReferences: [],
            participantCount: 20,
            pollSpecDigest: baseFields.pollSpecDigest,
            postVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
            proofEncodingProfileId: 'fixture-proof-encoding',
            proofParameterProfileId: 'fixture-proof-parameters',
            proofProfileId: 'fixture-proof',
            receiverEncryptionProfileDigest: digest('receiver-profile'),
            rosterDigest: baseFields.rosterDigest,
            shareCommitmentMessageBoundCertDigest:
                baseFields.shareCommitmentMessageBoundCertDigest,
            shareCommitmentProfileDigest: digest('share-commitment-profile'),
            shareVectorWidth: 22,
            thresholdProfileDigest: baseFields.thresholdProfileDigest,
            votingClosedBoardHeadDigest: baseFields.votingClosedBoardHeadDigest,
        },
    }) as unknown as AggregateDerivationComponent;

const createSetupEvidenceFixture =
    (): PendingBridgeProofRecordFromEvidenceInput['setupPackage'] => ({
        collectivePublicKey: {
            bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
            collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
        },
        profileBindings: {
            aggregateInputEncodingProfileDigest:
                baseFields.aggregateInputEncodingProfileDigest,
            backendProfileDigest: baseFields.rustBgvBackendProfileDigest,
            ballotScoreEncodingProfileDigest:
                baseFields.ballotScoreEncodingProfileDigest,
            ballotShareLayoutProfileDigest:
                baseFields.ballotShareLayoutProfileDigest,
            batchEncoderDigest: baseFields.bgvBatchEncoderDigest,
            canonicalCiphertextConventionDigest:
                baseFields.canonicalCiphertextConventionDigest,
            encodedAggregateLayoutDigest:
                baseFields.encodedAggregateLayoutDigest,
            encryptedAggregateBridgeDigest:
                baseFields.encryptedAggregateBridgeDigest,
            encryptedAggregateInputLayoutDigest:
                baseFields.encryptedAggregateInputLayoutDigest,
            encryptedAggregateReconstructionDigest:
                baseFields.encryptedAggregateReconstructionDigest,
            encryptedAggregateTargetBasisDataRoot:
                baseFields.encryptedAggregateTargetBasisDataRoot,
            profileDigest: baseFields.bgvProfileDigest,
            topKEvaluatorInputLayoutDigest:
                baseFields.topKEvaluatorInputLayoutDigest,
        },
        setupInputs: {
            ceremonyId: baseFields.ceremonyId,
            manifestDigest: baseFields.manifestDigest,
            rosterDigest: baseFields.rosterDigest,
            thresholdProfileDigest: baseFields.thresholdProfileDigest,
        },
    });

const recoveryMapFor = (
    contributions: readonly AggregateContribution[],
): Record<string, RecoveryEpochMapEntry> =>
    Object.fromEntries(
        contributions.map((contribution) => [
            contribution.contributorIdentity,
            {
                currentDeviceEpoch: contribution.deviceEpoch,
                currentRecoveryEpoch: contribution.recoveryEpoch,
                signerIdentity: contribution.contributorIdentity,
            },
        ]),
    );

describe('encrypted aggregate bridge objects', () => {
    it('creates pending bridge proof records from checked kernel bridge evidence', () => {
        const contributorIdentity = 'trustee-1';
        const contributorRosterExternalAcceptanceDigest =
            digest('acceptance-1');
        const aggregateDerivationComponentDigest = digest(
            'aggregate-derivation-1',
        );
        const aggregateShareCommitmentDigest = digest(
            'aggregate-share-commitment-1',
        );
        const aggregateDerivationComponent =
            createAggregateDerivationComponentFixture({
                aggregateDerivationComponentDigest,
                aggregateShareCommitmentDigest,
                contributorIdentity,
                contributorRosterExternalAcceptanceDigest,
                contributorRosterPosition: 1,
            });
        const setupPackage = createSetupEvidenceFixture();
        const bridgeProofProfileDigest = deriveBridgeProofProfileDigest({
            bgvEncryptionProofSubrelation:
                'SealedLatticeBoundedEncryptionRelation',
            bridgeProofProfileId: encryptedAggregateBridgeProfileId,
            proofBackend: 'SealedLatticeBridgeRelation',
        });
        const encryptedAggregateShareCiphertextRoot = digest(
            'aggregate-share-ciphertext-1',
        );
        const canonicalBytesHash512 = '4'.repeat(128);
        const canonicalByteLength = 180_781;
        const bridgeProofTargetContractDigest =
            deriveBridgeProofTargetContractDigest({
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
            });
        const bridgeProofStatementDigest = deriveBridgeProofStatementDigest({
            aggregateDerivationComponentDigest,
            aggregateInputEncodingProfileDigest:
                baseFields.aggregateInputEncodingProfileDigest,
            aggregateQuotientCoordinateCount:
                aggregateDerivationComponent.statement.shareVectorWidth,
            aggregateReducedCoordinateCount:
                aggregateDerivationComponent.statement.shareVectorWidth,
            aggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            aggregateShareCommitmentDigest,
            aggregateToPlaintextBindingStatus:
                'AggregateToPlaintextBindingProofPending',
            ballotScoreEncodingProfileDigest:
                baseFields.ballotScoreEncodingProfileDigest,
            ballotSetDigest: baseFields.ballotSetDigest,
            ballotShareLayoutProfileDigest:
                baseFields.ballotShareLayoutProfileDigest,
            basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
            bgvBatchEncoderDigest: baseFields.bgvBatchEncoderDigest,
            bgvEncryptionProofStatus: 'BoundedEncryptionProofPending',
            bgvProfileDigest: baseFields.bgvProfileDigest,
            bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
            bridgeLayoutDigest: baseFields.encryptedAggregateInputLayoutDigest,
            bridgeProofTargetContractDigest,
            bridgeWitnessPrivacyProfileDigest:
                baseFields.bridgeWitnessPrivacyProfileDigest,
            canonicalByteLength,
            canonicalBytesHash512,
            canonicalCiphertextConventionDigest:
                baseFields.canonicalCiphertextConventionDigest,
            ceremonyId: baseFields.ceremonyId,
            ciphertextRoot: digest('bridge-ciphertext-1'),
            coefficientDomainCanonical: true,
            coefficientCount: 32_768,
            collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
            contributorActionContextDigest:
                aggregateDerivationComponent.statement
                    .contributorActionContextDigest,
            contributorIdentity,
            contributorRosterExternalAcceptanceDigest,
            contributorRosterPosition: 1,
            encodedAggregateLayoutDigest:
                baseFields.encodedAggregateLayoutDigest,
            encodedShareVectorLayoutDigest:
                baseFields.encodedShareVectorLayoutDigest,
            encryptedAggregateBridgeDigest:
                baseFields.encryptedAggregateBridgeDigest,
            encryptedAggregateInputLayoutDigest:
                baseFields.encryptedAggregateInputLayoutDigest,
            encryptedAggregateReconstructionDigest:
                baseFields.encryptedAggregateReconstructionDigest,
            encryptedAggregateShareCiphertextRoot,
            encryptedAggregateTargetBasisDataRoot:
                baseFields.encryptedAggregateTargetBasisDataRoot,
            heParamDigest: baseFields.heParamDigest,
            hwangPiopStatus:
                'DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze',
            level: 15,
            manifestDigest: baseFields.manifestDigest,
            plaintextRoot: digest('bridge-plaintext-1'),
            pollSpecDigest: baseFields.pollSpecDigest,
            postVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
            proofProfileDigest: bridgeProofProfileDigest,
            rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyProofPending',
            rosterDigest: baseFields.rosterDigest,
            rustBgvBackendProfileDigest: baseFields.rustBgvBackendProfileDigest,
            sampledPublicRelationCheckPolicyDigest,
            sampledOnlyBridgeVerificationAccepted: false,
            shareCommitmentMessageBoundCertDigest:
                baseFields.shareCommitmentMessageBoundCertDigest,
            sharedWitnessBindingRequired: true,
            sharedWitnessBindingStatus: 'SharedWitnessBindingProofPending',
            slotCount: 32_768,
            thresholdProfileDigest: baseFields.thresholdProfileDigest,
            topKEvaluatorInputLayoutDigest:
                baseFields.topKEvaluatorInputLayoutDigest,
            votingClosedBoardHeadDigest: baseFields.votingClosedBoardHeadDigest,
        });
        const aggregateRelationChallengeHex = '1'.repeat(48);
        const aggregateRelationCommitmentDigest = digest(
            'aggregate-relation-commitment-1',
        );
        const aggregateRelationSubproofSizeBytes = 384;
        const bridgeProofBytesDigest = digest('bridge-proof-bytes-1');
        const bridgeProofRoot = digest('bridge-proof-root-1');
        const bridgeEncryptionEvidence: PendingBridgeProofRecordFromEvidenceInput['bridgeEncryptionEvidence'] =
            {
                aggregateDerivationComponentDigest,
                aggregateDerivationStatementDigest:
                    aggregateDerivationComponent.statement
                        .aggregateDerivationStatementDigest,
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateRelationChallengeHex,
                aggregateRelationCommitmentDigest,
                aggregateRelationSubproofSizeBytes,
                basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
                bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
                bridgeProofBytesDigest,
                bridgeProofBytesHex: 'aa',
                bridgeProofProfileDigest,
                bridgeProofRoot,
                bridgeProofStatementDigest,
                bridgeProofTargetContractDigest,
                bridgeProofVerificationStatus:
                    'BridgeProofBackendPending' as const,
                canonicalByteLength,
                canonicalBytesHash512,
                canonicalCiphertextConventionDigest:
                    baseFields.canonicalCiphertextConventionDigest,
                ciphertextRoot: digest('bridge-ciphertext-1'),
                coefficientCount: 32_768,
                collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
                encryptedAggregateShareCiphertextRoot,
                level: 15,
                plaintextRoot: digest('bridge-plaintext-1'),
                profileDigest: baseFields.bgvProfileDigest,
                rustBgvBackendProfileDigest:
                    baseFields.rustBgvBackendProfileDigest,
                sampledPublicRelationCheckPolicy,
                sampledPublicRelationChecks,
                slotCount: 32_768,
            };
        const bridgeEvidenceVerification: PendingBridgeProofRecordFromEvidenceInput['bridgeEvidenceVerification'] =
            {
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateRelationChallengeHex,
                aggregateRelationCommitmentDigest,
                aggregateRelationSubproofSizeBytes,
                bridgeEvidenceVerificationStatus:
                    'BridgeProofEvidenceChecked' as const,
                bridgeProofBytesDigest,
                bridgeProofProfileDigest,
                bridgeProofRoot,
                bridgeProofStatementDigest,
                bridgeProofTargetContractDigest,
                bridgeProofVerificationStatus:
                    'BridgeProofBackendPending' as const,
                encryptedAggregateShareCiphertextRoot,
                ok: true as const,
            };

        const bridgeProofRecord =
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            });

        expect(bridgeProofRecord).toMatchObject({
            aggregateDerivationComponentDigest,
            aggregateShareCommitmentDigest,
            bridgeProofVerificationStatus: 'BridgeProofBackendPending',
            encryptedAggregateShareCiphertextRoot,
            proofSizeBytes: 1,
            proofStatementDigest: bridgeProofStatementDigest,
            bridgeProofTargetContractDigest,
        });
        expect(
            verifyAggregateContributionStructure(
                createAggregateContributionFixture({
                    proofStatus:
                        bridgeProofRecord.bridgeProofVerificationStatus,
                    rosterPosition: 1,
                }),
            ),
        ).toMatchObject({
            backendAvailable: false,
            ok: true,
            unresolvedReason: 'OperationUnavailable',
        });
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofRoot: digest('wrong-bridge-proof-root'),
                },
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/bridge proof root/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    bridgeProofStatementDigest: digest(
                        'wrong-bridge-proof-statement',
                    ),
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofStatementDigest: digest(
                        'wrong-bridge-proof-statement',
                    ),
                },
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    bridgeProofTargetContractDigest: digest(
                        'wrong-bridge-proof-target-contract',
                    ),
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofTargetContractDigest: digest(
                        'wrong-bridge-proof-target-contract',
                    ),
                },
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof target contract digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateRelationChallengeHex: '0'.repeat(48),
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/aggregate relation challenge summary/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateRelationSubproofSizeBytes:
                        aggregateRelationSubproofSizeBytes + 1,
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/aggregate relation subproof size/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateReducedCoordinateCount:
                        aggregateDerivationComponent.statement
                            .shareVectorWidth - 1,
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/aggregate reduced coordinate count/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    canonicalBytesHash512: '5'.repeat(128),
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest: digest(
                    'wrong-aggregate-selection-policy',
                ),
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest: digest(
                    'wrong-bridge-witness-privacy',
                ),
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: digest('wrong-he-param'),
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
    });

    it('creates proof-checked aggregate contributions from checked bridge proof records', () => {
        const expectedContribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });

        const contribution = createAggregateContributionFromBridgeProofRecord({
            actionContext: expectedContribution.actionContext,
            boardPosition: expectedContribution.boardPosition,
            bridgeProofRecord: expectedContribution.bridgeProofRecord,
            closeRecordDigest: expectedContribution.closeRecordDigest,
            signature: expectedContribution.signature,
        });

        expect(contribution).toEqual(expectedContribution);
        expect(
            verifyAggregateContributionStructure(contribution),
        ).toMatchObject({
            backendAvailable: true,
            ok: true,
            unresolvedReason: null,
        });
        expect(contribution.bridgeProofRecordDigest).toBe(
            contribution.bridgeProofRecord.bridgeProofRecordDigest,
        );
        expect(contribution.contributorIdentity).toBe('trustee-1');
        expect(contribution.encryptedAggregateShareCiphertextRoot).toBe(
            expectedContribution.bridgeProofRecord
                .encryptedAggregateShareCiphertextRoot,
        );
    });

    it('rejects aggregate contribution creation from pending or mismatched bridge proof records', () => {
        const checkedContribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const pendingContribution = createAggregateContributionFixture({
            proofStatus: 'BridgeProofBackendPending',
            rosterPosition: 1,
        });

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: pendingContribution.actionContext,
                boardPosition: pendingContribution.boardPosition,
                bridgeProofRecord: pendingContribution.bridgeProofRecord,
                closeRecordDigest: pendingContribution.closeRecordDigest,
                signature: pendingContribution.signature,
            }),
        ).toThrow(/proof-checked bridge proof record/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: {
                    ...checkedContribution.actionContext,
                    signerIdentity: 'trustee-2',
                },
                boardPosition: checkedContribution.boardPosition,
                bridgeProofRecord: checkedContribution.bridgeProofRecord,
                closeRecordDigest: checkedContribution.closeRecordDigest,
                signature: checkedContribution.signature,
            }),
        ).toThrow(/action context/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: checkedContribution.actionContext,
                boardPosition: checkedContribution.boardPosition,
                bridgeProofRecord: checkedContribution.bridgeProofRecord,
                closeRecordDigest: 'not-a-digest' as ProtocolDigest,
                signature: checkedContribution.signature,
            }),
        ).toThrow(/close-record digest/u);
    });

    it('rejects aggregate contribution creation when the signature context does not bind the contribution', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: contribution.actionContext,
                boardPosition: contribution.boardPosition,
                bridgeProofRecord: contribution.bridgeProofRecord,
                closeRecordDigest: contribution.closeRecordDigest,
                signature: {
                    ...contribution.signature,
                    signedRoot: {
                        ...contribution.signature.signedRoot,
                        signerIdentity: 'trustee-2',
                    },
                },
            }),
        ).toThrow(/signature envelope/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: contribution.actionContext,
                boardPosition: contribution.boardPosition,
                bridgeProofRecord: contribution.bridgeProofRecord,
                closeRecordDigest: contribution.closeRecordDigest,
                signature: {
                    ...contribution.signature,
                    signedRoot: {
                        ...contribution.signature.signedRoot,
                        objectType: 'BridgeProofRecord',
                    },
                } as unknown as ProtocolSignatureEnvelope,
            }),
        ).toThrow(/signature envelope/u);
    });

    it('derives stable witness-clean contribution hashes and rejects stale mutations', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const changedContribution = createAggregateContributionFixture({
            encryptedAggregateShareCiphertextRoot: digest(
                'changed-share-ciphertext',
            ),
            rosterPosition: 1,
        });
        const staleContribution = {
            ...contribution,
            encryptedAggregateShareCiphertextRoot: digest(
                'stale-share-ciphertext',
            ),
        };

        expect(
            verifyAggregateContributionStructure(contribution),
        ).toMatchObject({
            backendAvailable: true,
            ok: true,
            unresolvedReason: null,
        });
        expect(contribution.aggregateContributionDigest).not.toBe(
            changedContribution.aggregateContributionDigest,
        );
        expect(contribution).not.toHaveProperty('bridgeWitness');
        expect(contribution).not.toHaveProperty('bgvPlaintext');
        expect(contribution).not.toHaveProperty('encryptionRandomness');
        expect(
            verifyAggregateContributionStructure(
                staleContribution as AggregateContribution,
            ),
        ).toMatchObject({
            ok: false,
        });
    });

    it('rejects public witness fields anywhere in the aggregate contribution object', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const leakyContribution = {
            ...contribution,
            bridgeProofRecord: {
                ...contribution.bridgeProofRecord,
                bgvPlaintext: [1, 2, 3],
            },
        };

        const verification = verifyAggregateContributionStructure(
            leakyContribution as AggregateContribution,
        );

        expect(verification.ok).toBe(false);
        expect(
            verification.refusedObjects.some((refusal) =>
                refusal.message.includes('bgvPlaintext'),
            ),
        ).toBe(true);
    });

    it('selects the first proof-valid aggregate contributors and keeps later arrivals out of the selected order hash', () => {
        const earlyContribution = createAggregateContributionFixture({
            boardSequence: 10,
            rosterPosition: 1,
        });
        const secondContribution = createAggregateContributionFixture({
            boardSequence: 20,
            rosterPosition: 2,
        });
        const lateContribution = createAggregateContributionFixture({
            boardSequence: 30,
            rosterPosition: 3,
        });
        const laterExtraContribution = createAggregateContributionFixture({
            boardSequence: 100,
            rosterPosition: 4,
        });
        const recoveryMap = recoveryMapFor([
            earlyContribution,
            secondContribution,
            lateContribution,
            laterExtraContribution,
        ]);

        const selection = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 2,
            contributions: [
                lateContribution,
                secondContribution,
                earlyContribution,
            ],
            currentRecoveryEpochMap: recoveryMap,
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });
        const selectionWithLateExtra = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 2,
            contributions: [
                lateContribution,
                laterExtraContribution,
                secondContribution,
                earlyContribution,
            ],
            currentRecoveryEpochMap: recoveryMap,
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });

        expect(selection.ok).toBe(true);
        expect(
            selection.selectedContributions.map(
                (contribution) => contribution.contributorRosterPosition,
            ),
        ).toEqual([1, 2]);
        expect(selectionWithLateExtra.firstValidOrderDigest).toBe(
            selection.firstValidOrderDigest,
        );
    });

    it('rejects conflicting duplicate identities, stale recovery epochs, and stale contexts', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const duplicateIdentityContribution =
            createAggregateContributionFixture({
                encryptedAggregateShareCiphertextRoot: digest(
                    'duplicate-identity-ciphertext',
                ),
                rosterPosition: 1,
            });
        const staleRecoveryContribution = createAggregateContributionFixture({
            recoveryEpoch: 0,
            rosterPosition: 2,
        });
        const wrongContextContribution = createAggregateContributionFixture({
            contextDigest: digest('wrong-post-voting-context'),
            rosterPosition: 3,
        });

        expect(
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: 1,
                contributions: [contribution, duplicateIdentityContribution],
                currentRecoveryEpochMap: recoveryMapFor([contribution]),
                expectedAggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    baseFields.postVotingClosedContextDigest,
            }).refusedObjects.some(
                (refusal) => refusal.code === 'ConflictingFirstValidObject',
            ),
        ).toBe(true);

        expect(
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: 1,
                contributions: [staleRecoveryContribution],
                currentRecoveryEpochMap: {
                    [staleRecoveryContribution.contributorIdentity]: {
                        currentDeviceEpoch: 1,
                        currentRecoveryEpoch: 1,
                        signerIdentity:
                            staleRecoveryContribution.contributorIdentity,
                    },
                },
                expectedAggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    baseFields.postVotingClosedContextDigest,
            }).refusedObjects.some(
                (refusal) => refusal.code === 'StaleRecoveryEpoch',
            ),
        ).toBe(true);

        expect(
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: 1,
                contributions: [wrongContextContribution],
                currentRecoveryEpochMap: recoveryMapFor([
                    wrongContextContribution,
                ]),
                expectedAggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    baseFields.postVotingClosedContextDigest,
            }).refusedObjects.some(
                (refusal) => refusal.code === 'FirstValidContextMismatch',
            ),
        ).toBe(true);
    });

    it('creates aggregate-ready records from recomputed interpolation coefficients', () => {
        const selectedContributions = [
            createAggregateContributionFixture({ rosterPosition: 1 }),
            createAggregateContributionFixture({ rosterPosition: 2 }),
        ];
        const selection = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 2,
            contributions: selectedContributions,
            currentRecoveryEpochMap: recoveryMapFor(selectedContributions),
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });
        const coefficientReport = deriveInterpolationCoefficientReport({
            contributorRosterPositions: [1, 2],
            rosterSize: 20,
            threshold: 2,
        });
        const record = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderDigest:
                selection.firstValidOrderDigest ?? digest('missing'),
            rosterSize: 20,
            selectedContributions: selection.selectedContributions,
            suppliedInterpolationCoefficientReport: coefficientReport,
        });
        const repeatedRecord = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderDigest:
                selection.firstValidOrderDigest ?? digest('missing'),
            rosterSize: 20,
            selectedContributions: selection.selectedContributions,
        });
        const changedContribution = createAggregateContributionFixture({
            encryptedAggregateShareCiphertextRoot: digest(
                'changed-ready-ciphertext',
            ),
            rosterPosition: 2,
        });
        const changedSelection = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 2,
            contributions: [selectedContributions[0], changedContribution],
            currentRecoveryEpochMap: recoveryMapFor([
                selectedContributions[0],
                changedContribution,
            ]),
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });
        const changedRecord = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderDigest:
                changedSelection.firstValidOrderDigest ?? digest('missing'),
            rosterSize: 20,
            selectedContributions: changedSelection.selectedContributions,
        });
        const mismatchedReport = {
            ...coefficientReport,
            coefficients: [
                {
                    ...coefficientReport.coefficients[0],
                    coefficient:
                        (coefficientReport.coefficients[0]?.coefficient ?? 0) +
                        1,
                },
                ...coefficientReport.coefficients.slice(1),
            ],
        };

        expect(selection.ok).toBe(true);
        expect(record.interpolationCoefficientReportDigest).toBe(
            coefficientReport.reportDigest,
        );
        expect(record.selectedContributorRosterPositions).toEqual([1, 2]);
        expect(record.aggregateReadyRecordDigest).toBe(
            repeatedRecord.aggregateReadyRecordDigest,
        );
        expect(changedRecord.aggregateReadyRecordDigest).not.toBe(
            record.aggregateReadyRecordDigest,
        );
        expect(() =>
            createAggregateReadyRecord({
                aggregateContributionQuorum: 2,
                firstValidOrderDigest:
                    selection.firstValidOrderDigest ?? digest('missing'),
                rosterSize: 20,
                selectedContributions: selection.selectedContributions,
                suppliedInterpolationCoefficientReport: mismatchedReport,
            }),
        ).toThrow(/does not match recomputation/u);
    });
});
