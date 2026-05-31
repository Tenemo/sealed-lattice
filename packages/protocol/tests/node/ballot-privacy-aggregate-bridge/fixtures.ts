import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveProtocolHash,
} from '@sealed-lattice/crypto';
import {
    encryptedAggregateBridgeProfileId,
    type ActionContext,
    type AggregateContribution,
    type AggregateDerivationComponent,
    type BridgeProofRecord,
    type ProtocolHash,
    type ProtocolSignatureEnvelope,
    type RecoveryEpochMapEntry,
} from '@sealed-lattice/types';

import type { PendingBridgeProofRecordFromEvidenceInput } from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    deriveAggregateContributionHash,
    deriveBridgeProofChallengeContextHash,
    deriveBridgeProofProfileHash,
    deriveBridgeProofRecordHash,
    deriveBridgeProofStatementHash,
    deriveBridgeProofTargetContractHash,
} from '#packages/protocol/src/ballot-privacy/index.js';
export const hash = (label: string): ProtocolHash =>
    deriveProtocolHash('ActionContextHash', { label });

export const sampledPublicRelationCheckPolicy = {
    acceptedForBridgeProofVerification: false,
    diagnosticOnly: true,
    fullBridgeProofRequired: true,
    objectType: 'AggregateBridgeSampledRelationCheckPolicy',
    objectVersion: 1,
    relationCheckSource: 'first-data-prime-diagnostic',
    sampledOnlyBridgeVerificationAccepted: false,
    sampledRelationCheckCount: 1,
} as const;

export const sampledPublicRelationChecks = [
    {
        componentOneCoefficient: 11,
        componentZeroCoefficient: 7,
        modulus: 140_737_487_306_753,
        position: 0,
        relationMatches: true,
    },
] as const;

export const sampledPublicRelationCheckPolicyHash = deriveProtocolHash(
    'BridgeProofRecordHash',
    {
        policy: sampledPublicRelationCheckPolicy,
        purpose:
            'sealed-lattice-aggregate-bridge-sampled-public-relation-check-policy-v1',
    },
);

export const baseFields = {
    aggregateInputEncodingProfileHash: hash('aggregate-input-encoding'),
    aggregateSelectionPolicyHash: hash('aggregate-selection-policy'),
    ballotScoreEncodingProfileHash: hash('ballot-score-encoding'),
    ballotSetHash: hash('ballot-set'),
    ballotShareLayoutProfileHash: hash('ballot-share-layout'),
    bgvBatchEncoderHash: hash('bgv-batch-encoder'),
    bgvProfileHash: hash('bgv-profile'),
    bgvPublicKeyRoot: hash('bgv-public-key-root'),
    bridgeLayoutHash: hash('bridge-layout'),
    bridgeWitnessPrivacyProfileHash: hash('bridge-witness-privacy'),
    canonicalCiphertextConventionHash: hash('ciphertext-convention'),
    ceremonyId: 'ceremony-1',
    closeRecordHash: hash('close-record'),
    collectivePublicKeyRoot: hash('collective-public-key-root'),
    collectivePublicKeyCoefficientRoot: hash(
        'collective-public-key-coefficient-root',
    ),
    encodedAggregateLayoutHash: hash('encoded-aggregate-layout'),
    encodedShareVectorLayoutHash: hash('encoded-share-vector-layout'),
    encryptedAggregateBridgeHash: hash('encrypted-aggregate-bridge'),
    encryptedAggregateInputLayoutHash: hash('encrypted-aggregate-input-layout'),
    encryptedAggregateReconstructionHash: hash(
        'encrypted-aggregate-reconstruction',
    ),
    encryptedAggregateTargetBasisRoot: hash('encrypted-aggregate-target-basis'),
    heParamHash: hash('he-param'),
    manifestHash: hash('manifest'),
    optionCount: 20,
    participantCount: 20,
    pollSpecHash: hash('poll-spec'),
    postVotingClosedContextHash: hash('post-voting-closed-context'),
    rosterHash: hash('roster'),
    rustBgvBackendProfileHash: hash('rust-bgv-backend-profile'),
    setupPackageHash: hash('setup-package'),
    shareCommitmentMessageBoundCertHash: hash(
        'share-commitment-message-bound-cert',
    ),
    shareVectorWidth: 220,
    thresholdProfileHash: hash('threshold-profile'),
    topKEvaluatorInputLayoutHash: hash('top-k-evaluator-input-layout'),
    votingClosedBoardHeadHash: hash('voting-closed-board-head'),
} as const;

type ContributionFixtureInput = {
    readonly boardPosition?: number;
    readonly boardSequence?: number;
    readonly contextHash?: ProtocolHash;
    readonly deviceEpoch?: number;
    readonly encryptedAggregateShareCiphertextRoot?: ProtocolHash;
    readonly proofStatus?: BridgeProofRecord['bridgeProofVerificationStatus'];
    readonly recoveryEpoch?: number;
    readonly rosterPosition: number;
};

const createActionContext = (input: {
    readonly actionSequence: number;
    readonly boardSequence: number;
    readonly contextHash: ProtocolHash;
    readonly deviceEpoch: number;
    readonly recoveryEpoch: number;
    readonly rosterExternalAcceptanceHash: ProtocolHash;
    readonly signerIdentity: string;
}): ActionContext => ({
    acceptedRecoveryEpochUpdateHash: null,
    actionContextHash: deriveProtocolHash('ActionContextHash', {
        actionSequence: input.actionSequence,
        boardSequence: input.boardSequence,
        contextHash: input.contextHash,
        signerIdentity: input.signerIdentity,
    }),
    actionSequence: input.actionSequence,
    boardHeadHash: baseFields.votingClosedBoardHeadHash,
    boardSequence: input.boardSequence,
    ceremonyId: baseFields.ceremonyId,
    contextHash: input.contextHash,
    deviceEpoch: input.deviceEpoch,
    electionManifestHash: baseFields.manifestHash,
    recoveryEpoch: input.recoveryEpoch,
    recoveryPolicyHash: hash('recovery-policy'),
    rosterExternalAcceptanceHash: input.rosterExternalAcceptanceHash,
    signerIdentity: input.signerIdentity,
});

const createSignatureEnvelope = (input: {
    readonly contextHash: ProtocolHash;
    readonly deviceEpoch: number;
    readonly objectRoot: ProtocolHash;
    readonly recoveryEpoch: number;
    readonly signerIdentity: string;
}): ProtocolSignatureEnvelope => {
    const keyFixture = createMlDsaKeyPairFixture(
        `aggregate-contribution-${input.signerIdentity}`,
    );

    return createProtocolSignatureFixture({
        profile: createMlDsaSignatureProfileFixture(),
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        publicKeyHash: keyFixture.publicKeyHash,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            boardHeadHash: baseFields.votingClosedBoardHeadHash,
            byteLength: 64,
            ceremonyId: baseFields.ceremonyId,
            chunkMerkleRoot: null,
            contextHash: input.contextHash,
            deviceEpoch: input.deviceEpoch,
            manifestHash: baseFields.manifestHash,
            objectRoot: input.objectRoot,
            objectType: 'AggregateContribution',
            objectVersion: 1,
            recoveryEpoch: input.recoveryEpoch,
            signerIdentity: input.signerIdentity,
            signerRole: 'Trustee',
        },
    });
};

export const createAggregateContributionFixture = (
    input: ContributionFixtureInput,
): AggregateContribution => {
    const contributorIdentity = `trustee-${input.rosterPosition}`;
    const contributorRosterExternalAcceptanceHash = hash(
        `acceptance-${input.rosterPosition}`,
    );
    const boardSequence = input.boardSequence ?? input.rosterPosition;
    const boardPosition = input.boardPosition ?? input.rosterPosition;
    const recoveryEpoch = input.recoveryEpoch ?? 0;
    const deviceEpoch = input.deviceEpoch ?? 0;
    const actionSequence = input.rosterPosition;
    const postVotingClosedContextHash =
        input.contextHash ?? baseFields.postVotingClosedContextHash;
    const bridgeProofProfileHash = deriveBridgeProofProfileHash({
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofSubrelation:
            'SealedLatticePassiveCollectiveCiphertextEquationRelation',
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        claimBearingBridgeEncryption: false,
        developmentKeyOnly: false,
        proofBackend: 'SealedLatticeBridgeRelation',
        thresholdDecryptable: true,
    });
    const aggregateDerivationComponentHash = hash(
        `aggregate-derivation-${input.rosterPosition}`,
    );
    const aggregateShareCommitmentHash = hash(
        `aggregate-share-commitment-${input.rosterPosition}`,
    );
    const encryptedAggregateShareCiphertextRoot =
        input.encryptedAggregateShareCiphertextRoot ??
        hash(`aggregate-share-ciphertext-${input.rosterPosition}`);
    const bridgeProofTargetContractHash = deriveBridgeProofTargetContractHash({
        aggregateQuotientCoordinateCount: 220,
        aggregateReducedCoordinateCount: 220,
        aggregateDerivationVerificationScope:
            'AggregateDerivationFullVerificationPreconditionNotBound',
    });
    const actionContext = createActionContext({
        actionSequence,
        boardSequence,
        contextHash: postVotingClosedContextHash,
        deviceEpoch,
        recoveryEpoch,
        rosterExternalAcceptanceHash: contributorRosterExternalAcceptanceHash,
        signerIdentity: contributorIdentity,
    });
    const proofStatementHash = deriveBridgeProofStatementHash({
        aggregateDerivationComponentHash,
        aggregateInputEncodingProfileHash:
            baseFields.aggregateInputEncodingProfileHash,
        aggregateQuotientCoordinateCount: 220,
        aggregateReducedCoordinateCount: 220,
        aggregateSelectionPolicyHash: baseFields.aggregateSelectionPolicyHash,
        aggregateShareCommitmentHash,
        aggregateToPlaintextBindingStatus:
            'AggregateToPlaintextModularBindingChecked',
        ballotScoreEncodingProfileHash:
            baseFields.ballotScoreEncodingProfileHash,
        ballotSetHash: baseFields.ballotSetHash,
        ballotShareLayoutProfileHash: baseFields.ballotShareLayoutProfileHash,
        basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
        batchEncodingBoundCertificateHash: hash(
            `batch-encoding-bound-certificate-${input.rosterPosition}`,
        ),
        bgvBatchEncoderHash: baseFields.bgvBatchEncoderHash,
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
        bgvProfileHash: baseFields.bgvProfileHash,
        bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
        bgvRandomnessBoundProofStatus:
            'BgvRandomnessErrorSupportPolynomialChecked',
        bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
        bridgeLayoutHash: baseFields.encryptedAggregateInputLayoutHash,
        bridgeProofTargetContractHash,
        bridgeWitnessPrivacyProfileHash:
            baseFields.bridgeWitnessPrivacyProfileHash,
        canonicalByteLength: 180_781,
        canonicalBytesHash512: '4'.repeat(128),
        canonicalCiphertextConventionHash:
            baseFields.canonicalCiphertextConventionHash,
        ceremonyId: baseFields.ceremonyId,
        ciphertextRoot: hash(`bridge-ciphertext-${input.rosterPosition}`),
        claimBearingBridgeEncryption: false,
        coefficientDomainCanonical: true,
        coefficientCount: 32_768,
        collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
        collectivePublicKeyCoefficientRoot:
            baseFields.collectivePublicKeyCoefficientRoot,
        contributorActionContextHash: actionContext.actionContextHash,
        contributorIdentity,
        contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: input.rosterPosition,
        developmentKeyOnly: false,
        optionCount: baseFields.optionCount,
        participantCount: baseFields.participantCount,
        encodedAggregateLayoutHash: baseFields.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash: baseFields.encodedShareVectorLayoutHash,
        encryptedAggregateBridgeHash: baseFields.encryptedAggregateBridgeHash,
        encryptedAggregateInputLayoutHash:
            baseFields.encryptedAggregateInputLayoutHash,
        encryptedAggregateInputRoot: encryptedAggregateShareCiphertextRoot,
        encryptedAggregateReconstructionHash:
            baseFields.encryptedAggregateReconstructionHash,
        encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisRoot:
            baseFields.encryptedAggregateTargetBasisRoot,
        heParamHash: baseFields.heParamHash,
        hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsProfileFreeze',
        level: 15,
        manifestHash: baseFields.manifestHash,
        aggregateDerivationVerificationScope:
            'AggregateDerivationFullVerificationPreconditionNotBound',
        plaintextCanonicalLiftProofStatus: 'PlaintextCanonicalLiftProofChecked',
        plaintextEncodingBoundCertificateHash: hash(
            `batch-encoding-bound-certificate-${input.rosterPosition}`,
        ),
        plaintextEncodingProofModuli: [
            140_737_487_306_753, 140_737_486_716_929,
        ],
        plaintextEncodingProofModulusProduct: '19807040250408114080301121537',
        plaintextEncodingProofModulusProductBitsFloor: 93,
        plaintextRoot: hash(`bridge-plaintext-${input.rosterPosition}`),
        pollSpecHash: baseFields.pollSpecHash,
        postVotingClosedContextHash,
        proofProfileHash: bridgeProofProfileHash,
        rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
        rosterHash: baseFields.rosterHash,
        rustBgvBackendProfileHash: baseFields.rustBgvBackendProfileHash,
        sampledPublicRelationCheckPolicyHash,
        sampledOnlyBridgeVerificationAccepted: false,
        setupPackageHash: baseFields.setupPackageHash,
        shareCommitmentMessageBoundCertHash:
            baseFields.shareCommitmentMessageBoundCertHash,
        shareVectorWidth: baseFields.shareVectorWidth,
        sharedWitnessBindingRequired: true,
        sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
        sharedWitnessChallengeBitsPerCheck: 64,
        sharedWitnessCheckCount: 2,
        sharedWitnessChallengeEntropyBits: 128,
        sharedWitnessRejectionAttemptLimit: 64,
        sharedWitnessGrindingDiscountBitsPerCheck: 6,
        sharedWitnessRejectionRetryLossBits: 12,
        sharedWitnessFullMatrixUnionBoundBits: 9,
        sharedWitnessRandomOracleQueryBoundBits: 0,
        sharedWitnessProofSystemLossBits: 0,
        sharedWitnessChallengeBiasBits: 0,
        sharedWitnessTargetBindingSoundnessBits: 128,
        sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor: 186,
        sharedWitnessEffectiveBindingSoundnessBitsFloor: 165,
        sharedWitnessEffectiveBindingBelowTarget: false,
        sharedWitnessWeakestRelation:
            'BGVBatchEncode65537IntegerLiftedInverseNegacyclicNtt',
        sharedWitnessWeakestRelationModuli: [
            140_737_487_306_753, 140_737_486_716_929,
        ],
        sharedWitnessWeakestRelationModulusProduct:
            '19807040250408114080301121537',
        sharedWitnessZeroKnowledgeStatus:
            'SharedWitnessZeroKnowledgeResponseDistributionChecked',
        slotCount: 32_768,
        thresholdProfileHash: baseFields.thresholdProfileHash,
        thresholdDecryptable: true,
        topKEvaluatorInputLayoutHash: baseFields.topKEvaluatorInputLayoutHash,
        votingClosedBoardHeadHash: baseFields.votingClosedBoardHeadHash,
    });
    const bridgeProofChallengeContextHash =
        deriveBridgeProofChallengeContextHash({
            bridgeProofProfileHash,
            bridgeProofStatementHash: proofStatementHash,
            bridgeProofTargetContractHash,
        });
    const bridgeProofRecordPayload: Omit<
        BridgeProofRecord,
        'bridgeProofRecordHash'
    > = {
        ...baseFields,
        aggregateDerivationComponentHash,
        aggregateDerivationVerificationScope:
            'AggregateDerivationFullVerificationPreconditionNotBound',
        aggregateShareCommitmentHash,
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofSubrelation:
            'SealedLatticePassiveCollectiveCiphertextEquationRelation',
        bridgeProofProfileHash,
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        bridgeProofChallengeContextHash,
        bridgeProofTargetContractHash,
        bridgeProofVerificationStatus:
            input.proofStatus ?? 'BridgeProofRelationChecked',
        claimBearingBridgeEncryption: false,
        contributorActionContextHash: actionContext.actionContextHash,
        contributorIdentity,
        contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: input.rosterPosition,
        developmentKeyOnly: false,
        encryptedAggregateInputRoot: encryptedAggregateShareCiphertextRoot,
        encryptedAggregateShareCiphertextRoot,
        objectType: 'BridgeProofRecord',
        objectVersion: 1,
        postVotingClosedContextHash,
        proofBackend: 'SealedLatticeBridgeRelation',
        proofBytesHash: hash(`bridge-proof-bytes-${input.rosterPosition}`),
        proofEncodingProfileHash: hash('bridge-proof-encoding'),
        proofParameterSetHash: hash('bridge-proof-parameters'),
        proofRoot: hash(`bridge-proof-root-${input.rosterPosition}`),
        proofSizeBytes: 128,
        proofStatementHash,
        publicRandomnessHash: hash(
            `bridge-proof-randomness-${input.rosterPosition}`,
        ),
        thresholdDecryptable: true,
    };
    const bridgeProofRecord = {
        ...bridgeProofRecordPayload,
        bridgeProofRecordHash: deriveBridgeProofRecordHash(
            bridgeProofRecordPayload,
        ),
    };
    const unsignedContributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionHash' | 'signature'
    > = {
        ...baseFields,
        actionContext,
        actionSequence,
        aggregateDerivationComponentHash,
        aggregateShareCommitmentHash,
        boardPosition,
        boardSequence,
        bridgeProofProfileHash,
        bridgeProofRecord,
        bridgeProofRecordHash: bridgeProofRecord.bridgeProofRecordHash,
        contributorIdentity,
        contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: input.rosterPosition,
        deviceEpoch,
        encryptedAggregateInputRoot: encryptedAggregateShareCiphertextRoot,
        encryptedAggregateShareCiphertextRoot,
        objectType: 'AggregateContribution',
        objectVersion: 1,
        postVotingClosedContextHash,
        recoveryEpoch,
    };
    const aggregateContributionHash = deriveAggregateContributionHash(
        unsignedContributionPayload,
    );
    const contributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionHash'
    > = {
        ...unsignedContributionPayload,
        signature: createSignatureEnvelope({
            contextHash: postVotingClosedContextHash,
            deviceEpoch,
            objectRoot: aggregateContributionHash,
            recoveryEpoch,
            signerIdentity: contributorIdentity,
        }),
    };

    return {
        ...contributionPayload,
        aggregateContributionHash,
    };
};

export const createAggregateDerivationComponentFixture = (input: {
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly aggregateShareCommitmentHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorRosterPosition: number;
}): AggregateDerivationComponent =>
    ({
        aggregateCommitment: {
            aggregateShareCommitmentHash: input.aggregateShareCommitmentHash,
            commitmentBodyHash: hash('commitment-body'),
            commitmentPolynomialVector: [['0']],
            contributorIdentity: input.contributorIdentity,
            contributorRosterPosition: input.contributorRosterPosition,
            manifestHash: baseFields.manifestHash,
            objectType: 'AggregateShareCommitment',
            objectVersion: 1,
            pollSpecHash: baseFields.pollSpecHash,
            rosterHash: baseFields.rosterHash,
            shareCommitmentProfileHash: hash('share-commitment-profile'),
            shareVectorWidth: 22,
        },
        aggregateDerivationComponentHash:
            input.aggregateDerivationComponentHash,
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
            profileHash: hash('bound-cert-profile'),
            profileId: 'fixture-bound-cert',
            quotientBoundForAggregateReduction: 10,
            shareCommitmentMessageBoundCertHash:
                baseFields.shareCommitmentMessageBoundCertHash,
            shareCommitmentProfileHash: hash('share-commitment-profile'),
            shareVectorWidth: 22,
        },
        statement: {
            aggregateCommitmentHash: input.aggregateShareCommitmentHash,
            aggregateDerivationStatementHash: hash(
                'aggregate-derivation-statement',
            ),
            aggregateInputEncodingProfileHash:
                baseFields.aggregateInputEncodingProfileHash,
            aggregateShareCommitmentHash: input.aggregateShareCommitmentHash,
            ballotScoreEncodingProfileHash:
                baseFields.ballotScoreEncodingProfileHash,
            ballotSetHash: baseFields.ballotSetHash,
            ballotShareLayoutProfileHash:
                baseFields.ballotShareLayoutProfileHash,
            canonicalTurnout: 1,
            ceremonyId: baseFields.ceremonyId,
            challengeDomainHash: hash('challenge-domain'),
            closeRecordHash: baseFields.closeRecordHash,
            contributorActionContextHash: hash('action-context'),
            contributorIdentity: input.contributorIdentity,
            contributorRosterExternalAcceptanceHash:
                input.contributorRosterExternalAcceptanceHash,
            contributorRosterPosition: input.contributorRosterPosition,
            encodedAggregateLayoutHash: baseFields.encodedAggregateLayoutHash,
            encodedShareVectorLayoutHash:
                baseFields.encodedShareVectorLayoutHash,
            manifestHash: baseFields.manifestHash,
            objectType: 'AggregateDerivationStatement',
            objectVersion: 1,
            optionCount: 2,
            packageReferences: [],
            participantCount: 20,
            pollSpecHash: baseFields.pollSpecHash,
            postVotingClosedContextHash: baseFields.postVotingClosedContextHash,
            proofEncodingProfileId: 'fixture-proof-encoding',
            proofParameterProfileId: 'fixture-proof-parameters',
            proofProfileId: 'fixture-proof',
            receiverEncryptionProfileHash: hash('receiver-profile'),
            rosterHash: baseFields.rosterHash,
            shareCommitmentMessageBoundCertHash:
                baseFields.shareCommitmentMessageBoundCertHash,
            shareCommitmentProfileHash: hash('share-commitment-profile'),
            shareVectorWidth: 22,
            thresholdProfileHash: baseFields.thresholdProfileHash,
            votingClosedBoardHeadHash: baseFields.votingClosedBoardHeadHash,
        },
    }) as unknown as AggregateDerivationComponent;

export const createSetupEvidenceFixture =
    (): PendingBridgeProofRecordFromEvidenceInput['setupPackage'] => ({
        collectivePublicKey: {
            bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
            collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
            collectivePublicKeyCoefficientRoot:
                baseFields.collectivePublicKeyCoefficientRoot,
        },
        profileBindings: {
            aggregateInputEncodingProfileHash:
                baseFields.aggregateInputEncodingProfileHash,
            backendProfileHash: baseFields.rustBgvBackendProfileHash,
            ballotScoreEncodingProfileHash:
                baseFields.ballotScoreEncodingProfileHash,
            ballotShareLayoutProfileHash:
                baseFields.ballotShareLayoutProfileHash,
            batchEncoderHash: baseFields.bgvBatchEncoderHash,
            canonicalCiphertextConventionHash:
                baseFields.canonicalCiphertextConventionHash,
            encodedAggregateLayoutHash: baseFields.encodedAggregateLayoutHash,
            encryptedAggregateBridgeHash:
                baseFields.encryptedAggregateBridgeHash,
            encryptedAggregateInputLayoutHash:
                baseFields.encryptedAggregateInputLayoutHash,
            encryptedAggregateReconstructionHash:
                baseFields.encryptedAggregateReconstructionHash,
            encryptedAggregateTargetBasisRoot:
                baseFields.encryptedAggregateTargetBasisRoot,
            profileHash: baseFields.bgvProfileHash,
            topKEvaluatorInputLayoutHash:
                baseFields.topKEvaluatorInputLayoutHash,
        },
        setupPackageHash: baseFields.setupPackageHash,
        setupInputs: {
            ceremonyId: baseFields.ceremonyId,
            manifestHash: baseFields.manifestHash,
            participantCount: baseFields.participantCount,
            rosterHash: baseFields.rosterHash,
            thresholdProfileHash: baseFields.thresholdProfileHash,
        },
    });

export const recoveryMapFor = (
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
