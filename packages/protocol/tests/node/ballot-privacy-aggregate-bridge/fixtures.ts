import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveProtocolDigest,
} from '@sealed-lattice/crypto';
import {
    encryptedAggregateBridgeProfileId,
    type ActionContext,
    type AggregateContribution,
    type AggregateDerivationComponent,
    type BridgeProofRecord,
    type ProtocolDigest,
    type ProtocolSignatureEnvelope,
    type RecoveryEpochMapEntry,
} from '@sealed-lattice/types';

import type { PendingBridgeProofRecordFromEvidenceInput } from '../../../src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    deriveAggregateContributionDigest,
    deriveBridgeProofProfileDigest,
    deriveBridgeProofRecordDigest,
    deriveBridgeProofStatementDigest,
    deriveBridgeProofTargetContractDigest,
} from '../../../src/ballot-privacy/index.js';
export const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest('ActionContextDigest', { label });

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

export const sampledPublicRelationCheckPolicyDigest = deriveProtocolDigest(
    'BridgeProofRecordDigest',
    {
        policy: sampledPublicRelationCheckPolicy,
        purpose:
            'sealed-lattice-aggregate-bridge-sampled-public-relation-check-policy-v1',
    },
);

export const baseFields = {
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
    optionCount: 20,
    participantCount: 20,
    pollSpecDigest: digest('poll-spec'),
    postVotingClosedContextDigest: digest('post-voting-closed-context'),
    rosterDigest: digest('roster'),
    rustBgvBackendProfileDigest: digest('rust-bgv-backend-profile'),
    setupPackageDigest: digest('setup-package'),
    shareCommitmentMessageBoundCertDigest: digest(
        'share-commitment-message-bound-cert',
    ),
    shareVectorWidth: 220,
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
    readonly objectRoot: ProtocolDigest;
    readonly recoveryEpoch: number;
    readonly signerIdentity: string;
}): ProtocolSignatureEnvelope => {
    const keyFixture = createMlDsaKeyPairFixture(
        `aggregate-contribution-${input.signerIdentity}`,
    );

    return createProtocolSignatureFixture({
        profile: createMlDsaSignatureProfileFixture(),
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        publicKeyDigest: keyFixture.publicKeyDigest,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            boardHeadDigest: baseFields.votingClosedBoardHeadDigest,
            byteLength: 64,
            ceremonyId: baseFields.ceremonyId,
            chunkMerkleRoot: null,
            contextDigest: input.contextDigest,
            deviceEpoch: input.deviceEpoch,
            manifestDigest: baseFields.manifestDigest,
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
        bgvEncryptionProofSubrelation:
            'SealedLatticeDevelopmentCiphertextEquationRelation',
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
            'AggregateToPlaintextBindingProofChecked',
        ballotScoreEncodingProfileDigest:
            baseFields.ballotScoreEncodingProfileDigest,
        ballotSetDigest: baseFields.ballotSetDigest,
        ballotShareLayoutProfileDigest:
            baseFields.ballotShareLayoutProfileDigest,
        basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
        bgvBatchEncoderDigest: baseFields.bgvBatchEncoderDigest,
        bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
        bgvProfileDigest: baseFields.bgvProfileDigest,
        bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
        bgvRandomnessBoundProofStatus:
            'BgvRandomnessErrorSupportPolynomialChecked',
        bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
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
        optionCount: baseFields.optionCount,
        participantCount: baseFields.participantCount,
        encodedAggregateLayoutDigest: baseFields.encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            baseFields.encodedShareVectorLayoutDigest,
        encryptedAggregateBridgeDigest:
            baseFields.encryptedAggregateBridgeDigest,
        encryptedAggregateInputLayoutDigest:
            baseFields.encryptedAggregateInputLayoutDigest,
        encryptedAggregateInputRoot: encryptedAggregateShareCiphertextRoot,
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
        rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
        rosterDigest: baseFields.rosterDigest,
        rustBgvBackendProfileDigest: baseFields.rustBgvBackendProfileDigest,
        sampledPublicRelationCheckPolicyDigest,
        sampledOnlyBridgeVerificationAccepted: false,
        setupPackageDigest: baseFields.setupPackageDigest,
        shareCommitmentMessageBoundCertDigest:
            baseFields.shareCommitmentMessageBoundCertDigest,
        shareVectorWidth: baseFields.shareVectorWidth,
        sharedWitnessBindingRequired: true,
        sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
        sharedWitnessChallengeBitsPerCheck: 64,
        sharedWitnessCheckCount: 2,
        sharedWitnessSoundnessBits: 128,
        sharedWitnessZeroKnowledgeStatus:
            'SharedWitnessZeroKnowledgeResponseDistributionChecked',
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
        bgvEncryptionProofSubrelation:
            'SealedLatticeDevelopmentCiphertextEquationRelation',
        bridgeProofProfileDigest,
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        bridgeProofTargetContractDigest,
        bridgeProofVerificationStatus:
            input.proofStatus ?? 'BridgeProofRelationChecked',
        contributorActionContextDigest: actionContext.actionContextDigest,
        contributorIdentity,
        contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: input.rosterPosition,
        encryptedAggregateInputRoot: encryptedAggregateShareCiphertextRoot,
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
    const unsignedContributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionDigest' | 'signature'
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
        encryptedAggregateInputRoot: encryptedAggregateShareCiphertextRoot,
        encryptedAggregateShareCiphertextRoot,
        objectType: 'AggregateContribution',
        objectVersion: 1,
        postVotingClosedContextDigest,
        recoveryEpoch,
    };
    const aggregateContributionDigest = deriveAggregateContributionDigest(
        unsignedContributionPayload,
    );
    const contributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionDigest'
    > = {
        ...unsignedContributionPayload,
        signature: createSignatureEnvelope({
            contextDigest: postVotingClosedContextDigest,
            deviceEpoch,
            objectRoot: aggregateContributionDigest,
            recoveryEpoch,
            signerIdentity: contributorIdentity,
        }),
    };

    return {
        ...contributionPayload,
        aggregateContributionDigest,
    };
};

export const createAggregateDerivationComponentFixture = (input: {
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

export const createSetupEvidenceFixture =
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
        setupPackageDigest: baseFields.setupPackageDigest,
        setupInputs: {
            ceremonyId: baseFields.ceremonyId,
            manifestDigest: baseFields.manifestDigest,
            participantCount: baseFields.participantCount,
            rosterDigest: baseFields.rosterDigest,
            thresholdProfileDigest: baseFields.thresholdProfileDigest,
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
