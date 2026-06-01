import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    AggregateContribution,
    AggregateReadyRecord,
    BridgeClaimVerificationStatus,
    BridgeProofRecord,
    ProtocolHash,
} from '@sealed-lattice/types';

type AggregateContributionUnsignedPayload = Omit<
    AggregateContribution,
    'aggregateContributionHash' | 'signature'
>;

type AggregateContributionHashInput = AggregateContributionUnsignedPayload &
    Partial<Pick<AggregateContribution, 'signature'>>;

export const deriveBridgeProofProfileHash = (input: {
    readonly bgvEncryptionProofSubrelation:
        | 'SealedLatticePassiveCollectiveCiphertextEquationRelation'
        | 'SealedLatticeBoundedEncryptionRelation'
        | 'HwangPiopCandidate';
    readonly bgvEncryptionKeyMaterialKind: 'passive-transcript-derived-collective-public-key';
    readonly bridgeProofProfileId: string;
    readonly claimBearingBridgeEncryption: boolean;
    readonly developmentKeyOnly: false;
    readonly proofBackend: 'SealedLatticeBridgeRelation';
    readonly thresholdDecryptable: true;
}): ProtocolHash =>
    deriveProtocolHash('BridgeProofProfileHash', {
        bgvEncryptionKeyMaterialKind: input.bgvEncryptionKeyMaterialKind,
        bgvEncryptionProofSubrelation: input.bgvEncryptionProofSubrelation,
        bridgeProofProfileId: input.bridgeProofProfileId,
        claimBearingBridgeEncryption: input.claimBearingBridgeEncryption,
        developmentKeyOnly: input.developmentKeyOnly,
        proofBackend: input.proofBackend,
        thresholdDecryptable: input.thresholdDecryptable,
        purpose: 'sealed-lattice-aggregate-bridge-proof-profile-v1',
    });

const bridgePlaintextCoefficientCount = 32_768; // BGV ring degree (polynomial slots).
const bridgeDataPrimeCount = 17; // RNS data primes in the BGV ciphertext modulus.
const bridgeCiphertextComponentCount = 2;
const shareCommitmentModuleRank = 4;
const shareCommitmentModuleDegree = 256;
const shareCommitmentOpeningCoordinateCount = 64;
const plaintextBindingOpeningCoordinateCount =
    (bridgePlaintextCoefficientCount / shareCommitmentModuleDegree) *
    shareCommitmentOpeningCoordinateCount;
const plaintextCoefficientBindingScheme =
    'ChunkedAdditiveModuleSisPlaintextCoefficientCommitment';
const proofFriendlyPlaintextBindingStatus =
    'ProofFriendlyPlaintextCoefficientBindingRelationChecked';
const proofFriendlyPlaintextLiftBindingStatus =
    'ProofFriendlyPlaintextCoefficientLiftBindingChecked';
const ballotPrivacyFieldModulus = 65_537;
const sameWitnessLinkageModel =
    'SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired';
const bridgeSharedWitnessCheckCount = 5;
const bridgeSharedWitnessChallengeBitsPerCheck = 46;
const bridgeSharedWitnessChallengeEntropyBits =
    bridgeSharedWitnessCheckCount * bridgeSharedWitnessChallengeBitsPerCheck;
const bridgeSharedWitnessWeakestRelation =
    'BGVBatchEncode65537IntegerLiftedInverseNegacyclicNtt';
const bridgeSharedWitnessWeakestRelationModel =
    'aggregate-proof-ring-effective-binding-floor-v1';
const bridgeSharedWitnessWeakestRelationBitsPerCheck = 46;
const bridgeSharedWitnessChallengeSamplingModel =
    'nonzero-weakest-relation-46-bit-rejection-sampled-from-64-bit-lanes-v1';
const bridgeBatchIntegerLiftProofModuli = [
    140_737_487_306_753, 140_737_486_716_929,
] as const;
const bridgeBatchIntegerLiftProofModulusProduct =
    '19807040250408114080301121537';
const bridgeBatchIntegerLiftProofModulusProductBitsFloor = 93;
const bridgeSharedWitnessRejectionAttemptLimit = 64;
// Soundness accounting for the same-witness linkage between the two bridge sub-proofs:
// the challenge budget is capped at the weakest active relation floor.
const bridgeSharedWitnessGrindingDiscountBitsPerCheck = 6;
const bridgeSharedWitnessRejectionRetryLossBits =
    bridgeSharedWitnessGrindingDiscountBitsPerCheck *
    bridgeSharedWitnessCheckCount;
const bridgeSharedWitnessFullMatrixUnionBoundBits = 9;
const bridgeSharedWitnessRandomOracleQueryBoundBits = 32;
const bridgeSharedWitnessProofSystemLossBits = 0;
const bridgeSharedWitnessChallengeBiasBits = 0;
const bridgeSharedWitnessTargetBindingSoundnessBits = 128;
const bridgeSharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor =
    bridgeSharedWitnessWeakestRelationBitsPerCheck *
    bridgeSharedWitnessCheckCount;
const bridgeSharedWitnessEffectiveBindingSoundnessBitsFloor =
    bridgeSharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor -
    bridgeSharedWitnessRejectionRetryLossBits -
    bridgeSharedWitnessFullMatrixUnionBoundBits -
    bridgeSharedWitnessRandomOracleQueryBoundBits -
    bridgeSharedWitnessProofSystemLossBits -
    bridgeSharedWitnessChallengeBiasBits;
const bridgeSharedWitnessEffectiveBindingBelowTarget = false;
const bgvEncryptionKeyMaterialKind =
    'passive-transcript-derived-collective-public-key';
export type AggregateDerivationVerificationScope =
    | 'AggregateDerivationFullVerificationPreconditionNotBound'
    | 'AggregateDerivationFullVerificationChecked';

type BridgeSharedWitnessLayout = {
    readonly aggregateIntegerShareCoordinateCount: number;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateRelationRowCount: number;
    readonly bgvCiphertextEquationRowCount: number;
    readonly bridgeProofProfileId: 'EncryptedAggregateBridge-v1';
    readonly commitmentOpeningCoordinateCount: number;
    readonly encryptionErrorCoefficientCount: number;
    readonly encryptionRandomizerCoefficientCount: number;
    readonly layoutModel: 'single-shared-response-vector-v1';
    readonly objectType: 'AggregateBridgeSharedWitnessLayout';
    readonly objectVersion: 1;
    readonly plaintextCoefficientColumnRole: 'bgv-batch-encoding-and-bgv-encryption-message';
    readonly plaintextCoefficientCount: number;
    readonly plaintextBindingOpeningCoordinateCount: number;
    readonly plaintextEncodingQuotientCount: number;
    readonly plaintextEncodingRelationRowCount: number;
    readonly sameWitnessLinkageModel: typeof sameWitnessLinkageModel;
    readonly separateSubproofsAcceptedForClosure: false;
    readonly sharedReducedCoordinateColumnRole: 'aggregate-reduction-and-bgv-plaintext-slot';
    readonly sharedResponseScalarCount: number;
};

const createBridgeSharedWitnessLayout = (input: {
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
}): BridgeSharedWitnessLayout => {
    const aggregateIntegerShareCoordinateCount =
        input.aggregateReducedCoordinateCount;
    const plaintextEncodingQuotientCount = bridgePlaintextCoefficientCount;
    const encryptionRandomizerCoefficientCount =
        bridgePlaintextCoefficientCount;
    const encryptionErrorCoefficientCount =
        bridgeCiphertextComponentCount * bridgePlaintextCoefficientCount;
    const bgvCiphertextEquationRowCount =
        bridgeDataPrimeCount *
        bridgePlaintextCoefficientCount *
        bridgeCiphertextComponentCount;

    return {
        aggregateIntegerShareCoordinateCount,
        aggregateQuotientCoordinateCount:
            input.aggregateQuotientCoordinateCount,
        aggregateReducedCoordinateCount: input.aggregateReducedCoordinateCount,
        aggregateRelationRowCount:
            shareCommitmentModuleRank + input.aggregateReducedCoordinateCount,
        bgvCiphertextEquationRowCount,
        bridgeProofProfileId: 'EncryptedAggregateBridge-v1',
        commitmentOpeningCoordinateCount: shareCommitmentOpeningCoordinateCount,
        encryptionErrorCoefficientCount,
        encryptionRandomizerCoefficientCount,
        layoutModel: 'single-shared-response-vector-v1',
        objectType: 'AggregateBridgeSharedWitnessLayout',
        objectVersion: 1,
        plaintextCoefficientColumnRole:
            'bgv-batch-encoding-and-bgv-encryption-message',
        plaintextCoefficientCount: bridgePlaintextCoefficientCount,
        plaintextBindingOpeningCoordinateCount,
        plaintextEncodingQuotientCount,
        plaintextEncodingRelationRowCount: bridgePlaintextCoefficientCount,
        sameWitnessLinkageModel,
        separateSubproofsAcceptedForClosure: false,
        sharedReducedCoordinateColumnRole:
            'aggregate-reduction-and-bgv-plaintext-slot',
        // Length of the single shared response vector that binds the aggregate-reduction
        // and BGV-encryption sub-relations to one witness: the concatenation of every
        // shared-witness coordinate block (shares, openings, reduced, quotients, plaintext
        // coefficients, encoding quotients, encryption randomizer, encryption error).
        sharedResponseScalarCount:
            aggregateIntegerShareCoordinateCount +
            shareCommitmentOpeningCoordinateCount +
            input.aggregateReducedCoordinateCount +
            input.aggregateQuotientCoordinateCount +
            bridgePlaintextCoefficientCount +
            plaintextEncodingQuotientCount +
            plaintextBindingOpeningCoordinateCount +
            encryptionRandomizerCoefficientCount +
            encryptionErrorCoefficientCount,
    };
};

const deriveBridgeSharedWitnessLayoutHash = (
    layout: BridgeSharedWitnessLayout,
): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        layout,
        purpose: 'sealed-lattice-aggregate-bridge-shared-witness-layout-v1',
    });

export const deriveBridgeProofTargetContractHash = (input: {
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateDerivationVerificationScope: AggregateDerivationVerificationScope;
    readonly bridgeClaimClosureStatus: BridgeClaimVerificationStatus;
    readonly claimBearingBridgeEncryption: boolean;
}): ProtocolHash => {
    const sharedWitnessLayout = createBridgeSharedWitnessLayout(input);
    const sharedWitnessLayoutHash =
        deriveBridgeSharedWitnessLayoutHash(sharedWitnessLayout);

    return deriveProtocolHash('BridgeProofRecordHash', {
        contract: {
            aggregateQuotientCoordinateCount:
                input.aggregateQuotientCoordinateCount,
            aggregateReducedCoordinateCount:
                input.aggregateReducedCoordinateCount,
            aggregateReductionRowCount: input.aggregateReducedCoordinateCount,
            aggregateToPlaintextBindingStatus:
                'AggregateToPlaintextModularBindingChecked',
            aggregateDerivationVerificationScope:
                input.aggregateDerivationVerificationScope,
            bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
            bgvEncryptionProofSubrelation:
                'SealedLatticePassiveCollectiveCiphertextEquationRelation',
            bgvEncryptionKeyMaterialKind,
            bgvRandomnessBoundProofStatus:
                'BgvRandomnessErrorSupportPolynomialChecked',
            bridgeClaimClosureStatus: input.bridgeClaimClosureStatus,
            bridgeProofProfileId: 'EncryptedAggregateBridge-v1',
            claimBearingBridgeEncryption: input.claimBearingBridgeEncryption,
            ciphertextCoefficientEquationCount:
                bridgeDataPrimeCount *
                bridgePlaintextCoefficientCount *
                bridgeCiphertextComponentCount,
            ciphertextComponentCount: bridgeCiphertextComponentCount,
            coefficientDomainCanonical: true,
            commitmentOpeningCoordinateCount:
                shareCommitmentOpeningCoordinateCount,
            dataPrimeCount: bridgeDataPrimeCount,
            developmentKeyOnly: false,
            fieldReductionModulus: ballotPrivacyFieldModulus,
            fullRnsCoverageRequired: true,
            hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsProfileFreeze',
            naiveLinearExpansionBackendStatus:
                'InfeasibleForEncryptedAggregateBridgeClaim',
            objectType: 'AggregateBridgeProofTargetContract',
            objectVersion: 1,
            plaintextCoefficientCount: bridgePlaintextCoefficientCount,
            plaintextEncodingRelation: bridgeSharedWitnessWeakestRelation,
            plaintextCanonicalLiftProofStatus:
                'PlaintextCanonicalLiftProofChecked',
            polynomialDegree: bridgePlaintextCoefficientCount,
            proofFriendlyPlaintextBindingRequired: true,
            proofFriendlyPlaintextBindingStatus,
            proofFriendlyPlaintextBindingScheme:
                plaintextCoefficientBindingScheme,
            proofFriendlyPlaintextBindingOpeningCoordinateCount:
                plaintextBindingOpeningCoordinateCount,
            proofFriendlyPlaintextLiftBindingRequired: true,
            proofFriendlyPlaintextLiftBindingStatus,
            proofBackend: 'SealedLatticeBridgeRelation',
            publicPlaintextRootAcceptedAsClosureEvidence: false,
            relationScope: 'sealed-lattice-aggregate-bridge-relation',
            rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
            sameWitnessLinkageModel,
            sampledDiagnosticsAcceptedForVerification: false,
            separateSubproofsAcceptedForClosure: false,
            separateSubproofsClosureStatus:
                'RejectedForAggregateBridgeClaimClosure',
            sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
            sharedWitnessChallengeBitsPerCheck:
                bridgeSharedWitnessChallengeBitsPerCheck,
            sharedWitnessCheckCount: bridgeSharedWitnessCheckCount,
            sharedWitnessChallengeEntropyBits:
                bridgeSharedWitnessChallengeEntropyBits,
            sharedWitnessChallengeSamplingModel:
                bridgeSharedWitnessChallengeSamplingModel,
            sharedWitnessGrindingDiscountBitsPerCheck:
                bridgeSharedWitnessGrindingDiscountBitsPerCheck,
            sharedWitnessRejectionRetryLossBits:
                bridgeSharedWitnessRejectionRetryLossBits,
            sharedWitnessFullMatrixUnionBoundBits:
                bridgeSharedWitnessFullMatrixUnionBoundBits,
            sharedWitnessRandomOracleQueryBoundBits:
                bridgeSharedWitnessRandomOracleQueryBoundBits,
            sharedWitnessProofSystemLossBits:
                bridgeSharedWitnessProofSystemLossBits,
            sharedWitnessChallengeBiasBits:
                bridgeSharedWitnessChallengeBiasBits,
            sharedWitnessTargetBindingSoundnessBits:
                bridgeSharedWitnessTargetBindingSoundnessBits,
            sharedWitnessEffectiveBindingBelowTarget:
                bridgeSharedWitnessEffectiveBindingBelowTarget,
            sharedWitnessRejectionAttemptLimit:
                bridgeSharedWitnessRejectionAttemptLimit,
            sharedWitnessEffectiveBindingSoundnessBitsFloor:
                bridgeSharedWitnessEffectiveBindingSoundnessBitsFloor,
            sharedWitnessLayout,
            sharedWitnessLayoutHash,
            sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor:
                bridgeSharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor,
            sharedWitnessWeakestRelation: bridgeSharedWitnessWeakestRelation,
            sharedWitnessWeakestRelationModel:
                bridgeSharedWitnessWeakestRelationModel,
            sharedWitnessWeakestRelationBitsPerCheck:
                bridgeSharedWitnessWeakestRelationBitsPerCheck,
            sharedWitnessWeakestRelationModuli:
                bridgeBatchIntegerLiftProofModuli,
            batchIntegerLiftProofModuli: bridgeBatchIntegerLiftProofModuli,
            batchIntegerLiftProofModulusProduct:
                bridgeBatchIntegerLiftProofModulusProduct,
            batchIntegerLiftProofModulusProductBitsFloor:
                bridgeBatchIntegerLiftProofModulusProductBitsFloor,
            plaintextEncodingProofModuli: bridgeBatchIntegerLiftProofModuli,
            plaintextEncodingProofModulusProduct:
                bridgeBatchIntegerLiftProofModulusProduct,
            plaintextEncodingProofModulusProductBitsFloor:
                bridgeBatchIntegerLiftProofModulusProductBitsFloor,
            sharedWitnessZeroKnowledgeStatus:
                'SharedWitnessZeroKnowledgeResponseDistributionChecked',
            thresholdDecryptable: true,
        },
        purpose: 'sealed-lattice-aggregate-bridge-proof-target-contract-v1',
    });
};

export const deriveBridgeProofChallengeContextHash = (input: {
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        bridgeProofProfileHash: input.bridgeProofProfileHash,
        bridgeProofStatementHash: input.bridgeProofStatementHash,
        bridgeProofTargetContractHash: input.bridgeProofTargetContractHash,
        purpose: 'sealed-lattice-aggregate-bridge-proof-challenge-context-v1',
    });

type BridgeProofStatementHashInput = {
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly aggregateShareCommitmentHash: ProtocolHash;
    readonly aggregateToPlaintextBindingStatus: 'AggregateToPlaintextModularBindingChecked';
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly ballotSetHash: ProtocolHash;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly basisId: string;
    readonly batchEncodingBoundCertificateHash: ProtocolHash;
    readonly bgvBatchEncoderHash: ProtocolHash;
    readonly bgvEncryptionKeyMaterialKind: typeof bgvEncryptionKeyMaterialKind;
    readonly bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked';
    readonly bgvProfileHash: ProtocolHash;
    readonly bgvPublicKeyRoot: ProtocolHash;
    readonly bgvRandomnessBoundProofStatus: 'BgvRandomnessErrorSupportPolynomialChecked';
    readonly bridgeClaimClosureStatus: BridgeClaimVerificationStatus;
    readonly bridgeLayoutHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly canonicalCiphertextConventionHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly ciphertextRoot: ProtocolHash;
    readonly claimBearingBridgeEncryption: boolean;
    readonly coefficientCount: number;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
    readonly contributorActionContextHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorRosterPosition: number;
    readonly developmentKeyOnly: false;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly encodedAggregateLayoutHash: ProtocolHash;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly encryptedAggregateBridgeHash: ProtocolHash;
    readonly encryptedAggregateInputLayoutHash: ProtocolHash;
    readonly encryptedAggregateInputRoot: ProtocolHash;
    readonly encryptedAggregateReconstructionHash: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolHash;
    readonly encryptedAggregateTargetBasisRoot: ProtocolHash;
    readonly heParamHash: ProtocolHash;
    readonly hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsProfileFreeze';
    readonly level: number;
    readonly manifestHash: ProtocolHash;
    readonly aggregateDerivationVerificationScope: AggregateDerivationVerificationScope;
    readonly plaintextCanonicalLiftProofStatus: 'PlaintextCanonicalLiftProofChecked';
    readonly plaintextCoefficientBindingCommitmentHash: ProtocolHash;
    readonly plaintextEncodingBoundCertificateHash: ProtocolHash;
    readonly plaintextEncodingProofModuli: typeof bridgeBatchIntegerLiftProofModuli;
    readonly plaintextEncodingProofModulusProduct: typeof bridgeBatchIntegerLiftProofModulusProduct;
    readonly plaintextEncodingProofModulusProductBitsFloor: 93;
    readonly plaintextRoot: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly proofFriendlyPlaintextBindingStatus: typeof proofFriendlyPlaintextBindingStatus;
    readonly proofFriendlyPlaintextLiftBindingHash: ProtocolHash;
    readonly proofFriendlyPlaintextLiftBindingStatus: typeof proofFriendlyPlaintextLiftBindingStatus;
    readonly proofProfileHash: ProtocolHash;
    readonly rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked';
    readonly rosterHash: ProtocolHash;
    readonly rustBgvBackendProfileHash: ProtocolHash;
    readonly sampledPublicRelationCheckPolicyHash: ProtocolHash;
    readonly sampledOnlyBridgeVerificationAccepted: false;
    readonly setupPackageHash: ProtocolHash;
    readonly shareCommitmentMessageBoundCertHash: ProtocolHash;
    readonly shareVectorWidth: number;
    readonly sharedWitnessBindingRequired: true;
    readonly sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked';
    readonly sharedWitnessChallengeBitsPerCheck: 46;
    readonly sharedWitnessCheckCount: 5;
    readonly sharedWitnessChallengeEntropyBits: 230;
    readonly sharedWitnessChallengeSamplingModel: typeof bridgeSharedWitnessChallengeSamplingModel;
    readonly sharedWitnessRejectionAttemptLimit: 64;
    readonly sharedWitnessRejectionRetryLossBits: 30;
    readonly sharedWitnessFullMatrixUnionBoundBits: 9;
    readonly sharedWitnessRandomOracleQueryBoundBits: 32;
    readonly sharedWitnessProofSystemLossBits: 0;
    readonly sharedWitnessChallengeBiasBits: 0;
    readonly sharedWitnessTargetBindingSoundnessBits: 128;
    readonly sharedWitnessGrindingDiscountBitsPerCheck: 6;
    readonly sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor: 230;
    readonly sharedWitnessEffectiveBindingSoundnessBitsFloor: 159;
    readonly sharedWitnessEffectiveBindingBelowTarget: false;
    readonly sharedWitnessWeakestRelation: typeof bridgeSharedWitnessWeakestRelation;
    readonly sharedWitnessWeakestRelationModel: typeof bridgeSharedWitnessWeakestRelationModel;
    readonly sharedWitnessWeakestRelationBitsPerCheck: 46;
    readonly sharedWitnessWeakestRelationModuli: typeof bridgeBatchIntegerLiftProofModuli;
    readonly batchIntegerLiftProofModuli: typeof bridgeBatchIntegerLiftProofModuli;
    readonly batchIntegerLiftProofModulusProduct: typeof bridgeBatchIntegerLiftProofModulusProduct;
    readonly batchIntegerLiftProofModulusProductBitsFloor: 93;
    readonly sharedWitnessZeroKnowledgeStatus: 'SharedWitnessZeroKnowledgeResponseDistributionChecked';
    readonly coefficientDomainCanonical: true;
    readonly slotCount: number;
    readonly thresholdProfileHash: ProtocolHash;
    readonly thresholdDecryptable: true;
    readonly topKEvaluatorInputLayoutHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
};

const bridgeProofStatementStringHashFieldNames = [
    'aggregateDerivationComponentHash',
    'aggregateInputEncodingProfileHash',
    'aggregateSelectionPolicyHash',
    'aggregateShareCommitmentHash',
    'ballotScoreEncodingProfileHash',
    'ballotSetHash',
    'ballotShareLayoutProfileHash',
    'basisId',
    'batchEncodingBoundCertificateHash',
    'bgvBatchEncoderHash',
    'bgvProfileHash',
    'bgvPublicKeyRoot',
    'bridgeLayoutHash',
    'bridgeProofTargetContractHash',
    'bridgeWitnessPrivacyProfileHash',
    'canonicalBytesHash512',
    'canonicalCiphertextConventionHash',
    'ceremonyId',
    'ciphertextRoot',
    'collectivePublicKeyRoot',
    'collectivePublicKeyCoefficientRoot',
    'contributorActionContextHash',
    'contributorIdentity',
    'contributorRosterExternalAcceptanceHash',
    'encodedAggregateLayoutHash',
    'encodedShareVectorLayoutHash',
    'encryptedAggregateBridgeHash',
    'encryptedAggregateInputLayoutHash',
    'encryptedAggregateInputRoot',
    'encryptedAggregateReconstructionHash',
    'encryptedAggregateShareCiphertextRoot',
    'encryptedAggregateTargetBasisRoot',
    'heParamHash',
    'manifestHash',
    'plaintextCoefficientBindingCommitmentHash',
    'plaintextRoot',
    'pollSpecHash',
    'postVotingClosedContextHash',
    'proofFriendlyPlaintextLiftBindingHash',
    'proofProfileHash',
    'rosterHash',
    'rustBgvBackendProfileHash',
    'sampledPublicRelationCheckPolicyHash',
    'setupPackageHash',
    'shareCommitmentMessageBoundCertHash',
    'thresholdProfileHash',
    'topKEvaluatorInputLayoutHash',
    'votingClosedBoardHeadHash',
] as const satisfies readonly (keyof BridgeProofStatementHashInput)[];

const bridgeProofStatementNumberHashFieldNames = [
    'coefficientCount',
    'contributorRosterPosition',
    'canonicalByteLength',
    'level',
    'optionCount',
    'participantCount',
    'shareVectorWidth',
    'slotCount',
] as const satisfies readonly (keyof BridgeProofStatementHashInput)[];

const bridgeProofStatementRelationStringHashFieldNames = [
    'sharedWitnessBindingStatus',
    'sharedWitnessZeroKnowledgeStatus',
    'aggregateToPlaintextBindingStatus',
    'aggregateDerivationVerificationScope',
    'bgvEncryptionKeyMaterialKind',
    'bgvEncryptionProofStatus',
    'bgvRandomnessBoundProofStatus',
    'rnsCrtConsistencyProofStatus',
    'bridgeClaimClosureStatus',
    'hwangPiopStatus',
    'batchIntegerLiftProofModulusProduct',
    'plaintextEncodingBoundCertificateHash',
    'plaintextEncodingProofModulusProduct',
    'proofFriendlyPlaintextBindingStatus',
    'proofFriendlyPlaintextLiftBindingHash',
    'proofFriendlyPlaintextLiftBindingStatus',
    'sharedWitnessChallengeSamplingModel',
    'sharedWitnessWeakestRelation',
    'sharedWitnessWeakestRelationModel',
] as const satisfies readonly (keyof BridgeProofStatementHashInput)[];

const bridgeProofStatementRelationNumberHashFieldNames = [
    'aggregateReducedCoordinateCount',
    'aggregateQuotientCoordinateCount',
    'sharedWitnessChallengeBitsPerCheck',
    'sharedWitnessCheckCount',
    'sharedWitnessChallengeEntropyBits',
    'sharedWitnessWeakestRelationBitsPerCheck',
    'batchIntegerLiftProofModulusProductBitsFloor',
    'plaintextEncodingProofModulusProductBitsFloor',
    'sharedWitnessRejectionAttemptLimit',
    'sharedWitnessRejectionRetryLossBits',
    'sharedWitnessFullMatrixUnionBoundBits',
    'sharedWitnessRandomOracleQueryBoundBits',
    'sharedWitnessProofSystemLossBits',
    'sharedWitnessChallengeBiasBits',
    'sharedWitnessTargetBindingSoundnessBits',
    'sharedWitnessGrindingDiscountBitsPerCheck',
    'sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor',
    'sharedWitnessEffectiveBindingSoundnessBitsFloor',
] as const satisfies readonly (keyof BridgeProofStatementHashInput)[];

const bridgeProofStatementRelationBooleanHashFieldNames = [
    'sharedWitnessBindingRequired',
    'sampledOnlyBridgeVerificationAccepted',
    'coefficientDomainCanonical',
    'developmentKeyOnly',
    'thresholdDecryptable',
    'claimBearingBridgeEncryption',
    'sharedWitnessEffectiveBindingBelowTarget',
] as const satisfies readonly (keyof BridgeProofStatementHashInput)[];

const bridgeProofStatementRelationArrayHashFieldNames = [
    'batchIntegerLiftProofModuli',
    'plaintextEncodingProofModuli',
    'sharedWitnessWeakestRelationModuli',
] as const satisfies readonly (keyof BridgeProofStatementHashInput)[];

export const deriveBridgeProofStatementHash = (
    input: BridgeProofStatementHashInput,
): ProtocolHash => {
    const hashInput: Record<string, unknown> = {
        purpose: 'sealed-lattice-aggregate-bridge-proof-statement-v1',
    };

    for (const fieldName of bridgeProofStatementStringHashFieldNames) {
        hashInput[fieldName] = input[fieldName];
    }
    for (const fieldName of bridgeProofStatementNumberHashFieldNames) {
        hashInput[fieldName] = input[fieldName];
    }
    for (const fieldName of bridgeProofStatementRelationStringHashFieldNames) {
        hashInput[fieldName] = input[fieldName];
    }
    for (const fieldName of bridgeProofStatementRelationNumberHashFieldNames) {
        hashInput[fieldName] = input[fieldName];
    }
    for (const fieldName of bridgeProofStatementRelationBooleanHashFieldNames) {
        hashInput[fieldName] = input[fieldName];
    }
    for (const fieldName of bridgeProofStatementRelationArrayHashFieldNames) {
        hashInput[fieldName] = input[fieldName];
    }

    return deriveProtocolHash('BridgeProofRecordHash', hashInput);
};

export const deriveBridgeProofRecordHash = (
    proofRecord: Omit<BridgeProofRecord, 'bridgeProofRecordHash'>,
): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        proofRecord,
        purpose: 'sealed-lattice-aggregate-bridge-proof-record-v1',
    });

export const deriveAggregateContributionHash = (
    contribution: AggregateContributionHashInput,
): ProtocolHash => {
    const { signature, ...unsignedContribution } = contribution;
    void signature;

    return deriveProtocolHash('AggregateContributionHash', {
        contribution: unsignedContribution,
        purpose: 'sealed-lattice-aggregate-contribution-v1',
    });
};

export const deriveSelectedAggregateContributionOrderHash = (input: {
    readonly requiredPostVotingClosedContextHash: ProtocolHash;
    readonly selectedAggregateContributionHashes: readonly ProtocolHash[];
    readonly selectionPolicyHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('FirstValidOrderHash', {
        orderedObjectHashes: input.selectedAggregateContributionHashes,
        purpose: 'sealed-lattice-selected-aggregate-contribution-order-v1',
        requiredContextHash: input.requiredPostVotingClosedContextHash,
        selectionPolicyHash: input.selectionPolicyHash,
    });

export const deriveEncryptedAggregateReconstructionRoot = (input: {
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly encryptedAggregateReconstructionHash: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoots: readonly ProtocolHash[];
    readonly firstValidOrderHash: ProtocolHash;
    readonly interpolationCoefficientReportHash: ProtocolHash;
    readonly selectedAggregateContributionHashes: readonly ProtocolHash[];
}): ProtocolHash =>
    deriveProtocolHash('EncryptedAggregateReconstructionHash', {
        ...input,
        purpose: 'sealed-lattice-aggregate-ready-reconstruction-root-v1',
    });

export const deriveAggregateReadyRecordHash = (
    record: Omit<AggregateReadyRecord, 'aggregateReadyRecordHash'>,
): ProtocolHash =>
    deriveProtocolHash('AggregateReadyRecordHash', {
        purpose: 'sealed-lattice-aggregate-ready-record-v1',
        record,
    });
