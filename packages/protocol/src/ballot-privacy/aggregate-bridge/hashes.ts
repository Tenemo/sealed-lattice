import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    AggregateContribution,
    AggregateReadyRecord,
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
        | 'SealedLatticeDevelopmentCiphertextEquationRelation'
        | 'SealedLatticeBoundedEncryptionRelation'
        | 'HwangPiopCandidate';
    readonly bridgeProofProfileId: string;
    readonly proofBackend: 'SealedLatticeBridgeRelation';
}): ProtocolHash =>
    deriveProtocolHash('BridgeProofProfileHash', {
        bgvEncryptionProofSubrelation: input.bgvEncryptionProofSubrelation,
        bridgeProofProfileId: input.bridgeProofProfileId,
        proofBackend: input.proofBackend,
        purpose: 'sealed-lattice-aggregate-bridge-proof-profile-v1',
    });

const bridgePlaintextCoefficientCount = 32_768;
const bridgeDataPrimeCount = 16;
const bridgeCiphertextComponentCount = 2;
const shareCommitmentModuleRank = 4;
const shareCommitmentOpeningCoordinateCount = 64;
const ballotPrivacyFieldModulus = 65_537;
const sameWitnessLinkageModel =
    'SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired';
const bridgeSharedWitnessCheckCount = 2;
const bridgeSharedWitnessChallengeBitsPerCheck = 64;
const bridgeSharedWitnessSoundnessBits =
    bridgeSharedWitnessCheckCount * bridgeSharedWitnessChallengeBitsPerCheck;

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
    const plaintextEncodingQuotientCount = 0;
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
        plaintextEncodingQuotientCount,
        plaintextEncodingRelationRowCount: bridgePlaintextCoefficientCount,
        sameWitnessLinkageModel,
        separateSubproofsAcceptedForClosure: false,
        sharedReducedCoordinateColumnRole:
            'aggregate-reduction-and-bgv-plaintext-slot',
        sharedResponseScalarCount:
            aggregateIntegerShareCoordinateCount +
            shareCommitmentOpeningCoordinateCount +
            input.aggregateReducedCoordinateCount +
            input.aggregateQuotientCoordinateCount +
            bridgePlaintextCoefficientCount +
            plaintextEncodingQuotientCount +
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
                'AggregateToPlaintextBindingProofChecked',
            bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
            bgvEncryptionProofSubrelation:
                'SealedLatticeDevelopmentCiphertextEquationRelation',
            bgvRandomnessBoundProofStatus:
                'BgvRandomnessErrorSupportPolynomialChecked',
            bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
            bridgeProofProfileId: 'EncryptedAggregateBridge-v1',
            ciphertextCoefficientEquationCount:
                bridgeDataPrimeCount *
                bridgePlaintextCoefficientCount *
                bridgeCiphertextComponentCount,
            ciphertextComponentCount: bridgeCiphertextComponentCount,
            coefficientDomainCanonical: true,
            commitmentOpeningCoordinateCount:
                shareCommitmentOpeningCoordinateCount,
            dataPrimeCount: bridgeDataPrimeCount,
            fieldReductionModulus: ballotPrivacyFieldModulus,
            fullRnsCoverageRequired: true,
            hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsProfileFreeze',
            naiveLinearExpansionBackendStatus:
                'InfeasibleForEncryptedAggregateBridgeClaim',
            objectType: 'AggregateBridgeProofTargetContract',
            objectVersion: 1,
            plaintextCoefficientCount: bridgePlaintextCoefficientCount,
            plaintextEncodingRelation:
                'BGVBatchEncode65537InverseNegacyclicNtt',
            plaintextCanonicalLiftProofStatus:
                'PlaintextCanonicalLiftProofMissing',
            polynomialDegree: bridgePlaintextCoefficientCount,
            proofFriendlyPlaintextBindingRequired: true,
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
            sharedWitnessLayout,
            sharedWitnessLayoutHash,
            sharedWitnessSoundnessBits: bridgeSharedWitnessSoundnessBits,
            sharedWitnessZeroKnowledgeStatus:
                'SharedWitnessZeroKnowledgeResponseDistributionChecked',
        },
        purpose: 'sealed-lattice-aggregate-bridge-proof-target-contract-v1',
    });
};

export const deriveBridgeProofStatementHash = (input: {
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly aggregateShareCommitmentHash: ProtocolHash;
    readonly aggregateToPlaintextBindingStatus: 'AggregateToPlaintextBindingProofChecked';
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly ballotSetHash: ProtocolHash;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly basisId: string;
    readonly bgvBatchEncoderHash: ProtocolHash;
    readonly bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked';
    readonly bgvProfileHash: ProtocolHash;
    readonly bgvPublicKeyRoot: ProtocolHash;
    readonly bgvRandomnessBoundProofStatus: 'BgvRandomnessErrorSupportPolynomialChecked';
    readonly bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing';
    readonly bridgeLayoutHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly canonicalCiphertextConventionHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly ciphertextRoot: ProtocolHash;
    readonly coefficientCount: number;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly contributorActionContextHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorRosterPosition: number;
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
    readonly aggregateDerivationVerificationScope: 'AggregateDerivationFullVerificationPreconditionNotBound';
    readonly plaintextCanonicalLiftProofStatus: 'PlaintextCanonicalLiftProofMissing';
    readonly plaintextRoot: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
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
    readonly sharedWitnessChallengeBitsPerCheck: 64;
    readonly sharedWitnessCheckCount: 2;
    readonly sharedWitnessSoundnessBits: 128;
    readonly sharedWitnessZeroKnowledgeStatus: 'SharedWitnessZeroKnowledgeResponseDistributionChecked';
    readonly coefficientDomainCanonical: true;
    readonly slotCount: number;
    readonly thresholdProfileHash: ProtocolHash;
    readonly topKEvaluatorInputLayoutHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        ...input,
        purpose: 'sealed-lattice-aggregate-bridge-proof-statement-v1',
    });

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
