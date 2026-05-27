import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    AggregateContribution,
    AggregateReadyRecord,
    BridgeProofRecord,
    ProtocolDigest,
} from '@sealed-lattice/types';

type AggregateContributionUnsignedPayload = Omit<
    AggregateContribution,
    'aggregateContributionDigest' | 'signature'
>;

type AggregateContributionDigestInput = AggregateContributionUnsignedPayload &
    Partial<Pick<AggregateContribution, 'signature'>>;

export const deriveBridgeProofProfileDigest = (input: {
    readonly bgvEncryptionProofSubrelation:
        | 'SealedLatticeDevelopmentCiphertextEquationRelation'
        | 'SealedLatticeBoundedEncryptionRelation'
        | 'HwangPiopCandidate';
    readonly bridgeProofProfileId: string;
    readonly proofBackend: 'SealedLatticeBridgeRelation';
}): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofProfileDigest', {
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

const deriveBridgeSharedWitnessLayoutDigest = (
    layout: BridgeSharedWitnessLayout,
): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        layout,
        purpose: 'sealed-lattice-aggregate-bridge-shared-witness-layout-v1',
    });

export const deriveBridgeProofTargetContractDigest = (input: {
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
}): ProtocolDigest => {
    const sharedWitnessLayout = createBridgeSharedWitnessLayout(input);
    const sharedWitnessLayoutDigest =
        deriveBridgeSharedWitnessLayoutDigest(sharedWitnessLayout);

    return deriveProtocolDigest('BridgeProofRecordDigest', {
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
            bgvRandomnessBoundProofStatus: 'BgvRandomnessBoundProofMissing',
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
            hwangPiopStatus:
                'DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze',
            naiveLinearExpansionBackendStatus:
                'InfeasibleForEncryptedAggregateBridgeClaim',
            objectType: 'AggregateBridgeProofTargetContract',
            objectVersion: 1,
            plaintextCoefficientCount: bridgePlaintextCoefficientCount,
            plaintextEncodingRelation:
                'BGVBatchEncode65537InverseNegacyclicNtt',
            plaintextRootProofBindingStatus: 'PlaintextRootProofBindingChecked',
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
            sharedWitnessLayoutDigest,
            sharedWitnessSoundnessBits: bridgeSharedWitnessSoundnessBits,
            sharedWitnessZeroKnowledgeStatus:
                'SharedWitnessZeroKnowledgeProofMissing',
        },
        purpose: 'sealed-lattice-aggregate-bridge-proof-target-contract-v1',
    });
};

export const deriveBridgeProofStatementDigest = (input: {
    readonly aggregateDerivationComponentDigest: ProtocolDigest;
    readonly aggregateInputEncodingProfileDigest: ProtocolDigest;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly aggregateShareCommitmentDigest: ProtocolDigest;
    readonly aggregateToPlaintextBindingStatus: 'AggregateToPlaintextBindingProofChecked';
    readonly ballotScoreEncodingProfileDigest: ProtocolDigest;
    readonly ballotSetDigest: ProtocolDigest;
    readonly ballotShareLayoutProfileDigest: ProtocolDigest;
    readonly basisId: string;
    readonly bgvBatchEncoderDigest: ProtocolDigest;
    readonly bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked';
    readonly bgvProfileDigest: ProtocolDigest;
    readonly bgvPublicKeyRoot: ProtocolDigest;
    readonly bgvRandomnessBoundProofStatus: 'BgvRandomnessBoundProofMissing';
    readonly bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing';
    readonly bridgeLayoutDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly ciphertextRoot: ProtocolDigest;
    readonly coefficientCount: number;
    readonly collectivePublicKeyRoot: ProtocolDigest;
    readonly contributorActionContextDigest: ProtocolDigest;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceDigest: ProtocolDigest;
    readonly contributorRosterPosition: number;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly encodedAggregateLayoutDigest: ProtocolDigest;
    readonly encodedShareVectorLayoutDigest: ProtocolDigest;
    readonly encryptedAggregateBridgeDigest: ProtocolDigest;
    readonly encryptedAggregateInputLayoutDigest: ProtocolDigest;
    readonly encryptedAggregateInputRoot: ProtocolDigest;
    readonly encryptedAggregateReconstructionDigest: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly encryptedAggregateTargetBasisDataRoot: ProtocolDigest;
    readonly heParamDigest: ProtocolDigest;
    readonly hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze';
    readonly level: number;
    readonly manifestDigest: ProtocolDigest;
    readonly plaintextRoot: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly proofProfileDigest: ProtocolDigest;
    readonly rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked';
    readonly rosterDigest: ProtocolDigest;
    readonly rustBgvBackendProfileDigest: ProtocolDigest;
    readonly sampledPublicRelationCheckPolicyDigest: ProtocolDigest;
    readonly sampledOnlyBridgeVerificationAccepted: false;
    readonly setupPackageDigest: ProtocolDigest;
    readonly shareCommitmentMessageBoundCertDigest: ProtocolDigest;
    readonly shareVectorWidth: number;
    readonly sharedWitnessBindingRequired: true;
    readonly sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked';
    readonly sharedWitnessChallengeBitsPerCheck: 64;
    readonly sharedWitnessCheckCount: 2;
    readonly sharedWitnessSoundnessBits: 128;
    readonly sharedWitnessZeroKnowledgeStatus: 'SharedWitnessZeroKnowledgeProofMissing';
    readonly coefficientDomainCanonical: true;
    readonly slotCount: number;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly topKEvaluatorInputLayoutDigest: ProtocolDigest;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        ...input,
        purpose: 'sealed-lattice-aggregate-bridge-proof-statement-v1',
    });

export const deriveBridgeProofRecordDigest = (
    proofRecord: Omit<BridgeProofRecord, 'bridgeProofRecordDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        proofRecord,
        purpose: 'sealed-lattice-aggregate-bridge-proof-record-v1',
    });

export const deriveAggregateContributionDigest = (
    contribution: AggregateContributionDigestInput,
): ProtocolDigest => {
    const { signature, ...unsignedContribution } = contribution;
    void signature;

    return deriveProtocolDigest('AggregateContributionDigest', {
        contribution: unsignedContribution,
        purpose: 'sealed-lattice-aggregate-contribution-v1',
    });
};

export const deriveSelectedAggregateContributionOrderDigest = (input: {
    readonly requiredPostVotingClosedContextDigest: ProtocolDigest;
    readonly selectedAggregateContributionDigests: readonly ProtocolDigest[];
    readonly selectionPolicyDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('FirstValidOrderDigest', {
        orderedObjectDigests: input.selectedAggregateContributionDigests,
        purpose: 'sealed-lattice-selected-aggregate-contribution-order-v1',
        requiredContextDigest: input.requiredPostVotingClosedContextDigest,
        selectionPolicyDigest: input.selectionPolicyDigest,
    });

export const deriveEncryptedAggregateReconstructionRoot = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly encryptedAggregateReconstructionDigest: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoots: readonly ProtocolDigest[];
    readonly firstValidOrderDigest: ProtocolDigest;
    readonly interpolationCoefficientReportDigest: ProtocolDigest;
    readonly selectedAggregateContributionDigests: readonly ProtocolDigest[];
}): ProtocolDigest =>
    deriveProtocolDigest('EncryptedAggregateReconstructionDigest', {
        ...input,
        purpose: 'sealed-lattice-aggregate-ready-reconstruction-root-v1',
    });

export const deriveAggregateReadyRecordDigest = (
    record: Omit<AggregateReadyRecord, 'aggregateReadyRecordDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateReadyRecordDigest', {
        purpose: 'sealed-lattice-aggregate-ready-record-v1',
        record,
    });
