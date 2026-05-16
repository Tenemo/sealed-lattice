import type { ProtocolDigest } from './protocol-digest.js';
import type {
    ConflictingHeadEvidence,
    ProtocolObjectType,
    ProtocolSignatureEnvelope,
    StructuredProtocolVerificationResult,
} from './protocol-objects.js';

/** Signed bulletin-board head used for append-only consistency checks. */
export type SignedBoardHead = {
    readonly objectType: 'BoardHead';
    readonly objectVersion: 1;
    readonly headDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly boardSequence: number;
    readonly boardRoot: ProtocolDigest;
    readonly previousHeadDigest: ProtocolDigest | null;
    readonly boardPolicyDigest: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

/** One sibling edge in a board-entry Merkle inclusion path. */
export type BoardEntryMerklePathStep = {
    readonly siblingPosition: 'Left' | 'Right';
    readonly siblingDigest: ProtocolDigest;
};

/** Inclusion evidence for one protocol object under a signed board head. */
export type InclusionProof = {
    readonly boardHeadDigest: ProtocolDigest;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly includedObjectType: ProtocolObjectType;
    readonly includedObjectDigest: ProtocolDigest;
    readonly boardEntryDigest: ProtocolDigest;
    readonly boardRoot: ProtocolDigest;
    readonly boardEntryCount?: number;
    readonly boardEntryMerklePath?: readonly BoardEntryMerklePathStep[];
    readonly boardEntryDigests?: readonly ProtocolDigest[];
    readonly inclusionProofDigest: ProtocolDigest;
};

/** Append-only proof represented as a signed board-head chain. */
export type AppendOnlyConsistencyProof = {
    readonly proofType: 'SignedHeadChain';
    readonly fromBoardHeadDigest: ProtocolDigest | null;
    readonly toBoardHeadDigest: ProtocolDigest;
    readonly signedBoardHeads: readonly SignedBoardHead[];
};

/** Input bundle used to verify bulletin-board consistency. */
export type BoardConsistencyInput = {
    readonly ceremonyId: string;
    readonly boardPolicyDigest: ProtocolDigest;
    readonly signedBoardHeads: readonly SignedBoardHead[];
    readonly expectedBoardPublicKeyDigest: ProtocolDigest;
    readonly inclusionProofs?: readonly InclusionProof[];
    readonly consistencyProofs?: readonly AppendOnlyConsistencyProof[];
    readonly conflictingHeadEvidence?: readonly ConflictingHeadEvidence[];
};

/** Bulletin-board consistency result with verified head digests. */
export type BoardConsistencyVerification =
    StructuredProtocolVerificationResult & {
        readonly verifiedHeadDigests: readonly ProtocolDigest[];
    };

/** Signed receipt proving that one voter ballot package was accepted. */
export type CastReceipt = {
    readonly objectType: 'CastReceipt';
    readonly objectVersion: 1;
    readonly castReceiptDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly voterIdentity: string;
    readonly ballotPackageDigest: ProtocolDigest;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly contextDigest: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Close-record kind for registration and voting closure records. */
export type CloseRecordKind = 'RegistrationClosed' | 'VotingClosed';

/** Signed organizer record closing registration or voting. */
export type CloseRecord = {
    readonly objectType: 'CloseRecord';
    readonly objectVersion: 1;
    readonly closeRecordDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly closeKind: CloseRecordKind;
    readonly closedBoardHeadDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest | null;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly organizerIdentity: string;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Input used to verify a cast receipt and its board inclusion. */
export type CastReceiptVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly receipt: CastReceipt;
    readonly receiptInclusionProof: InclusionProof;
    readonly expectedElectionManifestDigest: ProtocolDigest;
    readonly expectedVoterPublicKeyDigest: ProtocolDigest;
};

/** Cast receipt verification result. */
export type CastReceiptVerification = StructuredProtocolVerificationResult & {
    readonly castReceiptDigest?: ProtocolDigest;
};

/** Input used to verify a close record and its board inclusion. */
export type CloseRecordVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly closeRecord: CloseRecord;
    readonly closeRecordInclusionProof: InclusionProof;
    readonly expectedElectionManifestDigest: ProtocolDigest;
    readonly expectedOrganizerIdentity: string;
    readonly expectedOrganizerPublicKeyDigest: ProtocolDigest;
};

/** Close record verification result. */
export type CloseRecordVerification = StructuredProtocolVerificationResult & {
    readonly closeRecordDigest?: ProtocolDigest;
    readonly postVotingClosedContextDigest?: ProtocolDigest;
};

/** Witness roster and quorum policy for target finality. */
export type WitnessPolicy = {
    readonly witnessPolicyDigest: ProtocolDigest;
    readonly witnessIdentities: readonly string[];
    readonly witnessQuorum: number;
    readonly totalWitnesses: number;
};

/** Target finality policy for one deterministic target acceptance. */
export type TargetFinalityPolicy = {
    readonly targetFinalityPolicyDigest: ProtocolDigest;
    readonly targetFinalityScope: string;
    readonly witnessQuorum: number;
    readonly totalWitnesses: number;
};

/** Exact target proposal authorized by target-finality witnesses. */
export type TargetProposal = {
    readonly targetProposalDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly evaluationContextDigest: ProtocolDigest;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly topKCiphertextDigest: ProtocolDigest;
    readonly publicSlotMaskDigest: ProtocolDigest;
    readonly targetCiphertextDigest: ProtocolDigest;
    readonly targetLayoutDigest: ProtocolDigest;
    readonly evaluationProofProfileDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
};

/** Full checkpoint whose digest is signed by target-finality witnesses. */
export type TargetFinalityCheckpoint = TargetProposal & {
    readonly objectType: 'TargetFinalityCheckpoint';
    readonly objectVersion: 1;
    readonly targetFinalityCheckpointDigest: ProtocolDigest;
    readonly boardPolicyDigest: ProtocolDigest;
    readonly finalizedBoardHeadDigest: ProtocolDigest;
    readonly witnessPolicyDigest: ProtocolDigest;
};

/** Signed witness checkpoint over a finalized board head and target policy. */
export type WitnessCheckpoint = {
    readonly objectType: 'WitnessCheckpoint';
    readonly objectVersion: 1;
    readonly checkpointDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly targetFinalityScope: string;
    readonly targetProposalDigest: ProtocolDigest;
    readonly targetFinalityCheckpointDigest: ProtocolDigest;
    readonly witnessPolicyDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
    readonly witnessIdentity: string;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Record proving that enough witnesses finalized one target acceptance. */
export type TargetFinalityRecord = {
    readonly objectType: 'TargetFinalityRecord';
    readonly objectVersion: 1;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly targetFinalityScope: string;
    readonly targetProposalDigest: ProtocolDigest;
    readonly targetFinalityCheckpoint: TargetFinalityCheckpoint;
    readonly witnessPolicyDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
    readonly inclusionProof: InclusionProof;
    readonly witnessCheckpoints: readonly WitnessCheckpoint[];
};

/** Input used to verify target finality against board and witness evidence. */
export type TargetFinalityVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly record: TargetFinalityRecord;
    readonly targetFinalityPolicy: TargetFinalityPolicy;
    readonly witnessPolicy: WitnessPolicy;
    readonly witnessPublicKeyDigests: Readonly<Record<string, ProtocolDigest>>;
    readonly conflictingRecords?: readonly TargetFinalityRecord[];
};

/** Target finality verification result with accepted witnesses and equivocation. */
export type TargetFinalityVerification =
    StructuredProtocolVerificationResult & {
        readonly targetFinalityRecordDigest?: ProtocolDigest;
        readonly targetProposalDigest?: ProtocolDigest;
        readonly targetFinalityCheckpointDigest?: ProtocolDigest;
        readonly validWitnessIdentities: readonly string[];
        readonly equivocatingWitnessIdentities: readonly string[];
    };

/** Minimal checkpoint values carried forward after target finality is accepted. */
export type AcceptedTargetFinalityCheckpoint = {
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly targetProposalDigest: ProtocolDigest;
    readonly targetFinalityCheckpointDigest: ProtocolDigest;
    readonly finalizedBoardHeadDigest: ProtocolDigest;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly evaluationContextDigest: ProtocolDigest;
    readonly topKCiphertextDigest: ProtocolDigest;
    readonly publicSlotMaskDigest: ProtocolDigest;
    readonly targetCiphertextDigest: ProtocolDigest;
    readonly targetLayoutDigest: ProtocolDigest;
    readonly evaluationProofProfileDigest: ProtocolDigest;
    readonly targetFinalityScope: string;
    readonly witnessPolicyDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
};

export type EvaluationProofRecord = {
    readonly objectType: 'EvaluationProofRecord';
    readonly objectVersion: 1;
    readonly evaluationProofRecordDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly targetProposalDigest: ProtocolDigest;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly evaluationProofProfileDigest: ProtocolDigest;
    readonly evaluationContextDigest: ProtocolDigest;
    readonly topKCiphertextDigest: ProtocolDigest;
    readonly publicSlotMaskDigest: ProtocolDigest;
    readonly targetCiphertextDigest: ProtocolDigest;
    readonly targetLayoutDigest: ProtocolDigest;
    readonly proofRoot: ProtocolDigest;
    readonly boardSequence: number;
    readonly boardPosition: number;
};

export type LocalReplayRecord = {
    readonly objectType: 'LocalReplayRecord';
    readonly objectVersion: 1;
    readonly localReplayRecordDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly participantIdentity: string;
    readonly targetProposalDigest: ProtocolDigest;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly evaluationProofRecordDigest: ProtocolDigest;
    readonly replayContextDigest: ProtocolDigest;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly mobileReplayCertDigest: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

export type TargetAcceptedRecord = {
    readonly objectType: 'TargetAcceptedRecord';
    readonly objectVersion: 1;
    readonly targetAcceptedRecordDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly targetFinalityScope: string;
    readonly targetProposalDigest: ProtocolDigest;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly targetContextDigest: ProtocolDigest;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly targetFinalityCheckpointDigest: ProtocolDigest;
    readonly evaluationProofRecordDigest: ProtocolDigest;
    readonly evaluationProofProfileDigest: ProtocolDigest;
    readonly targetPreimageDigest: ProtocolDigest;
    readonly targetCiphertextDigest: ProtocolDigest;
    readonly targetLayoutDigest: ProtocolDigest;
    readonly cpadProfileDigest: ProtocolDigest;
    readonly cpadProfileId: string;
    readonly thresholdDecryptionProfileDigest: ProtocolDigest;
    readonly thresholdDecryptionProfileId: string;
    readonly bgvAsyncThresholdCPADProfileDigest: ProtocolDigest;
    readonly targetBasisDigest: ProtocolDigest;
    readonly acceptanceMode: 'evaluation-proof';
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly organizerIdentity: string;
    readonly signature: ProtocolSignatureEnvelope;
};

export type TopKDecryptionShareShell = {
    readonly objectType: 'TopKDecryptionShare';
    readonly objectVersion: 1;
    readonly topKDecryptionShareDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly trusteeIdentity: string;
    readonly targetAcceptedRecordDigest: ProtocolDigest;
    readonly targetProposalDigest: ProtocolDigest;
    readonly targetPreimageDigest: ProtocolDigest;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly targetFinalityCheckpointDigest: ProtocolDigest;
    readonly evaluationProofRecordDigest: ProtocolDigest;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly targetContextDigest: ProtocolDigest;
    readonly targetCiphertextDigest: ProtocolDigest;
    readonly cpadProfileDigest: ProtocolDigest;
    readonly thresholdDecryptionProfileDigest: ProtocolDigest;
    readonly bgvAsyncThresholdCPADProfileDigest: ProtocolDigest;
    readonly targetDecryptionPreparationRecordDigest: ProtocolDigest;
    readonly targetDecryptionCiphertextDigest: ProtocolDigest;
    readonly targetBasisDigest: ProtocolDigest;
    readonly thresholdShareVerificationKeyRoot: ProtocolDigest;
    readonly thresholdShareVerificationKeyDigest: ProtocolDigest;
    readonly trusteeThresholdVerificationKeyDigest: ProtocolDigest;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly shareRoot: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

export type LocalReplayRecordVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly record: LocalReplayRecord;
    readonly recordInclusionProof: InclusionProof;
    readonly targetFinalityRecord: TargetFinalityRecord;
    readonly targetFinalityVerification: TargetFinalityVerification;
    readonly evaluationProofRecord: EvaluationProofRecord;
    readonly expectedSignerPublicKeyDigest: ProtocolDigest;
};

export type LocalReplayRecordVerification =
    StructuredProtocolVerificationResult & {
        readonly localReplayRecordDigest?: ProtocolDigest;
        readonly targetFinalityRecordDigest?: ProtocolDigest;
    };

export type TargetAcceptedRecordVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly targetAcceptedRecord: TargetAcceptedRecord;
    readonly targetAcceptedRecordInclusionProof: InclusionProof;
    readonly targetFinalityRecord: TargetFinalityRecord;
    readonly targetFinalityVerification: TargetFinalityVerification;
    readonly evaluationProofRecord: EvaluationProofRecord;
    readonly expectedOrganizerPublicKeyDigest: ProtocolDigest;
};

export type TargetAcceptedRecordVerification =
    StructuredProtocolVerificationResult & {
        readonly targetAcceptedRecordDigest?: ProtocolDigest;
        readonly targetFinalityRecordDigest?: ProtocolDigest;
    };

export type TopKDecryptionShareShellVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly decryptionShare: TopKDecryptionShareShell;
    readonly decryptionShareInclusionProof: InclusionProof;
    readonly targetAcceptedRecord: TargetAcceptedRecord;
    readonly targetAcceptedRecordVerification: TargetAcceptedRecordVerification;
    readonly expectedTrusteePublicKeyDigest: ProtocolDigest;
};

export type TopKDecryptionShareShellVerification =
    StructuredProtocolVerificationResult & {
        readonly topKDecryptionShareDigest?: ProtocolDigest;
        readonly targetAcceptedRecordDigest?: ProtocolDigest;
        readonly targetFinalityRecordDigest?: ProtocolDigest;
    };
