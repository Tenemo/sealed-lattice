import type { ProtocolHash } from './protocol-hash.js';
import type {
    ConflictingHeadEvidence,
    ProtocolObjectType,
    ProtocolSignatureEnvelope,
    StructuredProtocolVerificationResult,
} from './protocol-objects.js';

/** Signed bulletin-board head used for append-only consistency checks. */
export type SignedBoardHead = {
    readonly objectType: 'BoardHead';
    readonly headHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly boardSequence: number;
    readonly boardRoot: ProtocolHash;
    readonly previousHeadHash: ProtocolHash | null;
    readonly boardPolicyHash: ProtocolHash;
    readonly signature: ProtocolSignatureEnvelope;
};

/** One sibling edge in a board-entry Merkle inclusion path. */
export type BoardEntryMerklePathStep = {
    readonly siblingPosition: 'Left' | 'Right';
    readonly siblingHash: ProtocolHash;
};

/** Inclusion evidence for one protocol object under a signed board head. */
export type InclusionProof = {
    readonly boardHeadHash: ProtocolHash;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly includedObjectType: ProtocolObjectType;
    readonly includedObjectHash: ProtocolHash;
    readonly boardEntryHash: ProtocolHash;
    readonly boardRoot: ProtocolHash;
    readonly boardEntryCount: number;
    readonly boardEntryMerklePath: readonly BoardEntryMerklePathStep[];
    readonly inclusionProofHash: ProtocolHash;
};

/** Append-only proof represented as a signed board-head chain. */
export type AppendOnlyConsistencyProof = {
    readonly proofType: 'SignedHeadChain';
    readonly fromBoardHeadHash: ProtocolHash | null;
    readonly toBoardHeadHash: ProtocolHash;
    readonly signedBoardHeads: readonly SignedBoardHead[];
};

/** Input bundle used to verify bulletin-board consistency. */
export type BoardConsistencyInput = {
    readonly ceremonyId: string;
    readonly boardPolicyHash: ProtocolHash;
    readonly signedBoardHeads: readonly SignedBoardHead[];
    readonly expectedBoardPublicKeyHash: ProtocolHash;
    readonly inclusionProofs?: readonly InclusionProof[];
    readonly consistencyProofs?: readonly AppendOnlyConsistencyProof[];
    readonly conflictingHeadEvidence?: readonly ConflictingHeadEvidence[];
};

/** Bulletin-board consistency result with verified head hashes. */
export type BoardConsistencyVerification =
    StructuredProtocolVerificationResult & {
        readonly verifiedHeadHashes: readonly ProtocolHash[];
    };

/** Signed receipt proving that one voter encrypted ballot was accepted. */
export type CastReceipt = {
    readonly objectType: 'CastReceipt';
    readonly castReceiptHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly electionManifestHash: ProtocolHash;
    readonly voterIdentity: string;
    readonly encryptedBallotHash: ProtocolHash;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly contextHash: ProtocolHash;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Close-record kind for registration and voting closure records. */
export type CloseRecordKind = 'RegistrationClosed' | 'VotingClosed';

/** Signed organizer record closing registration or voting. */
export type CloseRecord = {
    readonly objectType: 'CloseRecord';
    readonly closeRecordHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly electionManifestHash: ProtocolHash;
    readonly closeKind: CloseRecordKind;
    readonly closedBoardHeadHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash | null;
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
    readonly expectedElectionManifestHash: ProtocolHash;
    readonly expectedVoterPublicKeyHash: ProtocolHash;
};

/** Cast receipt verification result. */
export type CastReceiptVerification = StructuredProtocolVerificationResult & {
    readonly castReceiptHash?: ProtocolHash;
};

/** Input used to verify a close record and its board inclusion. */
export type CloseRecordVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly closeRecord: CloseRecord;
    readonly closeRecordInclusionProof: InclusionProof;
    readonly expectedElectionManifestHash: ProtocolHash;
    readonly expectedOrganizerIdentity: string;
    readonly expectedOrganizerPublicKeyHash: ProtocolHash;
};

/** Close record verification result. */
export type CloseRecordVerification = StructuredProtocolVerificationResult & {
    readonly closeRecordHash?: ProtocolHash;
    readonly postVotingClosedContextHash?: ProtocolHash;
};

/** Witness roster and quorum policy for target finality. */
export type WitnessPolicy = {
    readonly witnessPolicyHash: ProtocolHash;
    readonly witnessIdentities: readonly string[];
    readonly witnessQuorum: number;
    readonly totalWitnesses: number;
};

/** Target finality policy for one deterministic target acceptance. */
export type TargetFinalityPolicy = {
    readonly targetFinalityPolicyHash: ProtocolHash;
    readonly targetFinalityScope: string;
    readonly witnessQuorum: number;
    readonly totalWitnesses: number;
};

/** Exact target proposal authorized by target-finality witnesses. */
export type TargetProposal = {
    readonly targetProposalHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly electionManifestHash: ProtocolHash;
    readonly thresholdParametersHash: ProtocolHash;
    readonly evaluatorReplayContextHash: ProtocolHash;
    readonly evaluatorReplayRecordHash: ProtocolHash;
    readonly encryptedBallotAggregateHash: ProtocolHash;
    readonly targetCiphertextHash: ProtocolHash;
    readonly targetLayoutHash: ProtocolHash;
    readonly bgvParametersHash: ProtocolHash;
    readonly targetFinalityPolicyHash: ProtocolHash;
    readonly topOptionCount: number;
    readonly tiePolicyHash: ProtocolHash;
};

/** Full checkpoint whose hash is signed by target-finality witnesses. */
export type TargetFinalityCheckpoint = TargetProposal & {
    readonly objectType: 'TargetFinalityCheckpoint';
    readonly targetFinalityCheckpointHash: ProtocolHash;
    readonly boardPolicyHash: ProtocolHash;
    readonly finalizedBoardHeadHash: ProtocolHash;
    readonly witnessPolicyHash: ProtocolHash;
};

/** Signed witness checkpoint over a finalized board head and target policy. */
export type WitnessCheckpoint = {
    readonly objectType: 'WitnessCheckpoint';
    readonly checkpointHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly targetFinalityScope: string;
    readonly targetProposalHash: ProtocolHash;
    readonly targetFinalityCheckpointHash: ProtocolHash;
    readonly witnessPolicyHash: ProtocolHash;
    readonly targetFinalityPolicyHash: ProtocolHash;
    readonly witnessIdentity: string;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Record proving that enough witnesses finalized one target acceptance. */
export type TargetFinalityRecord = {
    readonly objectType: 'TargetFinalityRecord';
    readonly targetFinalityRecordHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly targetFinalityScope: string;
    readonly targetProposalHash: ProtocolHash;
    readonly targetFinalityCheckpoint: TargetFinalityCheckpoint;
    readonly witnessPolicyHash: ProtocolHash;
    readonly targetFinalityPolicyHash: ProtocolHash;
    readonly inclusionProof: InclusionProof;
    readonly witnessCheckpoints: readonly WitnessCheckpoint[];
};

/** Input used to verify target finality against board and witness evidence. */
export type TargetFinalityVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly record: TargetFinalityRecord;
    readonly targetFinalityPolicy: TargetFinalityPolicy;
    readonly witnessPolicy: WitnessPolicy;
    readonly witnessPublicKeyHashes: Readonly<Record<string, ProtocolHash>>;
    readonly conflictingRecords?: readonly TargetFinalityRecord[];
};

/** Target finality verification result with accepted witnesses and equivocation. */
export type TargetFinalityVerification =
    StructuredProtocolVerificationResult & {
        readonly targetFinalityRecordHash?: ProtocolHash;
        readonly targetProposalHash?: ProtocolHash;
        readonly targetFinalityCheckpointHash?: ProtocolHash;
        readonly validWitnessIdentities: readonly string[];
        readonly equivocatingWitnessIdentities: readonly string[];
    };

export type EvaluatorReplayRecord = {
    readonly objectType: 'EvaluatorReplayRecord';
    readonly evaluatorReplayRecordHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly electionManifestHash: ProtocolHash;
    readonly targetProposalHash: ProtocolHash;
    readonly encryptedBallotAggregateHash: ProtocolHash;
    readonly targetFinalityRecordHash: ProtocolHash;
    readonly bgvParametersHash: ProtocolHash;
    readonly evaluatorReplayContextHash: ProtocolHash;
    readonly targetCiphertextHash: ProtocolHash;
    readonly targetLayoutHash: ProtocolHash;
    readonly replayEvidenceRoot: ProtocolHash;
    readonly mobileRuntimeParametersHash: ProtocolHash;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

export type TargetAcceptedRecord = {
    readonly objectType: 'TargetAcceptedRecord';
    readonly targetAcceptedRecordHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly electionManifestHash: ProtocolHash;
    readonly targetFinalityScope: string;
    readonly targetProposalHash: ProtocolHash;
    readonly evaluatorReplayRecordHash: ProtocolHash;
    readonly targetContextHash: ProtocolHash;
    readonly targetFinalityRecordHash: ProtocolHash;
    readonly targetFinalityCheckpointHash: ProtocolHash;
    readonly bgvParametersHash: ProtocolHash;
    readonly targetPreimageHash: ProtocolHash;
    readonly targetCiphertextHash: ProtocolHash;
    readonly targetLayoutHash: ProtocolHash;
    readonly targetDecryptionParametersHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly organizerIdentity: string;
};
