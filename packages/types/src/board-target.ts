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

/** Bulletin-board consistency verification result. */
export type BoardConsistencyVerification = StructuredProtocolVerificationResult;

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
