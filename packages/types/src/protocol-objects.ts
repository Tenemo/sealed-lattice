import type { ProtocolHash } from './protocol-hash.js';
import type { DecodedSparseTopKSelection } from './target-result.js';

/** Canonical object type covered by protocol hash and verification helpers. */
export type ProtocolObjectType =
    | 'ActionContext'
    | 'EncryptedBallot'
    | 'EncryptedBallotAggregate'
    | 'BallotValidityProofRecord'
    | 'BoardHead'
    | 'CastReceipt'
    | 'CloseRecord'
    | 'CommonRandomnessCommit'
    | 'CommonRandomnessReveal'
    | 'ElectionManifest'
    | 'EvaluatorReplayRecord'
    | 'FirstValidOrder'
    | 'FrozenRosterParameters'
    | 'RecoveryEpochUpdate'
    | 'RegistrationEntry'
    | 'Roster'
    | 'RosterExternalAcceptance'
    | 'TargetAcceptedRecord'
    | 'TargetFinalityRecord'
    | 'TopKDecryptionShare'
    | 'TrusteeSetupEntry';

/** Object type that is signed as a canonical signed root. */
export type SignedObjectType =
    | 'EncryptedBallot'
    | 'EncryptedBallotAggregate'
    | 'BallotValidityProofRecord'
    | 'BoardHead'
    | 'CastReceipt'
    | 'CloseRecord'
    | 'CommonRandomnessCommit'
    | 'CommonRandomnessReveal'
    | 'ElectionManifest'
    | 'EvaluatorReplayRecord'
    | 'RecoveryEpochUpdate'
    | 'RegistrationEntry'
    | 'RosterExternalAcceptance'
    | 'SetupPhaseParticipantObject'
    | 'TargetFinalityRecord'
    | 'TopKDecryptionShare'
    | 'TrusteeSetupEntry'
    | 'VssShareAcceptance'
    | 'VssShareComplaint';

/** Role asserted by a protocol signature envelope. */
export type SignerRole =
    | 'Board'
    | 'Organizer'
    | 'Participant'
    | 'RecoveryRoot'
    | 'Trustee'
    | 'Voter';

/** ML-DSA signature mode recorded in signature profiles. */
export type MlDsaSignatureMode = 'PureMLDSA' | 'HashMLDSA' | 'ExternalMuMLDSA';

/** ML-DSA provider and context profile bound to protocol signatures. */
export type MlDsaSignatureProfile = {
    readonly algorithm: 'ML-DSA-65';
    readonly mode: MlDsaSignatureMode;
    readonly contextString: string;
};

/** Canonical root object covered by a protocol signature. */
export type CanonicalSignedRootObject = {
    readonly objectType: SignedObjectType;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash | null;
    readonly boardHeadHash: ProtocolHash | null;
    readonly objectRoot: ProtocolHash | null;
    readonly chunkMerkleRoot: ProtocolHash | null;
    readonly signerRole: SignerRole;
    readonly signerIdentity: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly contextHash: ProtocolHash;
};

/** Signature envelope attached to signed protocol objects. */
export type ProtocolSignatureEnvelope = {
    readonly profile: MlDsaSignatureProfile;
    readonly publicKeyHash: ProtocolHash;
    readonly publicKeyBytesHex: string;
    readonly signedRoot: CanonicalSignedRootObject;
    readonly signatureBytesHex: string;
    readonly signatureHash: ProtocolHash;
};

/** Stable refusal code emitted by protocol verification helpers. */
export type ProtocolRefusalCode =
    | 'EncryptedBallotInvalid'
    | 'EncryptedBallotAggregateInvalid'
    | 'BallotSetInvalid'
    | 'BallotValidityProofInvalid'
    | 'BallotValidityProofParametersInvalid'
    | 'BoardConsistencyFailure'
    | 'BoardForkDetected'
    | 'CastReceiptInvalid'
    | 'CloseRecordInvalid'
    | 'ConflictingFirstValidObject'
    | 'ConflictingEncryptedBallot'
    | 'ConflictingManifest'
    | 'DecryptionShareInvalid'
    | 'DuplicateEncryptedBallot'
    | 'DuplicateFirstValidObject'
    | 'DuplicateRegistration'
    | 'DuplicateTrusteeSetupEntry'
    | 'EvaluatorReplayInvalid'
    | 'FirstValidContextMismatch'
    | 'FirstValidPolicyMismatch'
    | 'InclusionProofInvalid'
    | 'InvalidMlDsaContext'
    | 'InvalidSignature'
    | 'InvalidSignedRoot'
    | 'LateRegistration'
    | 'ManifestHashMismatch'
    | 'MissingTrusteeSetupEntry'
    | 'OperationUnavailable'
    | 'RecoveryUpdateConflict'
    | 'RecoveryUpdateInvalid'
    | 'RecoveryUpdateStale'
    | 'RosterHashMismatch'
    | 'RosterExternalAcceptanceInvalid'
    | 'TargetAcceptedRecordInvalid'
    | 'StaleRecoveryEpoch'
    | 'UnknownBoardHead'
    | 'UnknownRecoveryEpoch'
    | 'WrongCeremony'
    | 'WrongObjectType'
    | 'WrongPublicKey'
    | 'WrongSignerRole';

/** Structured verification refusal for one object or condition. */
export type RefusalRecord = {
    readonly code: ProtocolRefusalCode;
    readonly message: string;
    readonly objectHash?: ProtocolHash;
    readonly objectType?: ProtocolObjectType | SignedObjectType;
};

/** Evidence that a board witness or backend published conflicting heads. */
export type ConflictingHeadEvidence = {
    readonly evidenceHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly boardPolicyHash: ProtocolHash;
    readonly leftBoardHeadHash: ProtocolHash;
    readonly rightBoardHeadHash: ProtocolHash;
    readonly targetFinalityScope?: string;
    readonly equivocatingWitnessIdentities?: readonly string[];
};

/** Shared structured result shape for protocol verification helpers. */
export type StructuredProtocolVerificationResult = {
    readonly isValid: boolean;
    readonly refusedObjects: readonly RefusalRecord[];
    readonly forkEvidence?: ConflictingHeadEvidence;
};

/** Structured result shape returned by signature verification. */
export type SignatureVerificationResult = StructuredProtocolVerificationResult;

/** Sparse target decoder result with structured rejection reasons. */
export type SparseTopKTargetDecoding = StructuredProtocolVerificationResult & {
    readonly decodedSelections: readonly DecodedSparseTopKSelection[];
    readonly selectedOptionOrdinals: readonly number[];
    readonly targetHash?: ProtocolHash;
};
