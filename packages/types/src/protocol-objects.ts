import type { ProtocolHash } from './protocol-hash.js';

/** Canonical object type covered by protocol hash and verification helpers. */
export type ProtocolObjectType =
    | 'ActionContext'
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
    | 'TrusteeSetupEntry';

/** Object type that is signed as a canonical signed root. */
export type SignedObjectType =
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
    | 'CollectiveBgvSetupIntentTrusteeRegistration'
    | 'TargetFinalityRecord'
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

/** Canonical root object covered by a protocol signature. */
export type CanonicalSignedRootObject = {
    readonly objectType: SignedObjectType;
    readonly ceremonyId: string;
    readonly manifestHash?: ProtocolHash;
    readonly boardHeadHash?: ProtocolHash;
    readonly objectRoot?: ProtocolHash;
    readonly chunkMerkleRoot?: ProtocolHash;
    readonly signerRole: SignerRole;
    readonly signerIdentity: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly contextHash: ProtocolHash;
};

/** Signature envelope attached to signed protocol objects. */
export type ProtocolSignatureEnvelope = {
    readonly publicKeyHash: ProtocolHash;
    readonly publicKeyBytesHex: string;
    readonly signedRoot: CanonicalSignedRootObject;
    readonly signatureBytesHex: string;
};

/** Stable refusal code emitted by protocol verification helpers. */
export type ProtocolRefusalCode =
    | 'BoardConsistencyFailure'
    | 'BoardForkDetected'
    | 'CastReceiptInvalid'
    | 'CloseRecordInvalid'
    | 'ConflictingFirstValidObject'
    | 'ConflictingManifest'
    | 'DuplicateRegistration'
    | 'DuplicateTrusteeSetupEntry'
    | 'FirstValidContextMismatch'
    | 'FirstValidPolicyMismatch'
    | 'InclusionProofInvalid'
    | 'InvalidSignature'
    | 'InvalidSignedRoot'
    | 'LateRegistration'
    | 'ManifestHashMismatch'
    | 'MissingTrusteeSetupEntry'
    | 'RecoveryUpdateConflict'
    | 'RecoveryUpdateInvalid'
    | 'RecoveryUpdateStale'
    | 'RosterHashMismatch'
    | 'RosterExternalAcceptanceInvalid'
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
