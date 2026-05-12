import type {
    FailureStatusLabel,
    ModeStatusLabel,
    PrimaryStatusLabel,
} from './lifecycle.js';
import type { DecodedSparseTopKSelection } from './plaintext-oracle.js';
import type { ProtocolDigest } from './protocol-digest.js';

/** Canonical object type covered by protocol digest and verification helpers. */
export type ProtocolObjectType =
    | 'ActionContext'
    | 'BoardHead'
    | 'CastReceipt'
    | 'CloseRecord'
    | 'ElectionManifest'
    | 'EvaluationReplayAttestation'
    | 'FirstComeOrder'
    | 'RecoveryEpochUpdate'
    | 'ReceiverKeyRegistration'
    | 'RegistrationEntry'
    | 'Roster'
    | 'TargetAcceptedRecord'
    | 'TargetFinalityRecord'
    | 'TopKDecryptionShare'
    | 'TopKEvaluationRecord'
    | 'TrusteeSetupEntry'
    | 'WitnessCheckpoint';

/** Object type that is signed as a canonical signed root. */
export type SignedObjectType =
    | 'BoardHead'
    | 'CastReceipt'
    | 'CloseRecord'
    | 'ElectionManifest'
    | 'EvaluationReplayAttestation'
    | 'RecoveryEpochUpdate'
    | 'ReceiverKeyRegistration'
    | 'RegistrationEntry'
    | 'TargetAcceptedRecord'
    | 'TargetFinalityRecord'
    | 'TopKDecryptionShare'
    | 'TrusteeSetupEntry'
    | 'WitnessCheckpoint';

/** Role asserted by a protocol signature envelope. */
export type SignerRole =
    | 'Board'
    | 'Organizer'
    | 'Participant'
    | 'RecoveryRoot'
    | 'Trustee'
    | 'Voter'
    | 'Witness';

/** ML-DSA signature mode recorded in signature profiles. */
export type MlDsaSignatureMode = 'PureMLDSA' | 'HashMLDSA' | 'ExternalMuMLDSA';

/** ML-DSA provider and context profile bound to protocol signatures. */
export type MlDsaSignatureProfile = {
    readonly algorithm: 'ML-DSA-65';
    readonly mode: MlDsaSignatureMode;
    readonly providerName: string;
    readonly providerVersion: string;
    readonly providerBuildHash: ProtocolDigest;
    readonly fips204Version: string;
    readonly errataStatus: string;
    readonly contextString: string;
    readonly contextStringByteLength: number;
};

/** Canonical root object covered by a protocol signature. */
export type CanonicalSignedRootObject = {
    readonly objectType: SignedObjectType;
    readonly objectVersion: number;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolDigest | null;
    readonly boardHeadHash: ProtocolDigest | null;
    readonly objectRoot: ProtocolDigest | null;
    readonly chunkMerkleRoot: ProtocolDigest | null;
    readonly byteLength: number;
    readonly signerRole: SignerRole;
    readonly signerIdentity: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly contextDigest: ProtocolDigest;
};

/** Signature envelope attached to signed protocol objects. */
export type ProtocolSignatureEnvelope = {
    readonly profile: MlDsaSignatureProfile;
    readonly publicKeyDigest: ProtocolDigest;
    readonly publicKeyBytesHex: string;
    readonly signedRoot: CanonicalSignedRootObject;
    readonly signatureBytesHex: string;
    readonly signatureDigest: ProtocolDigest;
};

/** Unified status label emitted by protocol verification helpers. */
export type ProtocolVerificationStatusLabel =
    | PrimaryStatusLabel
    | FailureStatusLabel
    | ModeStatusLabel;

/** Stable refusal code emitted by protocol verification helpers. */
export type ProtocolRefusalCode =
    | 'BoardConsistencyFailure'
    | 'BoardForkDetected'
    | 'CastReceiptInvalid'
    | 'CloseRecordInvalid'
    | 'ConflictingFirstComeCandidate'
    | 'ConflictingManifest'
    | 'DecryptionShareInvalid'
    | 'DuplicateReceiverKeyRegistration'
    | 'DuplicateFirstComeCandidate'
    | 'DuplicateRegistration'
    | 'DuplicateTrusteeSetupEntry'
    | 'DuplicateWitness'
    | 'FieldElementInvalid'
    | 'FirstComeContextMismatch'
    | 'FirstComePolicyMismatch'
    | 'InclusionProofInvalid'
    | 'InvalidMlDsaContext'
    | 'InvalidSignature'
    | 'InvalidSignedRoot'
    | 'LateRegistration'
    | 'ManifestDigestMismatch'
    | 'MissingReceiverKeyRegistration'
    | 'MissingTrusteeSetupEntry'
    | 'PlaintextOracleInvalid'
    | 'RecoveryUpdateConflict'
    | 'RecoveryUpdateInvalid'
    | 'RecoveryUpdateStale'
    | 'ReplayAttestationInvalid'
    | 'RosterDigestMismatch'
    | 'ShamirInputInvalid'
    | 'SparseTargetInvalid'
    | 'TargetAcceptedRecordInvalid'
    | 'TargetFinalityPolicyMismatch'
    | 'TargetPhaseAuthorizationFailure'
    | 'TopKEvaluationRecordNotIncluded'
    | 'StaleRecoveryEpoch'
    | 'UnknownBoardHead'
    | 'UnknownRecoveryEpoch'
    | 'UnknownWitness'
    | 'WitnessPolicyMismatch'
    | 'WitnessQuorumNotReached'
    | 'WrongCeremony'
    | 'WrongObjectType'
    | 'WrongPublicKey'
    | 'WrongSignerRole';

/** Structured verification refusal for one object or condition. */
export type RefusalRecord = {
    readonly code: ProtocolRefusalCode;
    readonly message: string;
    readonly objectDigest?: ProtocolDigest;
    readonly objectType?: ProtocolObjectType | SignedObjectType;
};

/** Evidence that a board witness or backend published conflicting heads. */
export type ConflictingHeadEvidence = {
    readonly evidenceDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly boardPolicyDigest: ProtocolDigest;
    readonly leftBoardHeadDigest: ProtocolDigest;
    readonly rightBoardHeadDigest: ProtocolDigest;
    readonly targetPhase?: string;
    readonly equivocatingWitnessIdentities?: readonly string[];
};

/** Shared structured result shape for protocol verification helpers. */
export type StructuredProtocolVerificationResult = {
    readonly ok: boolean;
    readonly statusLabels: readonly ProtocolVerificationStatusLabel[];
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly RefusalRecord[];
    readonly forkEvidence?: ConflictingHeadEvidence;
    readonly unresolvedReason?: string;
};

/** Structured result shape returned by signature verification. */
export type SignatureVerificationResult = StructuredProtocolVerificationResult;

/** Sparse target decoder result with structured rejection reasons. */
export type SparseTopKTargetDecoding = StructuredProtocolVerificationResult & {
    readonly decodedSelections: readonly DecodedSparseTopKSelection[];
    readonly selectedOptionOrdinals: readonly number[];
    readonly targetDigest?: ProtocolDigest;
};
