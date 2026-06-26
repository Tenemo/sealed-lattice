import type { BoardConsistencyInput, InclusionProof } from './board-target.js';
import type { FrozenRosterParameters, PollSpec } from './lifecycle.js';
import type { ProtocolHash } from './protocol-hash.js';
import type {
    ProtocolObjectType,
    ProtocolSignatureEnvelope,
    StructuredProtocolVerificationResult,
} from './protocol-objects.js';

/** Signed participant registration entry included before roster freeze. */
export type RegistrationEntry = {
    readonly objectType: 'RegistrationEntry';
    readonly objectVersion: 1;
    readonly registrationEntryHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly participantIdentity: string;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Signed trustee setup entry bound to a frozen roster participant. */
export type TrusteeSetupEntry = {
    readonly objectType: 'TrusteeSetupEntry';
    readonly objectVersion: 1;
    readonly trusteeSetupEntryHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly trusteeIdentity: string;
    readonly trusteeSetupRoot: ProtocolHash;
    readonly bgvParametersHash: ProtocolHash;
    readonly participantSetupRecordHash: ProtocolHash;
    readonly publicKeyShareRoot: ProtocolHash;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly trusteeThresholdVerificationKeyHash: ProtocolHash;
    readonly thresholdShareVerificationKeyRoot: ProtocolHash;
    readonly evaluationKeyRoot: ProtocolHash;
    readonly rotSetHash: ProtocolHash;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Policy hashes embedded in an election manifest. */
export type ManifestPolicyHashes = {
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly duplicateBallotPolicyHash: ProtocolHash;
    readonly firstValidPolicyHash: ProtocolHash;
    readonly recoveryPolicyHash: ProtocolHash;
    readonly targetFinalityPolicyHash: ProtocolHash;
    readonly witnessPolicyHash: ProtocolHash;
};

/** Opaque cryptographic implementation bindings embedded in a manifest. */
export type ManifestOpaqueBindings = {
    readonly heParamHash: ProtocolHash;
    readonly bgvPassiveSetupPackageHash: ProtocolHash;
    readonly bgvParametersHash: ProtocolHash;
    readonly bgvPublicKeyRoot: ProtocolHash;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly keySwitchDecompositionHash: ProtocolHash;
    readonly ballotValidityProofParametersHash: ProtocolHash;
    readonly comparisonInputDerivationCircuitHash: ProtocolHash;
    readonly encryptedComparisonInputHash: ProtocolHash;
    readonly encryptedSparseTargetProjectionHash: ProtocolHash;
    readonly targetLayoutHash: ProtocolHash;
    readonly evaluatorReplayParametersHash: ProtocolHash;
    readonly evaluationNoiseParametersHash: ProtocolHash;
    readonly heEvaluationNoiseCertHash: ProtocolHash;
    readonly rotSetHash: ProtocolHash;
    readonly evaluationKeyRoot: ProtocolHash;
    readonly evaluationKeySizeParametersHash: ProtocolHash;
    readonly thresholdShareVerificationKeyRoot: ProtocolHash;
    readonly thresholdShareVerificationKeyHash: ProtocolHash;
    readonly trusteeThresholdVerificationKeyHash: ProtocolHash;
    readonly targetDecryptionParametersHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly mobileRuntimeParametersHash: ProtocolHash;
};

/** Signed election manifest accepted after roster and setup checks. */
export type ElectionManifest = {
    readonly objectType: 'ElectionManifest';
    readonly objectVersion: 1;
    readonly electionManifestHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly thresholdParametersHash: ProtocolHash;
    readonly manifestPolicyHashes: ManifestPolicyHashes;
    readonly manifestOpaqueBindings: ManifestOpaqueBindings;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Participant-local acceptance of a frozen open-link public roster. */
export type RosterExternalAcceptance = {
    readonly objectType: 'RosterExternalAcceptance';
    readonly objectVersion: 1;
    readonly rosterExternalAcceptanceHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly participantIdentity: string;
    readonly rosterHash: ProtocolHash;
    readonly electionManifestHash: ProtocolHash;
    readonly acceptedBoardHeadHash: ProtocolHash;
    readonly warningTextVersion: string;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Conflicting manifest evidence with the manifest and its inclusion proof. */
export type ConflictingManifestEvidence = {
    readonly manifest: ElectionManifest;
    readonly manifestInclusionProof: InclusionProof;
};

/** Input used to verify roster, manifest, and trustee setup. */
export type RosterManifestTranscriptInput = {
    readonly ceremonyId: string;
    readonly boardEvidence: BoardConsistencyInput;
    readonly registrationEntries: readonly RegistrationEntry[];
    readonly registrationInclusionProofs: readonly InclusionProof[];
    readonly trusteeSetupEntries: readonly TrusteeSetupEntry[];
    readonly trusteeSetupInclusionProofs: readonly InclusionProof[];
    readonly pollSpec: PollSpec;
    readonly frozenRosterParameters: FrozenRosterParameters;
    readonly electionManifest: ElectionManifest;
    readonly organizerPublicKeyHash: ProtocolHash;
    readonly organizerIdentity: string;
    readonly rosterFreezeBoardSequence: number;
    readonly manifestInclusionProof: InclusionProof;
    readonly suppliedElectionManifests?: readonly ElectionManifest[];
    readonly conflictingManifestEvidence?: readonly ConflictingManifestEvidence[];
};

/** Roster and manifest transcript verification result. */
export type RosterManifestTranscriptVerification =
    StructuredProtocolVerificationResult & {
        readonly electionManifestHash?: ProtocolHash;
        readonly rosterHash?: ProtocolHash;
        readonly participantIdentities: readonly string[];
    };

/** Input used to verify participant-local open-link roster acceptance. */
export type RosterExternalAcceptanceVerificationInput = {
    readonly acceptance: RosterExternalAcceptance;
    readonly expectedCeremonyId: string;
    readonly expectedRosterHash: ProtocolHash;
    readonly expectedElectionManifestHash: ProtocolHash;
    readonly expectedAcceptedBoardHeadHash: ProtocolHash;
    readonly expectedParticipantPublicKeyHash: ProtocolHash;
};

/** Verification result for participant-local open-link roster acceptance. */
export type RosterExternalAcceptanceVerification =
    StructuredProtocolVerificationResult & {
        readonly rosterExternalAcceptanceHash?: ProtocolHash;
    };

/** Signed-action context used for replay and recovery freshness checks. */
export type ActionContext = {
    readonly actionContextHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly electionManifestHash: ProtocolHash;
    readonly signerIdentity: string;
    readonly boardHeadHash: ProtocolHash;
    readonly boardSequence: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly actionSequence: number;
    readonly recoveryPolicyHash: ProtocolHash;
    readonly acceptedRecoveryEpochUpdateHash: ProtocolHash | null;
    readonly rosterExternalAcceptanceHash: ProtocolHash | null;
    readonly contextHash: ProtocolHash;
};

/** Current recovery epoch state for one signer identity. */
export type RecoveryEpochMapEntry = {
    readonly signerIdentity: string;
    readonly currentRecoveryEpoch: number;
    readonly currentDeviceEpoch: number;
    readonly oldActionCutoffBoardSequence?: number;
};

/** Candidate action after context, epoch, and duplicate checks. */
export type ValidatedFirstValidObject = {
    readonly objectHash: ProtocolHash;
    readonly objectType: ProtocolObjectType;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly signerIdentity: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly actionSequence: number;
    readonly contextHash: ProtocolHash;
    readonly isByteIdenticalRetransmission: boolean;
};

/** Input used to derive deterministic first-valid ordering. */
export type FirstValidOrderingInput = {
    readonly objects: readonly ValidatedFirstValidObject[];
    readonly requiredContextHash: ProtocolHash;
    readonly selectionPolicyHash: ProtocolHash;
    readonly expectedSelectionPolicyHash: ProtocolHash;
    readonly currentRecoveryEpochMap: Readonly<
        Record<string, RecoveryEpochMapEntry>
    >;
    readonly maxPerIdentity?: number;
};

/** First-valid ordering verification result with ordered objects. */
export type FirstValidOrderingVerification =
    StructuredProtocolVerificationResult & {
        readonly firstValidOrderHash?: ProtocolHash;
        readonly orderedObjects: readonly ValidatedFirstValidObject[];
    };

/** Signed recovery epoch update for a participant or trustee identity. */
export type RecoveryEpochUpdate = {
    readonly objectType: 'RecoveryEpochUpdate';
    readonly objectVersion: 1;
    readonly recoveryEpochUpdateHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly signerIdentity: string;
    readonly recoveryRootPublicKeyHash: ProtocolHash;
    readonly recoveryPolicyHash: ProtocolHash;
    readonly previousRecoveryEpoch: number;
    readonly newRecoveryEpoch: number;
    readonly previousDeviceEpoch: number;
    readonly newDeviceEpoch: number;
    readonly oldActionCutoffBoardSequence: number;
    readonly boardHeadHash: ProtocolHash;
    readonly newSigningPublicKeyHash: ProtocolHash;
    readonly restoredEncryptedBallotStateCommitment: ProtocolHash;
    readonly newTrusteeSetupCommitment: ProtocolHash;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Input used to verify a recovery epoch update. */
export type RecoveryEpochVerificationInput = {
    readonly update: RecoveryEpochUpdate;
    readonly currentEntry: RecoveryEpochMapEntry;
    readonly expectedRecoveryRootPublicKeyHash: ProtocolHash;
    readonly expectedRecoveryPolicyHash: ProtocolHash;
    readonly boardEvidence: BoardConsistencyInput;
    readonly updateInclusionProof: InclusionProof;
    readonly conflictingUpdates?: readonly RecoveryEpochUpdate[];
};

/** Recovery epoch verification result with the updated epoch entry. */
export type RecoveryEpochVerification = StructuredProtocolVerificationResult & {
    readonly updatedEntry?: RecoveryEpochMapEntry;
};

/** Input used to check whether an action matches the current recovery epoch. */
export type ActionCurrentForRecoveryEpochInput = {
    readonly actionContext: ActionContext;
    readonly recoveryEpochState: RecoveryEpochMapEntry;
    readonly expectedRosterExternalAcceptanceHash?: ProtocolHash | null;
};

/** Result returned when checking action freshness against recovery state. */
export type ActionCurrentForRecoveryEpochResult =
    StructuredProtocolVerificationResult;
