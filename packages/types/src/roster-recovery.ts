import type { BoardConsistencyInput, InclusionProof } from './board-target.js';
import type { FrozenRosterProfile, PollSpec } from './lifecycle.js';
import type { ProtocolDigest } from './protocol-digest.js';
import type {
    ProtocolObjectType,
    ProtocolSignatureEnvelope,
    StructuredProtocolVerificationResult,
} from './protocol-objects.js';

/** Signed participant registration entry included before roster freeze. */
export type RegistrationEntry = {
    readonly objectType: 'RegistrationEntry';
    readonly objectVersion: 1;
    readonly registrationEntryDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly participantIdentity: string;
    readonly signingPublicKeyDigest: ProtocolDigest;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Signed receiver-key registration for encrypted trustee setup material. */
export type ReceiverKeyRegistration = {
    readonly objectType: 'ReceiverKeyRegistration';
    readonly objectVersion: 1;
    readonly receiverKeyRegistrationDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly participantIdentity: string;
    readonly receiverKeyRoot: ProtocolDigest;
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
    readonly trusteeSetupEntryDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly trusteeIdentity: string;
    readonly trusteeSetupRoot: ProtocolDigest;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Policy digests embedded in an election manifest. */
export type ManifestPolicyDigests = {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly duplicateBallotPolicyDigest: ProtocolDigest;
    readonly firstValidPolicyDigest: ProtocolDigest;
    readonly recoveryPolicyDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
    readonly witnessPolicyDigest: ProtocolDigest;
};

/** Opaque cryptographic implementation bindings embedded in a manifest. */
export type ManifestOpaqueBindings = {
    readonly encryptedAggregateBridgeProfileId: string;
    readonly bridgeWitnessPrivacyProfileId: string;
    readonly heParamDigest: ProtocolDigest;
    readonly bgvProfileDigest: ProtocolDigest;
    readonly rustBgvBackendProfileDigest: ProtocolDigest;
    readonly bgvPublicKeyRoot: ProtocolDigest;
    readonly collectivePublicKeyRoot: ProtocolDigest;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly encryptedAggregateBridgeDigest: ProtocolDigest;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly bgvBatchEncoderDigest: ProtocolDigest;
    readonly bridgeLayoutDigest: ProtocolDigest;
    readonly encryptedAggregateInputRoot: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly encryptedAggregateReconstructionDigest: ProtocolDigest;
    readonly scoreBitDerivationCircuitDigest: ProtocolDigest;
    readonly comparisonInputDerivationCircuitDigest: ProtocolDigest;
    readonly encryptedComparisonInputDigest: ProtocolDigest;
    readonly evaluationNoiseProfileDigest: ProtocolDigest;
    readonly heEvaluationNoiseCertDigest: ProtocolDigest;
    readonly allowedEvaluatorOpsDigest: ProtocolDigest;
    readonly evaluationProofProfileId: string;
    readonly evaluationProofProfileDigest: ProtocolDigest;
    readonly thresholdDecryptionProfileId: string;
    readonly thresholdDecryptionProfileDigest: ProtocolDigest;
    readonly kllpsTargetDecryptionProfileDigest: ProtocolDigest;
    readonly cpadProfileId: string;
    readonly cpadProfileDigest: ProtocolDigest;
    readonly targetBasisDigest: ProtocolDigest;
    readonly mobileProfileId: string;
    readonly bridgeBenchmarkReportPolicyDigest: ProtocolDigest;
};

/** Signed election manifest accepted after roster and setup checks. */
export type ElectionManifest = {
    readonly objectType: 'ElectionManifest';
    readonly objectVersion: 1;
    readonly electionManifestDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly pollSpecDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly manifestPolicyDigests: ManifestPolicyDigests;
    readonly manifestOpaqueBindings: ManifestOpaqueBindings;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Participant-local acceptance of a frozen open-link public roster. */
export type RosterExternalAcceptance = {
    readonly objectType: 'RosterExternalAcceptance';
    readonly objectVersion: 1;
    readonly rosterExternalAcceptanceDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly participantIdentity: string;
    readonly rosterDigest: ProtocolDigest;
    readonly electionManifestDigest: ProtocolDigest;
    readonly acceptedBoardHeadDigest: ProtocolDigest;
    readonly warningTextVersion: string;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Conflicting manifest evidence with the manifest and its inclusion proof. */
export type ConflictingManifestEvidence = {
    readonly manifest: ElectionManifest;
    readonly manifestInclusionProof: InclusionProof;
};

/** Input used to verify roster, manifest, receiver keys, and trustee setup. */
export type RosterManifestTranscriptInput = {
    readonly ceremonyId: string;
    readonly boardEvidence: BoardConsistencyInput;
    readonly registrationEntries: readonly RegistrationEntry[];
    readonly registrationInclusionProofs: readonly InclusionProof[];
    readonly receiverKeyRegistrations: readonly ReceiverKeyRegistration[];
    readonly receiverKeyRegistrationInclusionProofs: readonly InclusionProof[];
    readonly trusteeSetupEntries: readonly TrusteeSetupEntry[];
    readonly trusteeSetupInclusionProofs: readonly InclusionProof[];
    readonly pollSpec: PollSpec;
    readonly frozenRosterProfile: FrozenRosterProfile;
    readonly electionManifest: ElectionManifest;
    readonly organizerPublicKeyDigest: ProtocolDigest;
    readonly organizerIdentity: string;
    readonly rosterFreezeBoardSequence: number;
    readonly manifestInclusionProof: InclusionProof;
    readonly suppliedElectionManifests?: readonly ElectionManifest[];
    readonly conflictingManifestEvidence?: readonly ConflictingManifestEvidence[];
};

/** Roster and manifest transcript verification result. */
export type RosterManifestTranscriptVerification =
    StructuredProtocolVerificationResult & {
        readonly electionManifestDigest?: ProtocolDigest;
        readonly rosterDigest?: ProtocolDigest;
        readonly participantIdentities: readonly string[];
    };

/** Input used to verify participant-local open-link roster acceptance. */
export type RosterExternalAcceptanceVerificationInput = {
    readonly acceptance: RosterExternalAcceptance;
    readonly expectedCeremonyId: string;
    readonly expectedRosterDigest: ProtocolDigest;
    readonly expectedElectionManifestDigest: ProtocolDigest;
    readonly expectedAcceptedBoardHeadDigest: ProtocolDigest;
    readonly expectedParticipantPublicKeyDigest: ProtocolDigest;
};

/** Verification result for participant-local open-link roster acceptance. */
export type RosterExternalAcceptanceVerification =
    StructuredProtocolVerificationResult & {
        readonly rosterExternalAcceptanceDigest?: ProtocolDigest;
    };

/** Signed-action context used for replay and recovery freshness checks. */
export type ActionContext = {
    readonly actionContextDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly signerIdentity: string;
    readonly boardHeadDigest: ProtocolDigest;
    readonly boardSequence: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly actionSequence: number;
    readonly recoveryPolicyDigest: ProtocolDigest;
    readonly acceptedRecoveryEpochUpdateDigest: ProtocolDigest | null;
    readonly rosterExternalAcceptanceDigest: ProtocolDigest | null;
    readonly contextDigest: ProtocolDigest;
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
    readonly objectDigest: ProtocolDigest;
    readonly objectType: ProtocolObjectType;
    readonly boardSequence: number;
    readonly boardPosition: number;
    readonly signerIdentity: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly actionSequence: number;
    readonly contextDigest: ProtocolDigest;
    readonly isByteIdenticalRetransmission: boolean;
};

/** Input used to derive deterministic first-valid ordering. */
export type FirstValidOrderingInput = {
    readonly objects: readonly ValidatedFirstValidObject[];
    readonly requiredContextDigest: ProtocolDigest;
    readonly selectionPolicyDigest: ProtocolDigest;
    readonly expectedSelectionPolicyDigest: ProtocolDigest;
    readonly currentRecoveryEpochMap: Readonly<
        Record<string, RecoveryEpochMapEntry>
    >;
    readonly maxPerIdentity?: number;
};

/** First-valid ordering verification result with ordered objects. */
export type FirstValidOrderingVerification =
    StructuredProtocolVerificationResult & {
        readonly firstValidOrderDigest?: ProtocolDigest;
        readonly orderedObjects: readonly ValidatedFirstValidObject[];
    };

/** Signed recovery epoch update for a participant or trustee identity. */
export type RecoveryEpochUpdate = {
    readonly objectType: 'RecoveryEpochUpdate';
    readonly objectVersion: 1;
    readonly recoveryEpochUpdateDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly signerIdentity: string;
    readonly recoveryRootPublicKeyDigest: ProtocolDigest;
    readonly recoveryPolicyDigest: ProtocolDigest;
    readonly previousRecoveryEpoch: number;
    readonly newRecoveryEpoch: number;
    readonly previousDeviceEpoch: number;
    readonly newDeviceEpoch: number;
    readonly oldActionCutoffBoardSequence: number;
    readonly boardHeadDigest: ProtocolDigest;
    readonly newSigningPublicKeyDigest: ProtocolDigest;
    readonly restoredFrozenReceiverStateCommitment: ProtocolDigest;
    readonly newTrusteeSetupCommitment: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

/** Input used to verify a recovery epoch update. */
export type RecoveryEpochVerificationInput = {
    readonly update: RecoveryEpochUpdate;
    readonly currentEntry: RecoveryEpochMapEntry;
    readonly expectedRecoveryRootPublicKeyDigest: ProtocolDigest;
    readonly expectedRecoveryPolicyDigest: ProtocolDigest;
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
    readonly expectedRosterExternalAcceptanceDigest?: ProtocolDigest | null;
};

/** Result returned when checking action freshness against recovery state. */
export type ActionCurrentForRecoveryEpochResult =
    StructuredProtocolVerificationResult;
