import type { BoardConsistencyInput, InclusionProof } from './board-target.js';
import type { PollSpec, ThresholdProfile } from './lifecycle.js';
import type {
    FieldElement,
    NormalizedPlaintextScoreBallot,
    PlaintextScoreBallotInput,
    ShamirPolynomial,
} from './plaintext-oracle.js';
import type { ProtocolDigest } from './protocol-digest.js';
import type {
    ProtocolSignatureEnvelope,
    ProtocolVerificationStatusLabel,
    RefusalRecord,
} from './protocol-objects.js';

/** Fixed receiver share-vector width for additive score ballots. */
export type PvssBallotShareVectorWidth = 20;

/** Frozen roster entry used by internal ballot algebra helpers. */
export type PvssBallotRosterEntry = {
    readonly participantIdentity: string;
    readonly rosterPosition: number;
    readonly signingPublicKeyDigest?: ProtocolDigest;
};

/** Deterministic internal input for test-mode ballot algebra. */
export type PvssBallotAlgebraInput = {
    readonly ceremonyId: string;
    readonly voterIdentity: string;
    readonly voterRosterPosition: number;
    readonly electionManifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly duplicateBallotPolicyDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly pollSpec: PollSpec;
    readonly thresholdProfile: ThresholdProfile;
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly scoreBallot: PlaintextScoreBallotInput;
    readonly fixtureEntropy: string;
};

/** One option polynomial used by the internal ballot algebra fixture path. */
export type BallotOptionPolynomial = {
    readonly optionIndex: number;
    readonly optionOrdinal: number;
    readonly polynomial: ShamirPolynomial;
};

/** Deterministic Shamir polynomial set for one normalized score ballot. */
export type BallotPolynomialSet = {
    readonly ballotPolynomialSetDigest: ProtocolDigest;
    readonly normalizedBallot: NormalizedPlaintextScoreBallot;
    readonly optionPolynomials: readonly BallotOptionPolynomial[];
    readonly pvssThreshold: number;
};

/** One fixed-width receiver share vector for a frozen roster participant. */
export type ReceiverShareVector = {
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly optionCount: number;
    readonly shareVectorWidth: PvssBallotShareVectorWidth;
    readonly shareVector: readonly FieldElement[];
};

/** Deliberately weak additive commitment used only by internal tests. */
export type TestShareCommitment = {
    readonly objectType: 'TestShareCommitment';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly commitmentValues: readonly FieldElement[];
    readonly shareCommitmentDigest: ProtocolDigest;
};

/** Private opening witness for one test share commitment. */
export type TestShareCommitmentWitness = {
    readonly commitment: TestShareCommitment;
    readonly openingVector: readonly FieldElement[];
    readonly shareVector: readonly FieldElement[];
};

/** Private receiver payload placeholder used only by test fixtures. */
export type TestReceiverShareOpeningPayload = {
    readonly objectType: 'TestReceiverShareOpeningPayload';
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly shareVector: readonly FieldElement[];
    readonly openingVector: readonly FieldElement[];
    readonly payloadDigest: ProtocolDigest;
};

/** Digest reference to one receiver commitment inside a ballot package shell. */
export type ReceiverShareCommitmentReference = {
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCommitmentDigest: ProtocolDigest;
};

/** Digest reference to one receiver payload placeholder inside a ballot package shell. */
export type ReceiverPayloadDigestReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly payloadDigest: ProtocolDigest;
};

/** Transcript-facing shell for one internally generated ballot package. */
export type BallotPackageShell = {
    readonly objectType: 'BallotPackage';
    readonly objectVersion: 1;
    readonly ballotPackageDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly duplicateBallotPolicyDigest: ProtocolDigest;
    readonly voterIdentity: string;
    readonly voterRosterPosition: number;
    readonly optionCount: number;
    readonly shareVectorWidth: PvssBallotShareVectorWidth;
    readonly ballotPolynomialSetDigest: ProtocolDigest;
    readonly receiverShareCommitments: readonly ReceiverShareCommitmentReference[];
    readonly receiverPayloadDigests: readonly ReceiverPayloadDigestReference[];
    readonly signature: ProtocolSignatureEnvelope;
};

/** Private witness bundle for one internal test-mode ballot package. */
export type BallotPackageWitness = {
    readonly ballotPackage: BallotPackageShell;
    readonly polynomialSet: BallotPolynomialSet;
    readonly receiverShareVectors: readonly ReceiverShareVector[];
    readonly shareCommitmentWitnesses: readonly TestShareCommitmentWitness[];
    readonly receiverPayloads: readonly TestReceiverShareOpeningPayload[];
};

/** Stable signed-board position tuple used for deterministic ordering. */
export type SignedBoardOrder = {
    readonly boardSequence: number;
    readonly boardPosition: number;
};

/** Candidate ballot package and inclusion evidence supplied to set selection. */
export type BallotPackageCandidate = {
    readonly ballotPackage: BallotPackageShell;
    readonly inclusionProof: InclusionProof;
};

/** Counted ballot package emitted in deterministic board order. */
export type CountedBallotPackage = BallotPackageCandidate & {
    readonly signedBoardOrder: SignedBoardOrder;
};

/** Rejected candidate summary kept separate from fatal derivation refusals. */
export type RejectedBallotCandidate = {
    readonly ballotPackageDigest: ProtocolDigest;
    readonly voterIdentity?: string;
    readonly signedBoardOrder?: SignedBoardOrder;
    readonly refusalCodes: readonly string[];
};

/** Input used to derive the canonical counted ballot set. */
export type CanonicalBallotSetInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly duplicateBallotPolicyDigest: ProtocolDigest;
    readonly pollSpec: PollSpec;
    readonly thresholdProfile: ThresholdProfile;
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
    readonly closeRecordDigest: ProtocolDigest;
    readonly closeRecordBoardOrder: SignedBoardOrder;
    readonly candidateBallots: readonly BallotPackageCandidate[];
    readonly includeRejectedCandidateSummariesInDigest?: boolean;
};

/** Canonical ballot set selected under the frozen duplicate policy. */
export type CanonicalBallotSet = {
    readonly ok: boolean;
    readonly statusLabels: readonly ProtocolVerificationStatusLabel[];
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly RefusalRecord[];
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly duplicateBallotPolicyDigest: ProtocolDigest;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
    readonly closeRecordDigest: ProtocolDigest;
    readonly countedBallots: readonly CountedBallotPackage[];
    readonly rejectedCandidates: readonly RejectedBallotCandidate[];
    readonly ballotSetDigest?: ProtocolDigest;
};

/** Aggregate share and commitment for one trustee in the internal fixture path. */
export type TestAggregateShare = {
    readonly objectType: 'TestAggregateShare';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareVectorWidth: PvssBallotShareVectorWidth;
    readonly aggregateShareVector: readonly FieldElement[];
    readonly aggregateCommitmentValues: readonly FieldElement[];
    readonly aggregateShareCommitmentDigest: ProtocolDigest;
};

/** Private aggregate opening witness used only by tests. */
export type TestAggregateShareWitness = {
    readonly aggregateShare: TestAggregateShare;
    readonly aggregateOpeningVector: readonly FieldElement[];
};

/** Output of internal test aggregate-share derivation. */
export type TestAggregateShareSet = {
    readonly ballotSetDigest: ProtocolDigest;
    readonly aggregateShares: readonly TestAggregateShareWitness[];
};
