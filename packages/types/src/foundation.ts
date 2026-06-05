import type {
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
} from './board-target.js';
import type { ProtocolHash } from './protocol-hash.js';
import type { StructuredProtocolVerificationResult } from './protocol-objects.js';
import type {
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    RecoveryEpochVerificationInput,
    RecoveryEpochVerification,
    RosterExternalAcceptanceVerificationInput,
    RosterExternalAcceptanceVerification,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
} from './roster-recovery.js';

/** Integrated public foundation transcript verification input. */
export type FoundationTranscriptInput = {
    readonly rosterManifestTranscript: RosterManifestTranscriptInput;
    readonly rosterExternalAcceptance: RosterExternalAcceptanceVerificationInput;
    readonly firstValidOrdering: FirstValidOrderingInput;
    readonly targetFinality: TargetFinalityVerificationInput;
    readonly recoveryEpochUpdates?: readonly RecoveryEpochVerificationInput[];
    readonly expectedTopOptionCount: number;
    readonly expectedTiePolicyHash: ProtocolHash;
};

/** Component results retained by the integrated foundation verifier. */
export type FoundationTranscriptComponentResults = {
    readonly rosterManifest: RosterManifestTranscriptVerification;
    readonly rosterExternalAcceptance: RosterExternalAcceptanceVerification;
    readonly recoveryEpochUpdates: readonly RecoveryEpochVerification[];
    readonly firstValidOrdering: FirstValidOrderingVerification;
    readonly targetFinality: TargetFinalityVerification;
};

/** Structured foundation result that cannot represent a fully verified election. */
export type FoundationTranscriptVerification =
    StructuredProtocolVerificationResult & {
        readonly electionManifestHash?: ProtocolHash;
        readonly rosterHash?: ProtocolHash;
        readonly rosterExternalAcceptanceHash?: ProtocolHash;
        readonly firstValidOrderHash?: ProtocolHash;
        readonly targetProposalHash?: ProtocolHash;
        readonly targetFinalityCheckpointHash?: ProtocolHash;
        readonly targetFinalityRecordHash?: ProtocolHash;
        readonly validWitnessIdentities: readonly string[];
        readonly nextRequiredEvidence: readonly string[];
        readonly componentResults: FoundationTranscriptComponentResults;
    };
