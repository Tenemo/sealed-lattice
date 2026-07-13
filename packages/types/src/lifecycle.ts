import type { ProtocolHash } from './protocol-hash.js';

export const thresholdParameterDerivationErrorCodes = Object.freeze([
    'RosterSizeNotInteger',
    'RosterSizeBelowSupportedMinimum',
    'RosterSizeAboveSupportedMaximum',
    'FrozenRosterOutsidePollBounds',
    'MicroRosterForbidden',
] as const);

/** Stable failure code for threshold and frozen-roster parameter derivation. */
export type ThresholdParameterDerivationErrorCode =
    (typeof thresholdParameterDerivationErrorCodes)[number];

/** Machine-readable threshold and frozen-roster parameter derivation failure. */
export class ThresholdParameterDerivationError extends Error {
    public readonly code: ThresholdParameterDerivationErrorCode;

    public constructor(
        code: ThresholdParameterDerivationErrorCode,
        message: string,
    ) {
        super(message);
        this.name = 'ThresholdParameterDerivationError';
        this.code = code;
    }
}

/** Input used to derive structural threshold counts from a roster size. */
export type ThresholdParametersInput = {
    readonly rosterSize: number;
};

/**
 * Structurally derived threshold, quorum, and corruption-bound counts.
 *
 * This deterministic calculation is not a security certificate and does not
 * establish runtime support or a corruption theorem for a concrete backend.
 */
export type ThresholdParameters = {
    readonly rosterSize: number;
    readonly structuralCorruptionBound: number;
    readonly privacyCorruptionBound: number;
    readonly decryptionCorruptionBound: number;
    readonly activeFaultBound: number;
    readonly ballotReleaseFloor: number;
    readonly decryptionThreshold: number;
    readonly releaseQuorum: number;
    readonly maximumRaceShares: number;
    readonly setupCompletionQuorum: number;
};

/** Poll policy for frozen rosters containing fewer than ten participants. */
export type SmallRosterPolicy = 'ForbidMicroRoster' | 'AllowMicroRoster';

/** Untrusted poll specification input accepted by validation helpers. */
export type PollSpecInput = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
    readonly minRosterSize?: number;
    readonly maxRosterSize?: number;
    readonly smallRosterPolicy?: SmallRosterPolicy;
};

/** Normalized poll specification after validation defaults have been applied. */
export type PollSpec = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
    readonly smallRosterPolicy: SmallRosterPolicy;
};

/** Concrete threshold parameter output derived after roster freeze. */
export type FrozenRosterParameters = {
    readonly objectType: 'FrozenRosterParameters';
    readonly thresholdParametersHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly rosterSize: number;
    readonly smallRosterPolicy: SmallRosterPolicy;
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
    readonly thresholdParameters: ThresholdParameters;
};

/** Stable poll specification validation error code. */
export type PollSpecValidationErrorCode =
    | 'EmptyPollId'
    | 'EmptyQuestion'
    | 'UnsupportedHashCriticalText'
    | 'InvalidOptionCount'
    | 'EmptyOptionLabel'
    | 'DuplicateOptionLabel'
    | 'InvalidTopOptionCount'
    | 'InvalidRosterBounds'
    | 'UnsupportedSmallRosterPolicy';

/** Structured poll specification validation error. */
export type PollSpecValidationError = {
    readonly code: PollSpecValidationErrorCode;
    readonly field: string;
    readonly message: string;
};

/** Poll specification validation result with normalized output or errors. */
export type PollSpecValidation =
    | {
          readonly isValid: true;
          readonly normalized: PollSpec;
      }
    | {
          readonly isValid: false;
          readonly errors: readonly PollSpecValidationError[];
      };
