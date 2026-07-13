import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { ThresholdParameterDerivationError } from '@sealed-lattice/types';
import type {
    FrozenRosterParameters,
    PollSpec,
    ProtocolHash,
    ThresholdParameters,
    ThresholdParametersInput,
} from '@sealed-lattice/types';

import { derivePollSpecHash } from './poll-spec.js';
import {
    maximumSupportedRosterSize,
    minimumNonMicroRosterSize,
    minimumSupportedRosterSize,
} from './roster-policy.js';

/**
 * Derive deterministic structural counts for a roster.
 *
 * This calculator does not certify a backend corruption theorem, runtime
 * support, target-share selection, or any security level.
 */
export const deriveThresholdParameters = (
    input: ThresholdParametersInput,
): ThresholdParameters => {
    const { rosterSize } = input;
    if (!Number.isInteger(rosterSize)) {
        throw new ThresholdParameterDerivationError(
            'RosterSizeNotInteger',
            'Roster size must be an integer.',
        );
    }
    if (rosterSize < minimumSupportedRosterSize) {
        throw new ThresholdParameterDerivationError(
            'RosterSizeBelowSupportedMinimum',
            'Roster size must be at least 3.',
        );
    }
    if (rosterSize > maximumSupportedRosterSize) {
        throw new ThresholdParameterDerivationError(
            'RosterSizeAboveSupportedMaximum',
            'Roster size must be at most 20.',
        );
    }

    const structuralCorruptionBound = Math.floor(rosterSize / 3);
    const privacyCorruptionBound = structuralCorruptionBound;
    const decryptionCorruptionBound = structuralCorruptionBound;
    const activeFaultBound = Math.floor(rosterSize / 5);
    const ballotReleaseFloor = privacyCorruptionBound + 1;
    const decryptionThreshold = decryptionCorruptionBound + 1;
    const releaseQuorum = rosterSize;
    const maximumRaceShares = rosterSize;
    const setupCompletionQuorum = rosterSize;

    return {
        rosterSize,
        structuralCorruptionBound,
        privacyCorruptionBound,
        decryptionCorruptionBound,
        activeFaultBound,
        ballotReleaseFloor,
        decryptionThreshold,
        releaseQuorum,
        maximumRaceShares,
        setupCompletionQuorum,
    };
};

/**
 * Hash structural counts together with their poll and roster bindings.
 *
 * The resulting binding is deterministic but is not a certificate of runtime
 * support, cryptographic security, or participant acceptance.
 */
export const deriveThresholdParametersHash = (input: {
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly thresholdParameters: ThresholdParameters;
    readonly smallRosterPolicy: PollSpec['smallRosterPolicy'];
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
}): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'ThresholdParameters',
        activeFaultBound: input.thresholdParameters.activeFaultBound,
        ballotReleaseFloor: input.thresholdParameters.ballotReleaseFloor,
        decryptionCorruptionBound:
            input.thresholdParameters.decryptionCorruptionBound,
        decryptionThreshold: input.thresholdParameters.decryptionThreshold,
        maxRosterSize: input.maxRosterSize,
        maximumRaceShares: input.thresholdParameters.maximumRaceShares,
        minRosterSize: input.minRosterSize,
        pollSpecHash: input.pollSpecHash,
        privacyCorruptionBound:
            input.thresholdParameters.privacyCorruptionBound,
        releaseQuorum: input.thresholdParameters.releaseQuorum,
        rosterHash: input.rosterHash,
        rosterSize: input.thresholdParameters.rosterSize,
        setupCompletionQuorum: input.thresholdParameters.setupCompletionQuorum,
        smallRosterPolicy: input.smallRosterPolicy,
        structuralCorruptionBound:
            input.thresholdParameters.structuralCorruptionBound,
    });

/**
 * Validate poll roster bounds and bind the structural counts to a frozen roster.
 *
 * This function does not certify the roster, parameter security, or runtime
 * support; transcript verification must recompute and compare the binding.
 */
export const deriveFrozenRosterParameters = (input: {
    readonly pollSpec: PollSpec;
    readonly rosterHash: ProtocolHash;
    readonly rosterSize: number;
}): FrozenRosterParameters => {
    const { pollSpec, rosterSize } = input;

    if (
        rosterSize < pollSpec.minRosterSize ||
        rosterSize > pollSpec.maxRosterSize
    ) {
        throw new ThresholdParameterDerivationError(
            'FrozenRosterOutsidePollBounds',
            'Frozen roster size must be inside the poll roster bounds.',
        );
    }
    if (
        rosterSize < minimumNonMicroRosterSize &&
        pollSpec.smallRosterPolicy === 'ForbidMicroRoster'
    ) {
        throw new ThresholdParameterDerivationError(
            'MicroRosterForbidden',
            'Poll policy forbids freezing a micro-roster.',
        );
    }

    const thresholdParameters = deriveThresholdParameters({ rosterSize });
    const pollSpecHash = derivePollSpecHash(pollSpec);
    const thresholdParametersHash = deriveThresholdParametersHash({
        maxRosterSize: pollSpec.maxRosterSize,
        minRosterSize: pollSpec.minRosterSize,
        pollSpecHash,
        rosterHash: input.rosterHash,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        thresholdParameters,
    });

    return {
        objectType: 'FrozenRosterParameters',
        thresholdParametersHash,
        pollSpecHash,
        rosterHash: input.rosterHash,
        rosterSize,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        minRosterSize: pollSpec.minRosterSize,
        maxRosterSize: pollSpec.maxRosterSize,
        thresholdParameters,
    };
};
