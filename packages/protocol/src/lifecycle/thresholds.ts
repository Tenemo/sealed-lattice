import type {
    HeBackendCorruptionModel,
    RosterProfileKind,
    ThresholdProfile,
    ThresholdProfileInput,
    ThresholdWarning,
} from '@sealed-lattice/types';

import {
    mandatoryClaimRosterSize,
    maximumCertificateGatedRosterSize,
    minimumUnsafeRosterSize,
    strictLessThanOneThirdModel,
} from './profiles.js';

const isNonNegativeInteger = (value: number): boolean =>
    Number.isInteger(value) && value >= 0;

const normalizeBackendCorruptionModel = (
    rosterSize: number,
    model: HeBackendCorruptionModel | undefined,
): HeBackendCorruptionModel => {
    if (model === undefined) {
        return strictLessThanOneThirdModel;
    }

    if (model.kind === 'StrictLessThanOneThird') {
        return strictLessThanOneThirdModel;
    }

    if (!isNonNegativeInteger(model.backendCorruptionBound)) {
        throw new RangeError(
            'Certified HE backend corruption bound must be a non-negative integer.',
        );
    }
    if (model.backendCorruptionBound >= rosterSize) {
        throw new RangeError(
            'Certified HE backend corruption bound must be less than rosterSize.',
        );
    }
    if (model.certificateDigest.length === 0) {
        throw new Error('Certified HE backend profile requires a digest.');
    }

    return {
        kind: 'CertifiedCustom',
        backendCorruptionBound: model.backendCorruptionBound,
        certificateDigest: model.certificateDigest,
    };
};

const deriveRosterProfile = (
    rosterSize: number,
    unsafeMicroRosterAcknowledged: boolean | undefined,
): {
    readonly claimBearing: boolean;
    readonly rosterProfileKind: RosterProfileKind;
    readonly warnings: readonly ThresholdWarning[];
} => {
    if (!Number.isInteger(rosterSize)) {
        throw new RangeError('Roster size must be an integer.');
    }
    if (rosterSize < minimumUnsafeRosterSize) {
        throw new RangeError('Roster size must be at least 3.');
    }
    if (rosterSize > maximumCertificateGatedRosterSize) {
        throw new RangeError('Roster size must be at most 50.');
    }
    if (rosterSize < mandatoryClaimRosterSize) {
        if (unsafeMicroRosterAcknowledged !== true) {
            throw new Error(
                'Unsafe micro-roster profiles require explicit acknowledgement.',
            );
        }

        return {
            claimBearing: false,
            rosterProfileKind: 'UnsafeMicroRoster',
            warnings: ['UnsafeMicroRoster'],
        };
    }
    if (rosterSize === mandatoryClaimRosterSize) {
        return {
            claimBearing: true,
            rosterProfileKind: 'MandatoryN20',
            warnings: [],
        };
    }

    return {
        claimBearing: false,
        rosterProfileKind: 'CertificateGatedRange',
        warnings: ['CertificateGatedProfile', 'BackendCertificateRequired'],
    };
};

export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => {
    const { rosterSize } = input;
    const rosterProfile = deriveRosterProfile(
        rosterSize,
        input.unsafeMicroRosterAcknowledged,
    );
    const backendCorruptionModel = normalizeBackendCorruptionModel(
        rosterSize,
        input.heBackendCorruptionModel,
    );
    const structuralCorruptionBound = Math.floor(rosterSize / 3);
    const backendCorruptionBound =
        backendCorruptionModel.kind === 'StrictLessThanOneThird'
            ? Math.floor((rosterSize - 1) / 3)
            : backendCorruptionModel.backendCorruptionBound;
    const privacyCorruptionBound = Math.min(
        structuralCorruptionBound,
        backendCorruptionBound,
    );
    const decryptionCorruptionBound = privacyCorruptionBound;
    const activeFaultBound = Math.floor(rosterSize / 5);
    const replayBadCorruptionBound = activeFaultBound;
    const pvssThreshold = privacyCorruptionBound + 1;
    const decryptionThreshold = decryptionCorruptionBound + 1;
    const releaseQuorum = Math.min(
        rosterSize,
        Math.max(10, Math.ceil((2 * rosterSize) / 3)),
    );
    const aggregateContributionQuorum = pvssThreshold;
    const decryptionShareQuorum = decryptionThreshold;
    const evaluationReplayQuorum = activeFaultBound + 1;
    const maximumRaceShares = rosterSize;
    const setupCompletionQuorum = rosterSize;
    const warnings = [...rosterProfile.warnings];

    if (
        backendCorruptionModel.kind === 'CertifiedCustom' &&
        backendCorruptionModel.backendCorruptionBound >
            structuralCorruptionBound
    ) {
        warnings.push('BackendCorruptionBoundTooHigh');
    }

    return {
        rosterSize,
        rosterProfileKind: rosterProfile.rosterProfileKind,
        claimBearing: rosterProfile.claimBearing,
        structuralCorruptionBound,
        backendCorruptionBound,
        privacyCorruptionBound,
        decryptionCorruptionBound,
        activeFaultBound,
        replayBadCorruptionBound,
        pvssThreshold,
        decryptionThreshold,
        releaseQuorum,
        aggregateContributionQuorum,
        decryptionShareQuorum,
        evaluationReplayQuorum,
        maximumRaceShares,
        setupCompletionQuorum,
        backendCorruptionModel,
        warnings,
    };
};
