import type {
    TargetBoundShareSelectionProfile,
    DecryptionShareFilteringMode,
    DecryptionShareSelectionRule,
    HeBackendCorruptionModel,
    RosterProfileKind,
    ThresholdProfile,
    ThresholdProfileInput,
    ThresholdWarning,
} from '@sealed-lattice/types';

import { isNonNegativeInteger } from '../common/verification-helpers.js';

import {
    targetBoundShareSelectionProfileId,
    cpadProfileId,
    maximumSafeRosterSize,
    minimumSafeRosterSize,
    minimumUnsafeRosterSize,
    strictLessThanOneThirdModel,
} from './profiles.js';

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

const supportedDecryptionShareFilteringModes =
    new Set<DecryptionShareFilteringMode>([
        'ProofVerifiedSharesOnly',
        'RobustDecodeAfterInvalidShareFiltering',
    ]);

const supportedDecryptionShareSelectionRules =
    new Set<DecryptionShareSelectionRule>([
        'FirstValidSharesInCanonicalBoardOrder',
    ]);

const normalizeTargetBoundShareSelectionProfile = (
    rosterSize: number,
    decryptionThreshold: number,
    profile: TargetBoundShareSelectionProfile | undefined,
): TargetBoundShareSelectionProfile | null => {
    if (profile === undefined) {
        return null;
    }

    if (profile.profileId !== targetBoundShareSelectionProfileId) {
        throw new Error(
            'Target-bound share-selection profile uses an unsupported ID.',
        );
    }
    if (profile.certificateDigest.trim().length === 0) {
        throw new Error(
            'Target-bound share-selection profile requires a certificate digest.',
        );
    }
    if (profile.cpadProfileId !== cpadProfileId) {
        throw new Error(
            'Target-bound share-selection profile uses an unsupported CPAD profile ID.',
        );
    }
    if (profile.targetBasisDigest.trim().length === 0) {
        throw new Error(
            'Target-bound share-selection profile requires a target-basis digest.',
        );
    }
    if (!isNonNegativeInteger(profile.decryptionShareQuorum)) {
        throw new RangeError(
            'Target-bound decryption share quorum must be a non-negative integer.',
        );
    }
    if (profile.decryptionShareQuorum < decryptionThreshold) {
        throw new RangeError(
            'Target-bound decryption share quorum must be at least the decryption threshold.',
        );
    }
    if (profile.decryptionShareQuorum > rosterSize) {
        throw new RangeError(
            'Target-bound decryption share quorum must not exceed rosterSize.',
        );
    }
    if (!isNonNegativeInteger(profile.minimumSharesForInterpolation)) {
        throw new RangeError(
            'Target-bound interpolation share count must be a non-negative integer.',
        );
    }
    if (profile.minimumSharesForInterpolation < decryptionThreshold) {
        throw new RangeError(
            'Target-bound interpolation share count must be at least the decryption threshold.',
        );
    }
    if (profile.minimumSharesForInterpolation > profile.decryptionShareQuorum) {
        throw new RangeError(
            'Target-bound interpolation share count must not exceed the decryption share quorum.',
        );
    }
    if (!isNonNegativeInteger(profile.minimumArrivalsForRobustDecode)) {
        throw new RangeError(
            'Target-bound robust-decode arrival count must be a non-negative integer.',
        );
    }
    if (
        profile.minimumArrivalsForRobustDecode < profile.decryptionShareQuorum
    ) {
        throw new RangeError(
            'Target-bound robust-decode arrival count must be at least the decryption share quorum.',
        );
    }
    if (profile.minimumArrivalsForRobustDecode > rosterSize) {
        throw new RangeError(
            'Target-bound robust-decode arrival count must not exceed rosterSize.',
        );
    }
    if (
        !supportedDecryptionShareFilteringModes.has(
            profile.invalidShareFilteringMode,
        )
    ) {
        throw new Error(
            'Target-bound share-selection profile uses an unsupported invalid-share filtering mode.',
        );
    }
    if (
        !supportedDecryptionShareSelectionRules.has(profile.selectedShareRule)
    ) {
        throw new Error(
            'Target-bound share-selection profile uses an unsupported selected-share rule.',
        );
    }

    return {
        profileId: profile.profileId,
        certificateDigest: profile.certificateDigest,
        cpadProfileId: profile.cpadProfileId,
        targetBasisDigest: profile.targetBasisDigest,
        decryptionShareQuorum: profile.decryptionShareQuorum,
        minimumSharesForInterpolation: profile.minimumSharesForInterpolation,
        minimumArrivalsForRobustDecode: profile.minimumArrivalsForRobustDecode,
        invalidShareFilteringMode: profile.invalidShareFilteringMode,
        selectedShareRule: profile.selectedShareRule,
    };
};

const deriveRosterProfile = (
    rosterSize: number,
    unsafeSmallRosterAcknowledged: boolean | undefined,
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
    if (rosterSize > maximumSafeRosterSize) {
        throw new RangeError('Roster size must be at most 50.');
    }
    if (rosterSize < minimumSafeRosterSize) {
        if (unsafeSmallRosterAcknowledged !== true) {
            throw new Error(
                'Unsafe small-roster profiles require explicit acknowledgement.',
            );
        }

        return {
            claimBearing: true,
            rosterProfileKind: 'UnsafeSmallRoster',
            warnings: ['UnsafeSmallRoster'],
        };
    }

    return {
        claimBearing: true,
        rosterProfileKind: 'SupportedRosterRange',
        warnings: [],
    };
};

export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => {
    const { rosterSize } = input;
    const rosterProfile = deriveRosterProfile(
        rosterSize,
        input.unsafeSmallRosterAcknowledged ??
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
    const pvssThreshold = privacyCorruptionBound + 1;
    const decryptionThreshold = decryptionCorruptionBound + 1;
    const targetBoundShareSelectionProfile =
        normalizeTargetBoundShareSelectionProfile(
            rosterSize,
            decryptionThreshold,
            input.targetBoundShareSelectionProfile,
        );
    const releaseQuorum = Math.min(
        rosterSize,
        Math.max(10, Math.ceil((2 * rosterSize) / 3)),
    );
    const aggregateContributionQuorum = pvssThreshold;
    const decryptionShareQuorum =
        targetBoundShareSelectionProfile?.decryptionShareQuorum ?? null;
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
    if (targetBoundShareSelectionProfile === null) {
        warnings.push('ShareSelectionProfileRequired');
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
        pvssThreshold,
        decryptionThreshold,
        releaseQuorum,
        aggregateContributionQuorum,
        decryptionShareQuorum,
        targetBoundShareSelectionProfile,
        maximumRaceShares,
        setupCompletionQuorum,
        backendCorruptionModel,
        warnings,
    };
};
