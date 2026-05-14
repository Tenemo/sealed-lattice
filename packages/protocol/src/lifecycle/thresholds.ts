import type {
    AppendixCShareSelectionProfile,
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
    mandatoryClaimRosterSize,
    maximumCertificateGatedRosterSize,
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

const normalizeAppendixCShareSelectionProfile = (
    rosterSize: number,
    decryptionThreshold: number,
    profile: AppendixCShareSelectionProfile | undefined,
): AppendixCShareSelectionProfile | null => {
    if (profile === undefined) {
        return null;
    }

    if (profile.profileId.trim().length === 0) {
        throw new Error('Appendix C share-selection profile requires an ID.');
    }
    if (profile.certificateDigest.trim().length === 0) {
        throw new Error(
            'Appendix C share-selection profile requires a certificate digest.',
        );
    }
    if (!isNonNegativeInteger(profile.decryptionShareQuorum)) {
        throw new RangeError(
            'Appendix C decryption share quorum must be a non-negative integer.',
        );
    }
    if (profile.decryptionShareQuorum < decryptionThreshold) {
        throw new RangeError(
            'Appendix C decryption share quorum must be at least the decryption threshold.',
        );
    }
    if (profile.decryptionShareQuorum > rosterSize) {
        throw new RangeError(
            'Appendix C decryption share quorum must not exceed rosterSize.',
        );
    }
    if (!isNonNegativeInteger(profile.minimumSharesForInterpolation)) {
        throw new RangeError(
            'Appendix C interpolation share count must be a non-negative integer.',
        );
    }
    if (profile.minimumSharesForInterpolation < decryptionThreshold) {
        throw new RangeError(
            'Appendix C interpolation share count must be at least the decryption threshold.',
        );
    }
    if (profile.minimumSharesForInterpolation > profile.decryptionShareQuorum) {
        throw new RangeError(
            'Appendix C interpolation share count must not exceed the decryption share quorum.',
        );
    }
    if (!isNonNegativeInteger(profile.minimumArrivalsForRobustDecode)) {
        throw new RangeError(
            'Appendix C robust-decode arrival count must be a non-negative integer.',
        );
    }
    if (
        profile.minimumArrivalsForRobustDecode < profile.decryptionShareQuorum
    ) {
        throw new RangeError(
            'Appendix C robust-decode arrival count must be at least the decryption share quorum.',
        );
    }
    if (profile.minimumArrivalsForRobustDecode > rosterSize) {
        throw new RangeError(
            'Appendix C robust-decode arrival count must not exceed rosterSize.',
        );
    }
    if (
        !supportedDecryptionShareFilteringModes.has(
            profile.invalidShareFilteringMode,
        )
    ) {
        throw new Error(
            'Appendix C share-selection profile uses an unsupported invalid-share filtering mode.',
        );
    }
    if (
        !supportedDecryptionShareSelectionRules.has(profile.selectedShareRule)
    ) {
        throw new Error(
            'Appendix C share-selection profile uses an unsupported selected-share rule.',
        );
    }

    return {
        profileId: profile.profileId,
        certificateDigest: profile.certificateDigest,
        decryptionShareQuorum: profile.decryptionShareQuorum,
        minimumSharesForInterpolation: profile.minimumSharesForInterpolation,
        minimumArrivalsForRobustDecode: profile.minimumArrivalsForRobustDecode,
        invalidShareFilteringMode: profile.invalidShareFilteringMode,
        selectedShareRule: profile.selectedShareRule,
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
    const appendixCShareSelectionProfile =
        normalizeAppendixCShareSelectionProfile(
            rosterSize,
            decryptionThreshold,
            input.appendixCShareSelectionProfile,
        );
    const releaseQuorum = Math.min(
        rosterSize,
        Math.max(10, Math.ceil((2 * rosterSize) / 3)),
    );
    const aggregateContributionQuorum = pvssThreshold;
    const decryptionShareQuorum =
        appendixCShareSelectionProfile?.decryptionShareQuorum ?? null;
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
    if (appendixCShareSelectionProfile === null) {
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
        replayBadCorruptionBound,
        pvssThreshold,
        decryptionThreshold,
        releaseQuorum,
        aggregateContributionQuorum,
        decryptionShareQuorum,
        appendixCShareSelectionProfile,
        evaluationReplayQuorum,
        maximumRaceShares,
        setupCompletionQuorum,
        backendCorruptionModel,
        warnings,
    };
};
