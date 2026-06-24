import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    FrozenRosterProfile,
    PollSpec,
    ProtocolHash,
    TargetBoundShareSelectionProfile,
    DecryptionShareFilteringMode,
    HeBackendCorruptionModel,
    RosterProfileKind,
    ThresholdProfile,
    ThresholdProfileInput,
    ThresholdWarning,
} from '@sealed-lattice/types';

import {
    isNonNegativeInteger,
    isProtocolHashString,
} from '../common/verification-helpers.js';

import { derivePollSpecHash } from './poll-spec.js';
import {
    firstProfileRosterSize,
    maximumSupportedRosterSize,
    minimumDynamicRosterSize,
    minimumSupportedRosterSize,
    structuralOneThirdModel,
    targetBoundShareSelectionProfileId,
    targetDecryptionProfileId,
} from './profiles.js';

const normalizeDynamicRosterProfileCertificateHash = (
    hash: ProtocolHash | undefined,
): ProtocolHash | null => (isProtocolHashString(hash) ? hash : null);

const normalizeBackendCorruptionModel = (
    rosterSize: number,
    model: HeBackendCorruptionModel | undefined,
): HeBackendCorruptionModel => {
    if (model === undefined) {
        return structuralOneThirdModel;
    }

    if (model.kind === 'StructuralOneThird') {
        return structuralOneThirdModel;
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
    if (model.certificateHash.length === 0) {
        throw new Error('Certified HE backend profile requires a hash.');
    }

    return {
        kind: 'CertifiedCustom',
        backendCorruptionBound: model.backendCorruptionBound,
        certificateHash: model.certificateHash,
    };
};

const supportedDecryptionShareFilteringModes =
    new Set<DecryptionShareFilteringMode>([
        'ProofVerifiedSharesOnly',
        'RobustDecodeAfterInvalidShareFiltering',
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
    if (profile.certificateHash.trim().length === 0) {
        throw new Error(
            'Target-bound share-selection profile requires a certificate hash.',
        );
    }
    if (profile.targetDecryptionProfileId !== targetDecryptionProfileId) {
        throw new Error(
            'Target-bound share-selection profile uses an unsupported target decryption profile ID.',
        );
    }
    if (profile.targetBasisHash.trim().length === 0) {
        throw new Error(
            'Target-bound share-selection profile requires a target-basis hash.',
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

    return {
        profileId: profile.profileId,
        certificateHash: profile.certificateHash,
        targetDecryptionProfileId: profile.targetDecryptionProfileId,
        targetBasisHash: profile.targetBasisHash,
        decryptionShareQuorum: profile.decryptionShareQuorum,
        minimumSharesForInterpolation: profile.minimumSharesForInterpolation,
        minimumArrivalsForRobustDecode: profile.minimumArrivalsForRobustDecode,
        invalidShareFilteringMode: profile.invalidShareFilteringMode,
    };
};

const deriveRosterProfile = (
    rosterSize: number,
    input: ThresholdProfileInput,
): {
    readonly dynamicRosterProfileCertificateHash: ProtocolHash | null;
    readonly rosterProfileKind: RosterProfileKind;
    readonly warnings: readonly ThresholdWarning[];
} => {
    if (!Number.isInteger(rosterSize)) {
        throw new RangeError('Roster size must be an integer.');
    }
    if (rosterSize < minimumSupportedRosterSize) {
        throw new RangeError('Roster size must be at least 3.');
    }
    if (rosterSize > maximumSupportedRosterSize) {
        throw new RangeError('Roster size must be at most 20.');
    }
    const dynamicRosterProfileCertificateHash =
        normalizeDynamicRosterProfileCertificateHash(
            input.dynamicRosterProfileCertificateHash,
        );

    if (rosterSize < minimumDynamicRosterSize) {
        if (input.casualMicroRosterAcknowledged !== true) {
            throw new Error(
                'Casual micro-roster profiles require explicit acknowledgement.',
            );
        }

        return {
            dynamicRosterProfileCertificateHash: null,
            rosterProfileKind: 'CasualMicroRoster',
            warnings: ['CasualMicroRoster'],
        };
    }
    // Size 10 is the pre-certified first profile and is the only dynamic-range
    // size that runs without a separate dynamic-roster parameter certificate.
    if (rosterSize === firstProfileRosterSize) {
        return {
            dynamicRosterProfileCertificateHash: null,
            rosterProfileKind: 'FirstProfileRoster',
            warnings: [],
        };
    }
    if (dynamicRosterProfileCertificateHash !== null) {
        return {
            dynamicRosterProfileCertificateHash,
            rosterProfileKind: 'SupportedDynamicRosterRange',
            warnings: [],
        };
    }

    return {
        dynamicRosterProfileCertificateHash: null,
        rosterProfileKind: 'UncertifiedDynamicRoster',
        warnings: ['DynamicRosterProfileCertificateRequired'],
    };
};

export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => {
    const { rosterSize } = input;
    const rosterProfile = deriveRosterProfile(rosterSize, input);
    const backendCorruptionModel = normalizeBackendCorruptionModel(
        rosterSize,
        input.heBackendCorruptionModel,
    );
    // floor(n/3): tolerate up to a third corrupt (BFT-style 1/3 corruption
    // bound).
    const structuralCorruptionBound = Math.floor(rosterSize / 3);
    // Structural one-third model uses floor(n/3): the default HE-backend
    // corruption tolerance matches the structural bound, so the privacy bound
    // is c_priv = floor(n/3) and the decryption threshold is q_dec =
    // floor(n/3) + 1 (the stronger-privacy, non-degenerate convention; at n=3
    // this is a real 2-of-3, never 1-of-3). This is sound under the
    // secure-with-abort model, which does not require a strict n > 3f margin.
    const backendCorruptionBound =
        backendCorruptionModel.kind === 'StructuralOneThird'
            ? Math.floor(rosterSize / 3)
            : backendCorruptionModel.backendCorruptionBound;
    const privacyCorruptionBound = Math.min(
        structuralCorruptionBound,
        backendCorruptionBound,
    );
    const decryptionCorruptionBound = privacyCorruptionBound;
    // floor(n/5): active (Byzantine-fault) tolerance, the 1/5 active-fault bound.
    const activeFaultBound = Math.floor(rosterSize / 5);
    // +1 over the privacy corruption bound = one more share than an adversary
    // can hold is needed before ballot release or target decryption proceeds.
    const ballotReleaseFloor = privacyCorruptionBound + 1;
    const decryptionThreshold = decryptionCorruptionBound + 1;
    const targetBoundShareSelectionProfile =
        normalizeTargetBoundShareSelectionProfile(
            rosterSize,
            decryptionThreshold,
            input.targetBoundShareSelectionProfile,
        );
    // Full-roster ballot release for the secure-with-abort phase: q_ballot_release
    // = n. A flexible sub-unanimous turnout quorum (e.g. ceil(2n/3)) is a
    // deferred future-profile concept and is intentionally not used here.
    const releaseQuorum = rosterSize;
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
        dynamicRosterProfileCertificateHash:
            rosterProfile.dynamicRosterProfileCertificateHash,
        structuralCorruptionBound,
        backendCorruptionBound,
        privacyCorruptionBound,
        decryptionCorruptionBound,
        activeFaultBound,
        ballotReleaseFloor,
        decryptionThreshold,
        releaseQuorum,
        decryptionShareQuorum,
        targetBoundShareSelectionProfile,
        maximumRaceShares,
        setupCompletionQuorum,
        backendCorruptionModel,
        warnings,
    };
};

export const deriveThresholdProfileHash = (input: {
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly thresholdProfile: ThresholdProfile;
    readonly smallRosterPolicy: PollSpec['smallRosterPolicy'];
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
}): ProtocolHash =>
    deriveProtocolHash('ThresholdProfileHash', {
        activeFaultBound: input.thresholdProfile.activeFaultBound,
        ballotReleaseFloor: input.thresholdProfile.ballotReleaseFloor,
        backendCorruptionBound: input.thresholdProfile.backendCorruptionBound,
        backendCorruptionModel: input.thresholdProfile.backendCorruptionModel,
        decryptionCorruptionBound:
            input.thresholdProfile.decryptionCorruptionBound,
        decryptionShareQuorum: input.thresholdProfile.decryptionShareQuorum,
        decryptionThreshold: input.thresholdProfile.decryptionThreshold,
        dynamicRosterProfileCertificateHash:
            input.thresholdProfile.dynamicRosterProfileCertificateHash,
        maxRosterSize: input.maxRosterSize,
        maximumRaceShares: input.thresholdProfile.maximumRaceShares,
        minRosterSize: input.minRosterSize,
        pollSpecHash: input.pollSpecHash,
        privacyCorruptionBound: input.thresholdProfile.privacyCorruptionBound,
        releaseQuorum: input.thresholdProfile.releaseQuorum,
        rosterHash: input.rosterHash,
        rosterProfileKind: input.thresholdProfile.rosterProfileKind,
        rosterSize: input.thresholdProfile.rosterSize,
        setupCompletionQuorum: input.thresholdProfile.setupCompletionQuorum,
        smallRosterPolicy: input.smallRosterPolicy,
        structuralCorruptionBound:
            input.thresholdProfile.structuralCorruptionBound,
        targetBoundShareSelectionProfile:
            input.thresholdProfile.targetBoundShareSelectionProfile,
        warnings: input.thresholdProfile.warnings,
    });

export const deriveFrozenRosterProfile = (input: {
    readonly pollSpec: PollSpec;
    readonly rosterHash: ProtocolHash;
    readonly rosterSize: number;
    readonly heBackendCorruptionModel?: HeBackendCorruptionModel;
    readonly targetBoundShareSelectionProfile?: TargetBoundShareSelectionProfile;
    readonly dynamicRosterProfileCertificateHash?: ProtocolHash;
}): FrozenRosterProfile => {
    const { pollSpec, rosterSize } = input;
    const dynamicRosterProfileCertificateHash =
        normalizeDynamicRosterProfileCertificateHash(
            input.dynamicRosterProfileCertificateHash,
        );

    if (
        rosterSize < pollSpec.minRosterSize ||
        rosterSize > pollSpec.maxRosterSize
    ) {
        throw new RangeError(
            'Frozen roster size must be inside the poll roster bounds.',
        );
    }
    if (
        rosterSize < minimumDynamicRosterSize &&
        pollSpec.smallRosterPolicy === 'ForbidMicroRoster'
    ) {
        throw new Error(
            'Poll policy forbids freezing a casual micro-roster profile.',
        );
    }
    if (
        rosterSize >= minimumDynamicRosterSize &&
        rosterSize !== firstProfileRosterSize &&
        dynamicRosterProfileCertificateHash === null
    ) {
        throw new Error(
            'Dynamic roster profiles require parameter certificate coverage for the frozen roster size.',
        );
    }

    const thresholdProfile = deriveThresholdProfile({
        rosterSize,
        casualMicroRosterAcknowledged: rosterSize < minimumDynamicRosterSize,
        dynamicRosterProfileCertificateHash:
            dynamicRosterProfileCertificateHash ?? undefined,
        heBackendCorruptionModel: input.heBackendCorruptionModel,
        targetBoundShareSelectionProfile:
            input.targetBoundShareSelectionProfile,
    });
    const pollSpecHash = derivePollSpecHash(pollSpec);
    const thresholdProfileHash = deriveThresholdProfileHash({
        maxRosterSize: pollSpec.maxRosterSize,
        minRosterSize: pollSpec.minRosterSize,
        pollSpecHash,
        rosterHash: input.rosterHash,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        thresholdProfile,
    });

    return {
        objectType: 'FrozenRosterProfile',
        objectVersion: 1,
        thresholdProfileHash,
        pollSpecHash,
        rosterHash: input.rosterHash,
        rosterSize,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        minRosterSize: pollSpec.minRosterSize,
        maxRosterSize: pollSpec.maxRosterSize,
        dynamicRosterProfileCertificateHash:
            thresholdProfile.dynamicRosterProfileCertificateHash,
        thresholdProfile,
    };
};
