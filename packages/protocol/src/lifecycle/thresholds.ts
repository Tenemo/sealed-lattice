import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    FrozenRosterProfile,
    PollSpec,
    ProtocolDigest,
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

import { derivePollSpecDigest } from './poll-spec.js';
import {
    targetBoundShareSelectionProfileId,
    cpadProfileId,
    mandatoryBenchmarkRosterSize,
    maximumSupportedRosterSize,
    minimumDynamicRosterSize,
    minimumSupportedRosterSize,
    strictLessThanOneThirdModel,
} from './profiles.js';

const protocolDigestPattern = /^[0-9a-f]{128}$/u;

const normalizeDynamicRosterProfileCertificateDigest = (
    digest: ProtocolDigest | undefined,
): ProtocolDigest | null =>
    digest !== undefined && protocolDigestPattern.test(digest) ? digest : null;

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
    input: ThresholdProfileInput,
): {
    readonly claimBoundary: ThresholdProfile['claimBoundary'];
    readonly claimBearing: boolean;
    readonly dynamicRosterProfileCertificateDigest: ProtocolDigest | null;
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
        throw new RangeError('Roster size must be at most 50.');
    }
    const dynamicRosterProfileCertificateDigest =
        normalizeDynamicRosterProfileCertificateDigest(
            input.dynamicRosterProfileCertificateDigest,
        );

    if (rosterSize < minimumDynamicRosterSize) {
        if (
            input.casualMicroRosterAcknowledged !== true &&
            input.unsafeSmallRosterAcknowledged !== true &&
            input.unsafeMicroRosterAcknowledged !== true
        ) {
            throw new Error(
                'Casual micro-roster profiles require explicit acknowledgement.',
            );
        }

        return {
            claimBoundary: 'CasualMicroRoster',
            claimBearing: false,
            dynamicRosterProfileCertificateDigest: null,
            rosterProfileKind: 'CasualMicroRoster',
            warnings: ['CasualMicroRoster'],
        };
    }
    if (rosterSize === mandatoryBenchmarkRosterSize) {
        return {
            claimBoundary: 'MandatoryBenchmark',
            claimBearing: true,
            dynamicRosterProfileCertificateDigest: null,
            rosterProfileKind: 'MandatoryBenchmarkRoster',
            warnings: [],
        };
    }
    if (dynamicRosterProfileCertificateDigest !== null) {
        return {
            claimBoundary: 'DynamicRosterCertificate',
            claimBearing: true,
            dynamicRosterProfileCertificateDigest,
            rosterProfileKind: 'SupportedDynamicRosterRange',
            warnings: [],
        };
    }

    return {
        claimBoundary: 'DynamicRosterCertificateMissing',
        claimBearing: false,
        dynamicRosterProfileCertificateDigest: null,
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
        claimBoundary: rosterProfile.claimBoundary,
        claimBearing: rosterProfile.claimBearing,
        dynamicRosterProfileCertificateDigest:
            rosterProfile.dynamicRosterProfileCertificateDigest,
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

export const deriveThresholdProfileDigest = (input: {
    readonly pollSpecDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly thresholdProfile: ThresholdProfile;
    readonly rosterPolicy: PollSpec['rosterPolicy'];
    readonly thresholdProfileFamily: PollSpec['thresholdProfileFamily'];
    readonly smallRosterPolicy: PollSpec['smallRosterPolicy'];
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
}): ProtocolDigest =>
    deriveProtocolDigest('ThresholdProfileDigest', {
        activeFaultBound: input.thresholdProfile.activeFaultBound,
        aggregateContributionQuorum:
            input.thresholdProfile.aggregateContributionQuorum,
        backendCorruptionBound: input.thresholdProfile.backendCorruptionBound,
        backendCorruptionModel: input.thresholdProfile.backendCorruptionModel,
        claimBoundary: input.thresholdProfile.claimBoundary,
        claimBearing: input.thresholdProfile.claimBearing,
        decryptionCorruptionBound:
            input.thresholdProfile.decryptionCorruptionBound,
        decryptionShareQuorum: input.thresholdProfile.decryptionShareQuorum,
        decryptionThreshold: input.thresholdProfile.decryptionThreshold,
        dynamicRosterProfileCertificateDigest:
            input.thresholdProfile.dynamicRosterProfileCertificateDigest,
        maxRosterSize: input.maxRosterSize,
        maximumRaceShares: input.thresholdProfile.maximumRaceShares,
        minRosterSize: input.minRosterSize,
        pollSpecDigest: input.pollSpecDigest,
        privacyCorruptionBound: input.thresholdProfile.privacyCorruptionBound,
        pvssThreshold: input.thresholdProfile.pvssThreshold,
        releaseQuorum: input.thresholdProfile.releaseQuorum,
        rosterDigest: input.rosterDigest,
        rosterPolicy: input.rosterPolicy,
        rosterProfileKind: input.thresholdProfile.rosterProfileKind,
        rosterSize: input.thresholdProfile.rosterSize,
        setupCompletionQuorum: input.thresholdProfile.setupCompletionQuorum,
        smallRosterPolicy: input.smallRosterPolicy,
        structuralCorruptionBound:
            input.thresholdProfile.structuralCorruptionBound,
        targetBoundShareSelectionProfile:
            input.thresholdProfile.targetBoundShareSelectionProfile,
        thresholdProfileFamily: input.thresholdProfileFamily,
        warnings: input.thresholdProfile.warnings,
    });

export const deriveFrozenRosterProfile = (input: {
    readonly pollSpec: PollSpec;
    readonly rosterDigest: ProtocolDigest;
    readonly rosterSize: number;
    readonly heBackendCorruptionModel?: HeBackendCorruptionModel;
    readonly targetBoundShareSelectionProfile?: TargetBoundShareSelectionProfile;
    readonly dynamicRosterProfileCertificateDigest?: ProtocolDigest;
}): FrozenRosterProfile => {
    const { pollSpec, rosterSize } = input;
    const dynamicRosterProfileCertificateDigest =
        normalizeDynamicRosterProfileCertificateDigest(
            input.dynamicRosterProfileCertificateDigest,
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
        rosterSize !== mandatoryBenchmarkRosterSize &&
        dynamicRosterProfileCertificateDigest === null
    ) {
        throw new Error(
            'Dynamic claim-bearing roster profiles require parameter certificate coverage for the frozen roster size.',
        );
    }

    const thresholdProfile = deriveThresholdProfile({
        rosterSize,
        casualMicroRosterAcknowledged: rosterSize < minimumDynamicRosterSize,
        dynamicRosterProfileCertificateDigest:
            dynamicRosterProfileCertificateDigest ?? undefined,
        heBackendCorruptionModel: input.heBackendCorruptionModel,
        targetBoundShareSelectionProfile:
            input.targetBoundShareSelectionProfile,
    });
    const pollSpecDigest = derivePollSpecDigest(pollSpec);
    const thresholdProfileDigest = deriveThresholdProfileDigest({
        maxRosterSize: pollSpec.maxRosterSize,
        minRosterSize: pollSpec.minRosterSize,
        pollSpecDigest,
        rosterDigest: input.rosterDigest,
        rosterPolicy: pollSpec.rosterPolicy,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        thresholdProfile,
        thresholdProfileFamily: pollSpec.thresholdProfileFamily,
    });

    return {
        objectType: 'FrozenRosterProfile',
        objectVersion: 1,
        thresholdProfileDigest,
        pollSpecDigest,
        rosterDigest: input.rosterDigest,
        rosterSize,
        rosterPolicy: pollSpec.rosterPolicy,
        thresholdProfileFamily: pollSpec.thresholdProfileFamily,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        minRosterSize: pollSpec.minRosterSize,
        maxRosterSize: pollSpec.maxRosterSize,
        dynamicRosterProfileCertificateDigest:
            thresholdProfile.dynamicRosterProfileCertificateDigest,
        thresholdProfile,
    };
};
