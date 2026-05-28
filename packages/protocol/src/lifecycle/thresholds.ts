import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    FrozenRosterProfile,
    PollSpec,
    ProtocolHash,
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

import { derivePollSpecHash } from './poll-spec.js';
import {
    targetBoundShareSelectionProfileId,
    cpadProfileId,
    mandatoryBenchmarkRosterSize,
    maximumSupportedRosterSize,
    minimumDynamicRosterSize,
    minimumSupportedRosterSize,
    strictLessThanOneThirdModel,
} from './profiles.js';

const protocolHashPattern = /^[0-9a-f]{128}$/u;

const normalizeDynamicRosterProfileCertificateHash = (
    hash: ProtocolHash | undefined,
): ProtocolHash | null =>
    hash !== undefined && protocolHashPattern.test(hash) ? hash : null;

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
    if (profile.certificateHash.trim().length === 0) {
        throw new Error(
            'Target-bound share-selection profile requires a certificate hash.',
        );
    }
    if (profile.cpadProfileId !== cpadProfileId) {
        throw new Error(
            'Target-bound share-selection profile uses an unsupported CPAD profile ID.',
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
    if (
        !supportedDecryptionShareSelectionRules.has(profile.selectedShareRule)
    ) {
        throw new Error(
            'Target-bound share-selection profile uses an unsupported selected-share rule.',
        );
    }

    return {
        profileId: profile.profileId,
        certificateHash: profile.certificateHash,
        cpadProfileId: profile.cpadProfileId,
        targetBasisHash: profile.targetBasisHash,
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
        throw new RangeError('Roster size must be at most 50.');
    }
    const dynamicRosterProfileCertificateHash =
        normalizeDynamicRosterProfileCertificateHash(
            input.dynamicRosterProfileCertificateHash,
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
            dynamicRosterProfileCertificateHash: null,
            rosterProfileKind: 'CasualMicroRoster',
            warnings: ['CasualMicroRoster'],
        };
    }
    if (rosterSize === mandatoryBenchmarkRosterSize) {
        return {
            claimBoundary: 'MandatoryBenchmark',
            claimBearing: true,
            dynamicRosterProfileCertificateHash: null,
            rosterProfileKind: 'MandatoryBenchmarkRoster',
            warnings: [],
        };
    }
    if (dynamicRosterProfileCertificateHash !== null) {
        return {
            claimBoundary: 'DynamicRosterCertificate',
            claimBearing: true,
            dynamicRosterProfileCertificateHash,
            rosterProfileKind: 'SupportedDynamicRosterRange',
            warnings: [],
        };
    }

    return {
        claimBoundary: 'DynamicRosterCertificateMissing',
        claimBearing: false,
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
        dynamicRosterProfileCertificateHash:
            rosterProfile.dynamicRosterProfileCertificateHash,
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

export const deriveThresholdProfileHash = (input: {
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly thresholdProfile: ThresholdProfile;
    readonly rosterPolicy: PollSpec['rosterPolicy'];
    readonly thresholdProfileFamily: PollSpec['thresholdProfileFamily'];
    readonly smallRosterPolicy: PollSpec['smallRosterPolicy'];
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
}): ProtocolHash =>
    deriveProtocolHash('ThresholdProfileHash', {
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
        dynamicRosterProfileCertificateHash:
            input.thresholdProfile.dynamicRosterProfileCertificateHash,
        maxRosterSize: input.maxRosterSize,
        maximumRaceShares: input.thresholdProfile.maximumRaceShares,
        minRosterSize: input.minRosterSize,
        pollSpecHash: input.pollSpecHash,
        privacyCorruptionBound: input.thresholdProfile.privacyCorruptionBound,
        pvssThreshold: input.thresholdProfile.pvssThreshold,
        releaseQuorum: input.thresholdProfile.releaseQuorum,
        rosterHash: input.rosterHash,
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
        rosterSize !== mandatoryBenchmarkRosterSize &&
        dynamicRosterProfileCertificateHash === null
    ) {
        throw new Error(
            'Dynamic claim-bearing roster profiles require parameter certificate coverage for the frozen roster size.',
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
        rosterPolicy: pollSpec.rosterPolicy,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        thresholdProfile,
        thresholdProfileFamily: pollSpec.thresholdProfileFamily,
    });

    return {
        objectType: 'FrozenRosterProfile',
        objectVersion: 1,
        thresholdProfileHash,
        pollSpecHash,
        rosterHash: input.rosterHash,
        rosterSize,
        rosterPolicy: pollSpec.rosterPolicy,
        thresholdProfileFamily: pollSpec.thresholdProfileFamily,
        smallRosterPolicy: pollSpec.smallRosterPolicy,
        minRosterSize: pollSpec.minRosterSize,
        maxRosterSize: pollSpec.maxRosterSize,
        dynamicRosterProfileCertificateHash:
            thresholdProfile.dynamicRosterProfileCertificateHash,
        thresholdProfile,
    };
};
