import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type {
    FrozenRosterParameters,
    PollSpec,
    ProtocolHash,
    TargetBoundShareSelectionParameters,
    DecryptionShareFilteringMode,
    HeBackendCorruptionModel,
    RosterParametersKind,
    ThresholdParameters,
    ThresholdParametersInput,
    ThresholdWarning,
} from '@sealed-lattice/types';

import {
    isNonNegativeInteger,
    isProtocolHashString,
} from '../common/verification-helpers.js';

import { derivePollSpecHash } from './poll-spec.js';
import {
    foundationRosterSize,
    maximumSupportedRosterSize,
    minimumDynamicRosterSize,
    minimumSupportedRosterSize,
    structuralOneThirdModel,
} from './roster-policy.js';

const normalizeDynamicRosterParametersCertificateHash = (
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
        throw new Error('Certified HE backend parameters require a hash.');
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

const normalizeTargetBoundShareSelectionParameters = (
    rosterSize: number,
    decryptionThreshold: number,
    parameters: TargetBoundShareSelectionParameters | undefined,
): TargetBoundShareSelectionParameters | null => {
    if (parameters === undefined) {
        return null;
    }

    if (parameters.certificateHash.trim().length === 0) {
        throw new Error(
            'Target-bound share-selection parameters requires a certificate hash.',
        );
    }
    if (parameters.targetBasisHash.trim().length === 0) {
        throw new Error(
            'Target-bound share-selection parameters requires a target-basis hash.',
        );
    }
    if (!isNonNegativeInteger(parameters.decryptionShareQuorum)) {
        throw new RangeError(
            'Target-bound decryption share quorum must be a non-negative integer.',
        );
    }
    if (parameters.decryptionShareQuorum < decryptionThreshold) {
        throw new RangeError(
            'Target-bound decryption share quorum must be at least the decryption threshold.',
        );
    }
    if (parameters.decryptionShareQuorum > rosterSize) {
        throw new RangeError(
            'Target-bound decryption share quorum must not exceed rosterSize.',
        );
    }
    if (!isNonNegativeInteger(parameters.minimumSharesForInterpolation)) {
        throw new RangeError(
            'Target-bound interpolation share count must be a non-negative integer.',
        );
    }
    if (parameters.minimumSharesForInterpolation < decryptionThreshold) {
        throw new RangeError(
            'Target-bound interpolation share count must be at least the decryption threshold.',
        );
    }
    if (
        parameters.minimumSharesForInterpolation >
        parameters.decryptionShareQuorum
    ) {
        throw new RangeError(
            'Target-bound interpolation share count must not exceed the decryption share quorum.',
        );
    }
    if (!isNonNegativeInteger(parameters.minimumArrivalsForRobustDecode)) {
        throw new RangeError(
            'Target-bound robust-decode arrival count must be a non-negative integer.',
        );
    }
    if (
        parameters.minimumArrivalsForRobustDecode <
        parameters.decryptionShareQuorum
    ) {
        throw new RangeError(
            'Target-bound robust-decode arrival count must be at least the decryption share quorum.',
        );
    }
    if (parameters.minimumArrivalsForRobustDecode > rosterSize) {
        throw new RangeError(
            'Target-bound robust-decode arrival count must not exceed rosterSize.',
        );
    }
    if (
        !supportedDecryptionShareFilteringModes.has(
            parameters.invalidShareFilteringMode,
        )
    ) {
        throw new Error(
            'Target-bound share-selection parameters uses an unsupported invalid-share filtering mode.',
        );
    }

    return {
        certificateHash: parameters.certificateHash,
        targetBasisHash: parameters.targetBasisHash,
        decryptionShareQuorum: parameters.decryptionShareQuorum,
        minimumSharesForInterpolation: parameters.minimumSharesForInterpolation,
        minimumArrivalsForRobustDecode:
            parameters.minimumArrivalsForRobustDecode,
        invalidShareFilteringMode: parameters.invalidShareFilteringMode,
    };
};

const deriveRosterParameters = (
    rosterSize: number,
    input: ThresholdParametersInput,
): {
    readonly dynamicRosterParametersCertificateHash: ProtocolHash | null;
    readonly rosterParametersKind: RosterParametersKind;
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
    const dynamicRosterParametersCertificateHash =
        normalizeDynamicRosterParametersCertificateHash(
            input.dynamicRosterParametersCertificateHash,
        );

    if (rosterSize < minimumDynamicRosterSize) {
        if (input.isCasualMicroRosterAcknowledged !== true) {
            throw new Error(
                'Casual micro-roster parameter sets require explicit acknowledgement.',
            );
        }

        return {
            dynamicRosterParametersCertificateHash: null,
            rosterParametersKind: 'CasualMicroRoster',
            warnings: ['CasualMicroRoster'],
        };
    }
    // The fixed foundation profile is the only dynamic-range size that runs
    // without a separate dynamic-roster parameter certificate.
    if (rosterSize === foundationRosterSize) {
        return {
            dynamicRosterParametersCertificateHash: null,
            rosterParametersKind: 'FoundationRoster',
            warnings: [],
        };
    }
    if (dynamicRosterParametersCertificateHash !== null) {
        return {
            dynamicRosterParametersCertificateHash,
            rosterParametersKind: 'SupportedDynamicRosterRange',
            warnings: [],
        };
    }

    return {
        dynamicRosterParametersCertificateHash: null,
        rosterParametersKind: 'UncertifiedDynamicRoster',
        warnings: ['DynamicRosterParametersCertificateRequired'],
    };
};

export const deriveThresholdParameters = (
    input: ThresholdParametersInput,
): ThresholdParameters => {
    const { rosterSize } = input;
    const rosterParameters = deriveRosterParameters(rosterSize, input);
    const backendCorruptionModel = normalizeBackendCorruptionModel(
        rosterSize,
        input.heBackendCorruptionModel,
    );
    // floor(n/3): current structural one-third helper convention.
    const structuralCorruptionBound = Math.floor(rosterSize / 3);
    // The default HE-backend tolerance matches that helper convention, so
    // q_dec = floor(n/3) + 1 (at n = 3 this is 2-of-3, never 1-of-3). This is
    // parameter derivation only: parameter sets outside the first target
    // parameter set need their own certificate if a stricter backend
    // corruption theorem is used.
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
    const targetBoundShareSelectionParameters =
        normalizeTargetBoundShareSelectionParameters(
            rosterSize,
            decryptionThreshold,
            input.targetBoundShareSelectionParameters,
        );
    // Full-roster ballot release for the secure-with-abort phase: q_ballot_release
    // = n. A flexible sub-unanimous turnout quorum (e.g. ceil(2n/3)) is a
    // deferred future-parameters concept and is intentionally not used here.
    const releaseQuorum = rosterSize;
    const decryptionShareQuorum =
        targetBoundShareSelectionParameters?.decryptionShareQuorum ?? null;
    const maximumRaceShares = rosterSize;
    const setupCompletionQuorum = rosterSize;
    const warnings = [...rosterParameters.warnings];

    if (
        backendCorruptionModel.kind === 'CertifiedCustom' &&
        backendCorruptionModel.backendCorruptionBound >
            structuralCorruptionBound
    ) {
        warnings.push('BackendCorruptionBoundTooHigh');
    }
    if (targetBoundShareSelectionParameters === null) {
        warnings.push('ShareSelectionParametersRequired');
    }

    return {
        rosterSize,
        rosterParametersKind: rosterParameters.rosterParametersKind,
        dynamicRosterParametersCertificateHash:
            rosterParameters.dynamicRosterParametersCertificateHash,
        structuralCorruptionBound,
        backendCorruptionBound,
        privacyCorruptionBound,
        decryptionCorruptionBound,
        activeFaultBound,
        ballotReleaseFloor,
        decryptionThreshold,
        releaseQuorum,
        decryptionShareQuorum,
        targetBoundShareSelectionParameters,
        maximumRaceShares,
        setupCompletionQuorum,
        backendCorruptionModel,
        warnings,
    };
};

export const deriveThresholdParametersHash = (input: {
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly thresholdParameters: ThresholdParameters;
    readonly smallRosterPolicy: PollSpec['smallRosterPolicy'];
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
}): ProtocolHash =>
    // Threshold-parameter set hashed under the shared canonical-object domain,
    // separated by its objectType discriminator.
    deriveCanonicalObjectHash({
        objectType: 'ThresholdParameters',
        activeFaultBound: input.thresholdParameters.activeFaultBound,
        ballotReleaseFloor: input.thresholdParameters.ballotReleaseFloor,
        backendCorruptionBound:
            input.thresholdParameters.backendCorruptionBound,
        backendCorruptionModel:
            input.thresholdParameters.backendCorruptionModel,
        decryptionCorruptionBound:
            input.thresholdParameters.decryptionCorruptionBound,
        decryptionShareQuorum: input.thresholdParameters.decryptionShareQuorum,
        decryptionThreshold: input.thresholdParameters.decryptionThreshold,
        dynamicRosterParametersCertificateHash:
            input.thresholdParameters.dynamicRosterParametersCertificateHash,
        maxRosterSize: input.maxRosterSize,
        maximumRaceShares: input.thresholdParameters.maximumRaceShares,
        minRosterSize: input.minRosterSize,
        pollSpecHash: input.pollSpecHash,
        privacyCorruptionBound:
            input.thresholdParameters.privacyCorruptionBound,
        releaseQuorum: input.thresholdParameters.releaseQuorum,
        rosterHash: input.rosterHash,
        rosterParametersKind: input.thresholdParameters.rosterParametersKind,
        rosterSize: input.thresholdParameters.rosterSize,
        setupCompletionQuorum: input.thresholdParameters.setupCompletionQuorum,
        smallRosterPolicy: input.smallRosterPolicy,
        structuralCorruptionBound:
            input.thresholdParameters.structuralCorruptionBound,
        targetBoundShareSelectionParameters:
            input.thresholdParameters.targetBoundShareSelectionParameters,
        warnings: input.thresholdParameters.warnings,
    });

export const deriveFrozenRosterParameters = (input: {
    readonly pollSpec: PollSpec;
    readonly rosterHash: ProtocolHash;
    readonly rosterSize: number;
    readonly heBackendCorruptionModel?: HeBackendCorruptionModel;
    readonly targetBoundShareSelectionParameters?: TargetBoundShareSelectionParameters;
    readonly dynamicRosterParametersCertificateHash?: ProtocolHash;
}): FrozenRosterParameters => {
    const { pollSpec, rosterSize } = input;
    const dynamicRosterParametersCertificateHash =
        normalizeDynamicRosterParametersCertificateHash(
            input.dynamicRosterParametersCertificateHash,
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
            'Poll policy forbids freezing a casual micro-roster parameters.',
        );
    }
    if (
        rosterSize >= minimumDynamicRosterSize &&
        rosterSize !== foundationRosterSize &&
        dynamicRosterParametersCertificateHash === null
    ) {
        throw new Error(
            'Dynamic roster parameter sets require parameter certificate coverage for the frozen roster size.',
        );
    }

    const thresholdParameters = deriveThresholdParameters({
        rosterSize,
        isCasualMicroRosterAcknowledged: rosterSize < minimumDynamicRosterSize,
        dynamicRosterParametersCertificateHash:
            dynamicRosterParametersCertificateHash ?? undefined,
        heBackendCorruptionModel: input.heBackendCorruptionModel,
        targetBoundShareSelectionParameters:
            input.targetBoundShareSelectionParameters,
    });
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
        dynamicRosterParametersCertificateHash:
            thresholdParameters.dynamicRosterParametersCertificateHash,
        thresholdParameters,
    };
};
