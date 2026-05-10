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
    n: number,
    model: HeBackendCorruptionModel | undefined,
): HeBackendCorruptionModel => {
    if (model === undefined) {
        return strictLessThanOneThirdModel;
    }

    if (model.kind === 'StrictLessThanOneThird') {
        return strictLessThanOneThirdModel;
    }

    if (!isNonNegativeInteger(model.cHeBackend)) {
        throw new RangeError(
            'Certified HE backend corruption bound must be a non-negative integer.',
        );
    }
    if (model.cHeBackend >= n) {
        throw new RangeError(
            'Certified HE backend corruption bound must be less than n.',
        );
    }
    if (model.certificateDigest.length === 0) {
        throw new Error('Certified HE backend profile requires a digest.');
    }

    return {
        kind: 'CertifiedCustom',
        cHeBackend: model.cHeBackend,
        certificateDigest: model.certificateDigest,
    };
};

const deriveRosterProfile = (
    n: number,
    unsafeMicroRosterAcknowledged: boolean | undefined,
): {
    readonly claimBearing: boolean;
    readonly rosterProfileKind: RosterProfileKind;
    readonly warnings: readonly ThresholdWarning[];
} => {
    if (!Number.isInteger(n)) {
        throw new RangeError('Roster size must be an integer.');
    }
    if (n < minimumUnsafeRosterSize) {
        throw new RangeError('Roster size must be at least 3.');
    }
    if (n > maximumCertificateGatedRosterSize) {
        throw new RangeError('Roster size must be at most 50.');
    }
    if (n < mandatoryClaimRosterSize) {
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
    if (n === mandatoryClaimRosterSize) {
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
    const { n } = input;
    const rosterProfile = deriveRosterProfile(
        n,
        input.unsafeMicroRosterAcknowledged,
    );
    const backendCorruptionModel = normalizeBackendCorruptionModel(
        n,
        input.heBackendCorruptionModel,
    );
    const cStruct = Math.floor(n / 3);
    const cHeBackend =
        backendCorruptionModel.kind === 'StrictLessThanOneThird'
            ? Math.floor((n - 1) / 3)
            : backendCorruptionModel.cHeBackend;
    const cPriv = Math.min(cStruct, cHeBackend);
    const cDec = cPriv;
    const fAct = Math.floor(n / 5);
    const tPvss = cPriv + 1;
    const tDec = cDec + 1;
    const qRelease = Math.min(n, Math.max(10, Math.ceil((2 * n) / 3)));
    const qAgg = tPvss;
    const qDec = tDec;
    const qEval = fAct + 1;
    const raceShareMax = n;
    const qSetupComplete = n;
    const warnings = [...rosterProfile.warnings];

    if (
        backendCorruptionModel.kind === 'CertifiedCustom' &&
        backendCorruptionModel.cHeBackend > cStruct
    ) {
        warnings.push('BackendCorruptionBoundTooHigh');
    }

    return {
        n,
        rosterProfileKind: rosterProfile.rosterProfileKind,
        claimBearing: rosterProfile.claimBearing,
        cStruct,
        cHeBackend,
        cPriv,
        cDec,
        fAct,
        tPvss,
        tDec,
        qRelease,
        qAgg,
        qDec,
        qEval,
        raceShareMax,
        qSetupComplete,
        backendCorruptionModel,
        warnings,
    };
};
