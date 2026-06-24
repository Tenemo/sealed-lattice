import { setupProfileId } from './constants.js';
import {
    assertDerivedHashMatches,
    assertObjectRecord,
    hashField,
    numberArrayField,
    numberField,
    objectField,
    positiveNumberField,
    stringField,
} from './field-helpers.js';
import type {
    BgvRnsProfileForCertificates,
    CollectiveBgvSetupProfileForCertificates,
    JsonRecord,
} from './types.js';

export const setupProfileForCertificates = (
    setupProfileValue: CollectiveBgvSetupProfileForCertificates | JsonRecord,
): CollectiveBgvSetupProfileForCertificates => {
    const setupProfileRecord = assertObjectRecord(
        setupProfileValue,
        'setupProfile',
    );
    if (setupProfileRecord.setupProfileId !== setupProfileId) {
        throw new Error(
            `setupProfile.setupProfileId must be ${setupProfileId}.`,
        );
    }
    const setupProfile =
        setupProfileRecord as CollectiveBgvSetupProfileForCertificates;
    positiveNumberField(setupProfile, 'participantCount', 'setupProfile');
    positiveNumberField(setupProfile, 'qDec', 'setupProfile');
    hashField(setupProfile, 'setupProfileHash', 'setupProfile');
    const qShare = objectField(setupProfile, 'qShare', 'setupProfile');
    const qSharePrimes = numberArrayField(
        qShare,
        'primes',
        'setupProfile.qShare',
    );
    if (qSharePrimes.length === 0) {
        throw new Error('setupProfile.qShare.primes must not be empty.');
    }
    const qShareHash = hashField(setupProfile, 'qShareHash', 'setupProfile');
    assertDerivedHashMatches(
        'QSharePrimeListHash',
        qShare,
        qShareHash,
        'setupProfile.qShareHash',
    );
    hashField(
        setupProfile,
        'carryAwareVssShareRelationProfileHash',
        'setupProfile',
    );
    const commitmentProfile = objectField(
        setupProfile,
        'commitmentProfile',
        'setupProfile',
    );
    objectField(
        commitmentProfile,
        'messageEncoding',
        'setupProfile.commitmentProfile',
    );
    const commitmentProfileHash = hashField(
        setupProfile,
        'commitmentProfileHash',
        'setupProfile',
    );
    assertDerivedHashMatches(
        'SetupCommitmentProfileHash',
        commitmentProfile,
        commitmentProfileHash,
        'setupProfile.commitmentProfileHash',
    );
    const setupProofProfile = objectField(
        setupProfile,
        'setupProofProfile',
        'setupProfile',
    );
    const setupProofProfileHash = hashField(
        setupProfile,
        'setupProofProfileHash',
        'setupProfile',
    );
    assertDerivedHashMatches(
        'SetupProofProfileHash',
        setupProofProfile,
        setupProofProfileHash,
        'setupProfile.setupProofProfileHash',
    );
    const setupTransportProfile = objectField(
        setupProfile,
        'setupTransportProfile',
        'setupProfile',
    );
    const setupTransportProfileHash = hashField(
        setupProfile,
        'setupTransportProfileHash',
        'setupProfile',
    );
    assertDerivedHashMatches(
        'SetupTransportProfileHash',
        setupTransportProfile,
        setupTransportProfileHash,
        'setupProfile.setupTransportProfileHash',
    );
    const evaluatorKeyScheduleProfile = objectField(
        setupProfile,
        'evaluatorKeyScheduleProfile',
        'setupProfile',
    );
    const evaluatorKeyScheduleProfileHash = hashField(
        setupProfile,
        'evaluatorKeyScheduleProfileHash',
        'setupProfile',
    );
    assertDerivedHashMatches(
        'EvaluatorKeyScheduleProfileHash',
        evaluatorKeyScheduleProfile,
        evaluatorKeyScheduleProfileHash,
        'setupProfile.evaluatorKeyScheduleProfileHash',
    );
    const publicVssMaterialSizeProfile = objectField(
        setupProfile,
        'publicVssCommitmentMaterialSizeProfile',
        'setupProfile',
    );
    positiveNumberField(
        publicVssMaterialSizeProfile,
        'fullMaterialCoefficientBytes',
        'setupProfile.publicVssCommitmentMaterialSizeProfile',
    );

    return setupProfile;
};

export const bgvProfileForCertificates = (
    bgvProfileValue: BgvRnsProfileForCertificates | JsonRecord,
): BgvRnsProfileForCertificates => {
    const bgvProfile = assertObjectRecord(
        bgvProfileValue,
        'bgvProfile',
    ) as BgvRnsProfileForCertificates;
    const profile = objectField(bgvProfile, 'profile', 'bgvProfile');
    positiveNumberField(profile, 'polynomialDegree', 'bgvProfile.profile');
    positiveNumberField(profile, 'plaintextModulus', 'bgvProfile.profile');
    const dataPrimes = numberArrayField(
        profile,
        'dataPrimes',
        'bgvProfile.profile',
    );
    if (dataPrimes.length === 0) {
        throw new Error('bgvProfile.profile.dataPrimes must not be empty.');
    }
    positiveNumberField(profile, 'specialPrime', 'bgvProfile.profile');
    stringField(bgvProfile, 'securityEstimatorInputHash', 'bgvProfile');

    return bgvProfile;
};

export const relinearizationScheduleEntries = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): readonly Readonly<{ readonly level: number }>[] => {
    const evaluatorProfile = setupProfile.evaluatorKeyScheduleProfile;
    const entries = evaluatorProfile.relinearizationLevelSchedule;
    if (!Array.isArray(entries)) {
        throw new TypeError(
            'setupProfile.evaluatorKeyScheduleProfile.relinearizationLevelSchedule must be an array.',
        );
    }

    return entries.map((entry, entryIndex) => {
        const entryRecord = assertObjectRecord(
            entry,
            `setupProfile.evaluatorKeyScheduleProfile.relinearizationLevelSchedule.${String(entryIndex)}`,
        );

        return {
            ...entryRecord,
            level: numberField(
                entryRecord,
                'level',
                `setupProfile.evaluatorKeyScheduleProfile.relinearizationLevelSchedule.${String(entryIndex)}`,
            ),
        };
    });
};

export const galoisScheduleEntries = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): readonly Readonly<{ readonly level: number }>[] => {
    const evaluatorProfile = setupProfile.evaluatorKeyScheduleProfile;
    const entries = evaluatorProfile.requiredGaloisKeySchedule;
    if (!Array.isArray(entries)) {
        throw new TypeError(
            'setupProfile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule must be an array.',
        );
    }

    return entries.map((entry, entryIndex) => {
        const entryRecord = assertObjectRecord(
            entry,
            `setupProfile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule.${String(entryIndex)}`,
        );

        return {
            ...entryRecord,
            level: numberField(
                entryRecord,
                'level',
                `setupProfile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule.${String(entryIndex)}`,
            ),
        };
    });
};

export const commitmentModulusLimbs = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): readonly unknown[] => {
    const messageEncoding = setupProfile.commitmentProfile.messageEncoding;
    const limbs = messageEncoding.commitmentModulusLimbs;
    if (!Array.isArray(limbs) || limbs.length === 0) {
        throw new TypeError(
            'setupProfile.commitmentProfile.messageEncoding.commitmentModulusLimbs must be a non-empty array.',
        );
    }

    return limbs;
};

const commitmentModulusValues = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): readonly number[] =>
    commitmentModulusLimbs(setupProfile).map((limb, limbIndex) => {
        const fieldName = `setupProfile.commitmentProfile.messageEncoding.commitmentModulusLimbs.${String(limbIndex)}`;
        if (typeof limb === 'number') {
            if (!Number.isSafeInteger(limb) || limb <= 0) {
                throw new TypeError(
                    `${fieldName} must be a positive safe integer.`,
                );
            }

            return limb;
        }
        const limbRecord = assertObjectRecord(limb, fieldName);

        return positiveNumberField(limbRecord, 'modulus', fieldName);
    });

export const commitmentModulusProductForProfile = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): bigint =>
    commitmentModulusValues(setupProfile).reduce(
        (product, modulus) => product * BigInt(modulus),
        1n,
    );
