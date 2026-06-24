import {
    assertObjectRecord,
    hashField,
    numberArrayField,
    numberField,
    objectField,
    positiveNumberField,
} from './field-helpers.js';
import type {
    BgvRnsParametersForCertificates,
    CollectiveBgvSetupParametersForCertificates,
    JsonRecord,
} from './types.js';

export const setupParametersForCertificates = (
    setupParametersValue:
        | CollectiveBgvSetupParametersForCertificates
        | JsonRecord,
): CollectiveBgvSetupParametersForCertificates => {
    const setupParametersRecord = assertObjectRecord(
        setupParametersValue,
        'setupParameters',
    );
    const setupParameters =
        setupParametersRecord as CollectiveBgvSetupParametersForCertificates;
    positiveNumberField(setupParameters, 'participantCount', 'setupParameters');
    positiveNumberField(setupParameters, 'qDec', 'setupParameters');
    hashField(setupParameters, 'setupParametersHash', 'setupParameters');
    const qShare = objectField(setupParameters, 'qShare', 'setupParameters');
    const qSharePrimes = numberArrayField(
        qShare,
        'primes',
        'setupParameters.qShare',
    );
    if (qSharePrimes.length === 0) {
        throw new Error('setupParameters.qShare.primes must not be empty.');
    }
    const commitmentParameters = objectField(
        setupParameters,
        'commitment',
        'setupParameters',
    );
    objectField(
        commitmentParameters,
        'messageEncoding',
        'setupParameters.commitment',
    );
    objectField(setupParameters, 'setupProof', 'setupParameters');
    objectField(setupParameters, 'setupTransport', 'setupParameters');
    objectField(setupParameters, 'evaluatorKeySchedule', 'setupParameters');
    const publicVssMaterialSizeParameters = objectField(
        setupParameters,
        'publicVssCommitmentMaterialSize',
        'setupParameters',
    );
    positiveNumberField(
        publicVssMaterialSizeParameters,
        'fullMaterialCoefficientBytes',
        'setupParameters.publicVssCommitmentMaterialSize',
    );

    return setupParameters;
};

export const bgvParametersForCertificates = (
    bgvParametersValue: BgvRnsParametersForCertificates | JsonRecord,
): BgvRnsParametersForCertificates => {
    const bgvParameters = assertObjectRecord(
        bgvParametersValue,
        'bgvParameters',
    ) as BgvRnsParametersForCertificates;
    const parameters = objectField(
        bgvParameters,
        'parameters',
        'bgvParameters',
    );
    positiveNumberField(
        parameters,
        'polynomialDegree',
        'bgvParameters.parameters',
    );
    positiveNumberField(
        parameters,
        'plaintextModulus',
        'bgvParameters.parameters',
    );
    const dataPrimes = numberArrayField(
        parameters,
        'dataPrimes',
        'bgvParameters.parameters',
    );
    if (dataPrimes.length === 0) {
        throw new Error(
            'bgvParameters.parameters.dataPrimes must not be empty.',
        );
    }
    positiveNumberField(parameters, 'specialPrime', 'bgvParameters.parameters');
    hashField(bgvParameters, 'bgvParametersHash', 'bgvParameters');

    return bgvParameters;
};

export const relinearizationScheduleEntries = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
): readonly Readonly<{ readonly level: number }>[] => {
    const evaluatorSchedule = setupParameters.evaluatorKeySchedule;
    const entries = evaluatorSchedule.relinearizationLevelSchedule;
    if (!Array.isArray(entries)) {
        throw new TypeError(
            'setupParameters.evaluatorKeySchedule.relinearizationLevelSchedule must be an array.',
        );
    }

    return entries.map((entry, entryIndex) => {
        const entryRecord = assertObjectRecord(
            entry,
            `setupParameters.evaluatorKeySchedule.relinearizationLevelSchedule.${String(entryIndex)}`,
        );

        return {
            ...entryRecord,
            level: numberField(
                entryRecord,
                'level',
                `setupParameters.evaluatorKeySchedule.relinearizationLevelSchedule.${String(entryIndex)}`,
            ),
        };
    });
};

export const galoisScheduleEntries = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
): readonly Readonly<{ readonly level: number }>[] => {
    const evaluatorSchedule = setupParameters.evaluatorKeySchedule;
    const entries = evaluatorSchedule.requiredGaloisKeySchedule;
    if (!Array.isArray(entries)) {
        throw new TypeError(
            'setupParameters.evaluatorKeySchedule.requiredGaloisKeySchedule must be an array.',
        );
    }

    return entries.map((entry, entryIndex) => {
        const entryRecord = assertObjectRecord(
            entry,
            `setupParameters.evaluatorKeySchedule.requiredGaloisKeySchedule.${String(entryIndex)}`,
        );

        return {
            ...entryRecord,
            level: numberField(
                entryRecord,
                'level',
                `setupParameters.evaluatorKeySchedule.requiredGaloisKeySchedule.${String(entryIndex)}`,
            ),
        };
    });
};

export const commitmentModulusLimbs = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
): readonly unknown[] => {
    const messageEncoding = setupParameters.commitment.messageEncoding;
    const limbs = messageEncoding.commitmentModulusLimbs;
    if (!Array.isArray(limbs) || limbs.length === 0) {
        throw new TypeError(
            'setupParameters.commitment.messageEncoding.commitmentModulusLimbs must be a non-empty array.',
        );
    }

    return limbs;
};

const commitmentModulusValues = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
): readonly number[] =>
    commitmentModulusLimbs(setupParameters).map((limb, limbIndex) => {
        const fieldName = `setupParameters.commitment.messageEncoding.commitmentModulusLimbs.${String(limbIndex)}`;
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

export const commitmentModulusProductForParameters = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
): bigint =>
    commitmentModulusValues(setupParameters).reduce(
        (product, modulus) => product * BigInt(modulus),
        1n,
    );
