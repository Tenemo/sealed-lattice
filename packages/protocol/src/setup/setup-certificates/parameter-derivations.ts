import {
    assertObjectRecord,
    hashField,
    numberArrayField,
    objectField,
    positiveNumberField,
} from './field-helpers.js';
import type {
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

    return setupParameters;
};
