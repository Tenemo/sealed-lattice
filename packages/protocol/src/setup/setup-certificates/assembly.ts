import { createSetupCommitmentSecurityCertificate } from './commitment-security-certificate.js';
import {
    assertObjectRecord,
    hashArrayField,
    hashField,
    setupCertificateTransportedObjectInputs,
} from './field-helpers.js';
import { createBgvHeSecurityCertificate } from './he-security-certificate.js';
import {
    bgvProfileForCertificates,
    setupProfileForCertificates,
} from './profile-derivations.js';
import { createSetupProofAccountingCertificate } from './proof-accounting-certificate.js';
import { createSetupTransportCertificate } from './transport-certificate.js';
import type { SetupCertificates, SetupCertificatesInput } from './types.js';

export const createSetupCertificates = (
    input: SetupCertificatesInput,
): SetupCertificates => {
    const setupProfile = setupProfileForCertificates(input.setupProfile);
    const bgvProfile = bgvProfileForCertificates(input.bgvProfile);
    const vssCoefficientCommitmentMaterial = assertObjectRecord(
        input.vssCoefficientCommitmentMaterial,
        'vssCoefficientCommitmentMaterial',
    );
    const transport = assertObjectRecord(input.transport, 'transport');
    const transportInput = {
        fullObjectHash: hashField(transport, 'fullObjectHash', 'transport'),
        chunkHashes: hashArrayField(transport, 'chunkHashes', 'transport'),
        transportedObjects: setupCertificateTransportedObjectInputs(transport),
    };

    return {
        setupCommitmentSecurityCertificate:
            createSetupCommitmentSecurityCertificate(setupProfile),
        setupTransportCertificate: createSetupTransportCertificate(
            setupProfile,
            vssCoefficientCommitmentMaterial,
            transportInput,
        ),
        setupProofAccountingCertificate: createSetupProofAccountingCertificate(
            setupProfile,
            input.sameSecretLinkageAnchorProofAccounting === undefined
                ? undefined
                : assertObjectRecord(
                      input.sameSecretLinkageAnchorProofAccounting,
                      'sameSecretLinkageAnchorProofAccounting',
                  ),
            input.publicKeyShareProofAccounting === undefined
                ? undefined
                : assertObjectRecord(
                      input.publicKeyShareProofAccounting,
                      'publicKeyShareProofAccounting',
                  ),
            input.trusteeEvaluationKeyProofAccounting === undefined
                ? undefined
                : assertObjectRecord(
                      input.trusteeEvaluationKeyProofAccounting,
                      'trusteeEvaluationKeyProofAccounting',
                  ),
        ),
        heSecurityCertificate: createBgvHeSecurityCertificate(
            setupProfile,
            bgvProfile,
        ),
    };
};
