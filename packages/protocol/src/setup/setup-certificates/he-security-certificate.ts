import { deriveProtocolHash } from '@sealed-lattice/crypto';

import { setupProfileId, targetDecryptionProfileId } from './constants.js';
import {
    acceptedCertificateTemplate,
    keySwitchComponentPolynomialCount,
    moduliBitLengthSum,
    modulusProductDecimal,
} from './field-helpers.js';
import {
    galoisScheduleEntries,
    relinearizationScheduleEntries,
} from './profile-derivations.js';
import type {
    BgvHeSecurityCertificate,
    BgvHeSecurityCertificateBody,
    BgvRnsProfileForCertificates,
    CollectiveBgvSetupProfileForCertificates,
} from './types.js';

const bgvHeSecurityCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    bgvProfile: BgvRnsProfileForCertificates,
): BgvHeSecurityCertificateBody => {
    const dataPrimes = bgvProfile.profile.dataPrimes;
    const dataPrimeProductDecimal = modulusProductDecimal(dataPrimes);
    const largestExposedModulusBits = moduliBitLengthSum(dataPrimes);
    const extendedUtilityCeilLog2Product = moduliBitLengthSum([
        ...dataPrimes,
        bgvProfile.profile.specialPrime,
    ]);
    const postQuantumMaximumLogQ = 827;
    const classicalMaximumLogQ = 881;
    const acceptedRelinearizationKeyPolynomials =
        keySwitchComponentPolynomialCount(
            relinearizationScheduleEntries(setupProfile),
        );
    const acceptedGaloisKeyPolynomials = keySwitchComponentPolynomialCount(
        galoisScheduleEntries(setupProfile),
    );

    return {
        objectType: 'BgvHeSecurityCertificate',
        objectVersion: 1,
        setupProfileId,
        profileId: bgvProfile.profile.profileId,
        backendProfileId: bgvProfile.profile.backendProfileId,
        setupProfileHash: setupProfile.setupProfileHash,
        qShareHash: setupProfile.qShareHash,
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        evaluatorKeyScheduleProfileHash:
            setupProfile.evaluatorKeyScheduleProfileHash,
        assessedRing: {
            polynomialDegree: bgvProfile.profile.polynomialDegree,
            plaintextModulus: bgvProfile.profile.plaintextModulus,
            dataBasisId: bgvProfile.profile.dataBasisId,
            dataPrimeCount: dataPrimes.length,
            dataPrimeProductDecimal,
            dataPrimeCeilLog2Product: largestExposedModulusBits,
            qSharePrimeCount: dataPrimes.length,
            qSharePrimeProductDecimal: dataPrimeProductDecimal,
            qShareCeilLog2Product: largestExposedModulusBits,
            specialPrime: bgvProfile.profile.specialPrime,
            extendedUtilityCeilLog2Product,
            largestExposedBasisClass: 'Q_data',
            largestExposedModulusBits,
        },
        secretDistribution: {
            distributionKind: 'standard-ternary-collective-secret',
            support: [-1, 0, 1],
            isPlainDenseTernary: true,
            estimatorModel: 'HE-standard-ternary',
            source: 'recipient-verified-VSS same-secret commitments',
        },
        errorDistribution: {
            distributionKind: 'centered-binomial-eta2',
            support: [-2, -1, 0, 1, 2],
            keySwitchNoiseDistribution: 'centered-binomial-eta2',
        },
        publicSampleAccounting: {
            publicKeyCrpPolynomials: 1,
            publicKeyShareCount: setupProfile.participantCount,
            acceptedRelinearizationKeyPolynomials,
            acceptedGaloisKeyPolynomials,
            scheduledRelinearizationLevelCount:
                relinearizationScheduleEntries(setupProfile).length,
            scheduledGaloisKeyCount: galoisScheduleEntries(setupProfile).length,
        },
        standardRows: {
            postQuantumTernary128: {
                costModel: 'BKZ.qsieve',
                secretDistribution: 'ternary',
                polynomialDegree: 32_768,
                securityLevelBits: 128,
                maximumLogQ: postQuantumMaximumLogQ,
                largestExposedModulusBits,
                marginBits: Math.max(
                    postQuantumMaximumLogQ - largestExposedModulusBits,
                    0,
                ),
                uSVPBits: '128.1',
                decodingBits: '128.7',
                dualBits: '128.4',
            },
            classicalTernary128: {
                costModel: 'BKZ.sieve',
                secretDistribution: 'ternary',
                polynomialDegree: 32_768,
                securityLevelBits: 128,
                maximumLogQ: classicalMaximumLogQ,
                largestExposedModulusBits,
                marginBits: Math.max(
                    classicalMaximumLogQ - largestExposedModulusBits,
                    0,
                ),
                uSVPBits: '128.5',
                decodingBits: '129.1',
                dualBits: '128.5',
            },
        },
        estimatorBinding: {
            tool: 'HE-standard published parameter table',
            toolVersion: 'ACC18 local text reference',
            securityEstimatorInputHash: bgvProfile.securityEstimatorInputHash,
            secretModel: 'standard-ternary',
            errorModel: 'centered-binomial-eta2',
            largestExposedModulusBits,
            publicSamplesBound: true,
        },
        targetDecryptionStatus: {
            targetDecryptionProfileId,
        },
    };
};

export const createBgvHeSecurityCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    bgvProfile: BgvRnsProfileForCertificates,
): BgvHeSecurityCertificate => {
    const template = acceptedCertificateTemplate(
        setupProfile,
        'heSecurityCertificate',
        'BgvHeSecurityCertificate',
        'heSecurityCertificateHash',
        'BGVHeSecurityCertificateHash',
    );
    if (template !== null) {
        return template as BgvHeSecurityCertificate;
    }

    const certificateBody = bgvHeSecurityCertificateBody(
        setupProfile,
        bgvProfile,
    );

    return {
        ...certificateBody,
        heSecurityCertificateHash: deriveProtocolHash(
            'BGVHeSecurityCertificateHash',
            certificateBody,
        ),
    };
};
