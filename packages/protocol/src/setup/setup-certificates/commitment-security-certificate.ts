import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import {
    acceptedCertificateTemplate,
    ceilLog2Bigint,
    scalarPowerSum,
} from './field-helpers.js';
import {
    commitmentModulusLimbs,
    commitmentModulusProductForParameters,
} from './parameter-derivations.js';
import type {
    CollectiveBgvSetupParametersForCertificates,
    SetupCommitmentSecurityCertificate,
    SetupCommitmentSecurityCertificateBody,
} from './types.js';

const setupCommitmentSecurityCertificateBody = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
): SetupCommitmentSecurityCertificateBody => {
    const sourceRnsPrimes = setupParameters.qShare.primes;
    const maxSourceMessageModulus = Math.max(...sourceRnsPrimes);
    const recipientScalarSum = scalarPowerSum(
        setupParameters.qDec,
        setupParameters.participantCount,
    );
    const thresholdScalarSum =
        recipientScalarSum * BigInt(setupParameters.participantCount);
    const commitmentModulusProduct =
        commitmentModulusProductForParameters(setupParameters);
    const maxRecipientLiftedCoefficient =
        BigInt(maxSourceMessageModulus - 1) * recipientScalarSum;
    const maxThresholdLiftedCoefficient =
        BigInt(maxSourceMessageModulus - 1) * thresholdScalarSum;
    // No-wrap bound: the homomorphic threshold-share aggregate (sum of message * trusteePoint^i over all trustees) must stay below the commitment modulus product, or the re-derived commitment opening becomes ambiguous and binding fails.
    if (maxThresholdLiftedCoefficient >= commitmentModulusProduct) {
        throw new Error(
            'setupParameters commitment modulus product must cover the threshold-share aggregate no-wrap bound.',
        );
    }
    const commitmentModulusProductBits = ceilLog2Bigint(
        commitmentModulusProduct,
    );

    return {
        objectType: 'SetupCommitmentSecurityCertificate',
        objectVersion: 1,
        setupParametersHash: setupParameters.setupParametersHash,
        ringAndMatrixParameters: {
            coefficientRing: 'Z_q[X]/(X^N+1)',
            ringDegree: 32_768,
            sourceRnsLimbCount: sourceRnsPrimes.length,
            sourceRnsPrimes,
            commitmentModulusLimbs: commitmentModulusLimbs(setupParameters),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            commitmentModulusProductCeilBits: commitmentModulusProductBits,
            moduleRank: 2,
            randomnessWidth: 5,
            commitmentRowCount: 3,
            publicMatrixSource:
                'full-roster-common-randomness-XOF-unbiased-residue-stream',
            matrixHashBound: true,
        },
        freshOpeningDistribution: {
            distribution: 'coefficientwise-centered-ternary',
            coefficientSet: [-1, 0, 1],
            infinityNormBound: 1,
            randomnessWidth: 5,
            rawOpeningExported: false,
            perCoefficientOpeningExported: false,
        },
        fullWidthMessageBound: {
            messageSource: 'per-RNS-prime-Shamir-coefficient-ring-element',
            maxSourceMessageModulus,
            maxFreshMessageCoefficientDecimal: String(
                maxSourceMessageModulus - 1,
            ),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            freshMessageNoWrap:
                BigInt(maxSourceMessageModulus - 1) < commitmentModulusProduct,
        },
        aggregateOpeningBounds: {
            shamirCoefficientCount: setupParameters.qDec,
            maximumTrusteePoint: setupParameters.participantCount,
            recipientScalarPowerSumDecimal: recipientScalarSum.toString(),
            recipientAggregateOpeningInfinityBound: Number(recipientScalarSum),
            maxRecipientLiftedCoefficientDecimal:
                maxRecipientLiftedCoefficient.toString(),
            sourceTrusteeCountForThresholdAggregation:
                setupParameters.participantCount,
            thresholdScalarPowerSumDecimal: thresholdScalarSum.toString(),
            thresholdShareOpeningInfinityBound: Number(thresholdScalarSum),
            maxThresholdLiftedCoefficientDecimal:
                maxThresholdLiftedCoefficient.toString(),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            recipientAndThresholdNoWrap: true,
        },
        multiOpeningLeakage: {
            recipientAggregateOpeningsArePublic: false,
            recipientAggregateOpeningsAreMailboxPlaintext: false,
            maxCorruptRecipientsBeforeThreshold: setupParameters.qDec - 1,
            shamirPolynomialDegree: setupParameters.qDec - 1,
            rawCoefficientOpeningsExported: false,
            perCoefficientRandomnessExported: false,
            thresholdBoundary:
                'recipient-aggregate-openings-and-carry-witnesses-are-private-proof-witnesses',
        },
        bindingAssumption: {
            assumption: 'Module-SIS',
            boundTarget:
                'two-valid-openings-to-one-commitment-yield-short-module-SIS-solution',
            moduleRank: 2,
            randomnessWidth: 5,
            commitmentModulusProductCeilBits: commitmentModulusProductBits,
            extractedOpeningInfinityBound: Number(thresholdScalarSum),
        },
        hidingAssumption: {
            assumption:
                'Module-LWE with recipient-hidden proof-witness opening leakage boundary',
            openingDistribution: 'coefficientwise-centered-ternary',
            publicMatrixDistribution: 'hash-derived-uniform-residue-stream',
            lowEntropySecretHiding: true,
        },
        estimatorRows: [
            {
                rowId: 'first-roster-module-sis-binding-row',
                problem: 'Module-SIS',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                modulusCeilBits: commitmentModulusProductBits,
                shortVectorInfinityBoundDecimal: thresholdScalarSum.toString(),
                accountingBasis:
                    'accepted Module-SIS binding row under FPS25 commitment references and no-wrap threshold-opening bounds',
            },
            {
                rowId: 'first-roster-module-lwe-hiding-row',
                problem: 'Module-LWE',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                secretDistribution: 'centered-ternary-opening',
                modulusCeilBits: commitmentModulusProductBits,
                accountingBasis:
                    'accepted Module-LWE hiding row under FPS25/ACC18 references and recipient-hidden opening leakage boundary',
            },
        ],
    };
};

export const createSetupCommitmentSecurityCertificate = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
): SetupCommitmentSecurityCertificate => {
    const template = acceptedCertificateTemplate(
        setupParameters,
        'setupCommitmentSecurityCertificate',
        'SetupCommitmentSecurityCertificate',
        'setupCommitmentSecurityCertificateHash',
    );
    if (template !== null) {
        return template as SetupCommitmentSecurityCertificate;
    }

    const certificateBody =
        setupCommitmentSecurityCertificateBody(setupParameters);

    return {
        ...certificateBody,
        setupCommitmentSecurityCertificateHash:
            deriveCanonicalObjectHash(certificateBody),
    };
};
