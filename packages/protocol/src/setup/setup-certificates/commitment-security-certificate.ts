import { deriveProtocolHash } from '@sealed-lattice/crypto';

import { setupCommitmentProfileId, setupProfileId } from './constants.js';
import {
    acceptedCertificateTemplate,
    assertDerivedHashMatches,
    assertObjectRecord,
    ceilLog2Bigint,
    hashField,
    scalarPowerSum,
} from './field-helpers.js';
import {
    commitmentModulusLimbs,
    commitmentModulusProductForProfile,
} from './profile-derivations.js';
import type {
    CollectiveBgvSetupProfileForCertificates,
    SetupCommitmentSecurityCertificate,
    SetupCommitmentSecurityCertificateBody,
    JsonRecord,
} from './types.js';

const cloneJsonRecord = (value: JsonRecord): JsonRecord =>
    JSON.parse(JSON.stringify(value)) as JsonRecord;

const validatedCompactVssParameterCertificateInputBinding = (
    value: unknown,
    objectPath: string,
    expectedBindingHash?: string,
): JsonRecord => {
    const compactBinding = assertObjectRecord(value, objectPath);
    const bindingHash = hashField(
        compactBinding,
        'compactVssParameterCertificateInputBindingHash',
        objectPath,
    );
    if (
        expectedBindingHash !== undefined &&
        bindingHash !== expectedBindingHash
    ) {
        throw new Error(
            `${objectPath}.compactVssParameterCertificateInputBindingHash must match the profile compact VSS parameter certificate input binding hash.`,
        );
    }
    const bindingBody = cloneJsonRecord(compactBinding);
    delete bindingBody.compactVssParameterCertificateInputBindingHash;
    assertDerivedHashMatches(
        'CompactVssParameterCertificateInputBindingHash',
        bindingBody,
        bindingHash,
        `${objectPath}.compactVssParameterCertificateInputBindingHash`,
    );

    return cloneJsonRecord(compactBinding);
};

const compactVssParameterCertificateInputBindingForProfile = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): JsonRecord => {
    const profileBindingHash = hashField(
        setupProfile,
        'compactVssParameterCertificateInputBindingHash',
        'setupProfile',
    );

    return validatedCompactVssParameterCertificateInputBinding(
        setupProfile.compactVssParameterCertificateInputBinding,
        'setupProfile.compactVssParameterCertificateInputBinding',
        profileBindingHash,
    );
};

const validateSetupCommitmentTemplateCompactBinding = (
    template: JsonRecord,
    compactVssParameterCertificateInputBinding: JsonRecord,
): void => {
    const expectedBindingHash = hashField(
        compactVssParameterCertificateInputBinding,
        'compactVssParameterCertificateInputBindingHash',
        'setupProfile.compactVssParameterCertificateInputBinding',
    );
    const templateBindingHash = hashField(
        template,
        'compactVssParameterCertificateInputBindingHash',
        'setupProfile.acceptedCertificateTemplates.setupCommitmentSecurityCertificate',
    );
    if (templateBindingHash !== expectedBindingHash) {
        throw new Error(
            'setupProfile.acceptedCertificateTemplates.setupCommitmentSecurityCertificate.compactVssParameterCertificateInputBindingHash must match the profile compact VSS parameter certificate input binding hash.',
        );
    }
    validatedCompactVssParameterCertificateInputBinding(
        template.compactVssParameterCertificateInputBinding,
        'setupProfile.acceptedCertificateTemplates.setupCommitmentSecurityCertificate.compactVssParameterCertificateInputBinding',
        expectedBindingHash,
    );
};

const setupCommitmentSecurityCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): SetupCommitmentSecurityCertificateBody => {
    const sourceRnsPrimes = setupProfile.qShare.primes;
    const maxSourceMessageModulus = Math.max(...sourceRnsPrimes);
    const recipientScalarSum = scalarPowerSum(
        setupProfile.qDec,
        setupProfile.participantCount,
    );
    const thresholdScalarSum =
        recipientScalarSum * BigInt(setupProfile.participantCount);
    const commitmentModulusProduct =
        commitmentModulusProductForProfile(setupProfile);
    const maxRecipientLiftedCoefficient =
        BigInt(maxSourceMessageModulus - 1) * recipientScalarSum;
    const maxThresholdLiftedCoefficient =
        BigInt(maxSourceMessageModulus - 1) * thresholdScalarSum;
    // No-wrap bound: the homomorphic threshold-share aggregate (sum of message * trusteePoint^i over all trustees) must stay below the commitment modulus product, or the re-derived commitment opening becomes ambiguous and binding fails.
    if (maxThresholdLiftedCoefficient >= commitmentModulusProduct) {
        throw new Error(
            'setupProfile commitment modulus product must cover the threshold-share aggregate no-wrap bound.',
        );
    }
    const commitmentModulusProductBits = ceilLog2Bigint(
        commitmentModulusProduct,
    );
    const compactVssParameterCertificateInputBinding =
        compactVssParameterCertificateInputBindingForProfile(setupProfile);

    return {
        objectType: 'SetupCommitmentSecurityCertificate',
        objectVersion: 1,
        setupProfileId,
        setupProfileHash: setupProfile.setupProfileHash,
        commitmentProfileId: setupCommitmentProfileId,
        commitmentProfileHash: setupProfile.commitmentProfileHash,
        qShareHash: setupProfile.qShareHash,
        carryAwareVssShareRelationProfileHash:
            setupProfile.carryAwareVssShareRelationProfileHash,
        compactVssParameterCertificateInputBindingHash:
            compactVssParameterCertificateInputBinding.compactVssParameterCertificateInputBindingHash,
        compactVssParameterCertificateInputBinding,
        ringAndMatrixParameters: {
            coefficientRing: 'Z_q[X]/(X^N+1)',
            ringDegree: 32_768,
            sourceRnsLimbCount: sourceRnsPrimes.length,
            sourceRnsPrimes,
            commitmentModulusLimbs: commitmentModulusLimbs(setupProfile),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            commitmentModulusProductCeilBits: commitmentModulusProductBits,
            moduleRank: 2,
            randomnessWidth: 5,
            commitmentRowCount: 3,
            publicMatrixSource:
                'full-roster-common-randomness-XOF-unbiased-residue-stream',
        },
        freshOpeningDistribution: {
            distribution: 'coefficientwise-centered-ternary',
            coefficientSet: [-1, 0, 1],
            infinityNormBound: 1,
            randomnessWidth: 5,
        },
        fullWidthMessageBound: {
            messageSource: 'per-RNS-prime-Shamir-coefficient-ring-element',
            maxSourceMessageModulus,
            maxFreshMessageCoefficientDecimal: String(
                maxSourceMessageModulus - 1,
            ),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
        },
        aggregateOpeningBounds: {
            shamirCoefficientCount: setupProfile.qDec,
            maximumTrusteePoint: setupProfile.participantCount,
            recipientScalarPowerSumDecimal: recipientScalarSum.toString(),
            recipientAggregateOpeningInfinityBound: Number(recipientScalarSum),
            maxRecipientLiftedCoefficientDecimal:
                maxRecipientLiftedCoefficient.toString(),
            sourceTrusteeCountForThresholdAggregation:
                setupProfile.participantCount,
            thresholdScalarPowerSumDecimal: thresholdScalarSum.toString(),
            thresholdShareOpeningInfinityBound: Number(thresholdScalarSum),
            maxThresholdLiftedCoefficientDecimal:
                maxThresholdLiftedCoefficient.toString(),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
        },
        estimatorRows: [
            {
                rowId: 'first-profile-module-sis-binding-row',
                problem: 'Module-SIS',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                modulusCeilBits: commitmentModulusProductBits,
                shortVectorInfinityBoundDecimal: thresholdScalarSum.toString(),
            },
            {
                rowId: 'first-profile-module-lwe-hiding-row',
                problem: 'Module-LWE',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                secretDistribution: 'centered-ternary-opening',
                modulusCeilBits: commitmentModulusProductBits,
            },
        ],
    };
};

export const createSetupCommitmentSecurityCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): SetupCommitmentSecurityCertificate => {
    const compactVssParameterCertificateInputBinding =
        compactVssParameterCertificateInputBindingForProfile(setupProfile);
    const template = acceptedCertificateTemplate(
        setupProfile,
        'setupCommitmentSecurityCertificate',
        'SetupCommitmentSecurityCertificate',
        'setupCommitmentSecurityCertificateHash',
        'SetupCommitmentSecurityCertificateHash',
    );
    if (template !== null) {
        validateSetupCommitmentTemplateCompactBinding(
            template,
            compactVssParameterCertificateInputBinding,
        );
        return template as SetupCommitmentSecurityCertificate;
    }

    const certificateBody =
        setupCommitmentSecurityCertificateBody(setupProfile);

    return {
        ...certificateBody,
        setupCommitmentSecurityCertificateHash: deriveProtocolHash(
            'SetupCommitmentSecurityCertificateHash',
            certificateBody,
        ),
    };
};
