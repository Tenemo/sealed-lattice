import { deriveProtocolHash } from '@sealed-lattice/crypto';

import type { GaloisKeyShareBatch } from '../evaluation-key-proof-records.js';
import type {
    CollectivePublicKey,
    SetupPackagePublicKeyShareMaterialSet,
    PublicKeyShareSet,
    PublicKeyShareSuccinctProofSet,
} from '../public-key-share-records.js';
import {
    createCollectivePublicKey,
    createCollectivePublicKeyFromTransportedPublicKeyShareMaterial,
    publicKeyShareMaterialTransportEncoding,
} from '../public-key-share-records.js';
import type { SameSecretProofSet } from '../same-secret-consistency-records.js';
import { createSetupCertificates } from '../setup-certificates.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    assertObjectRecord,
    contextFieldNames,
    firstProfileDecryptionThreshold,
    firstProfileParticipantCount,
    firstProfileSetupCompletionQuorum,
    hashField,
    optionalNestedHashValue,
    optionalTopLevelHashValue,
    setupProfileId,
} from './constants-and-assertions.js';
import { setupCertificateTransportedObjectsFromPackageInput } from './transported-material.js';
import type {
    ActiveStaticSetupTheoremCertificate,
    ActiveStaticSetupTheoremCertificateBody,
    JsonRecord,
    SetupKeyCorrectnessCertificate,
    SetupKeyCorrectnessCertificateBody,
    SetupPackageCertificateRecords,
    SetupPackageInput,
    SetupPackageInputWithDerivedCollectivePublicKey,
} from './types.js';

export const resolveSetupCertificateRecords = (
    input: SetupPackageInput,
): SetupPackageCertificateRecords => {
    if (input.setupCertificateInput !== undefined) {
        if (
            input.setupCommitmentSecurityCertificate !== undefined ||
            input.setupTransportCertificate !== undefined ||
            input.setupProofAccountingCertificate !== undefined ||
            input.heSecurityCertificate !== undefined
        ) {
            throw new Error(
                'setupCertificateInput must not be mixed with prebuilt setup certificate records.',
            );
        }

        const transportedObjects =
            setupCertificateTransportedObjectsFromPackageInput(input);

        return createSetupCertificates({
            ...input.setupCertificateInput,
            vssCoefficientCommitmentMaterial:
                input.vssCoefficientCommitmentMaterial,
            transport:
                transportedObjects.length === 0
                    ? input.setupCertificateInput.transport
                    : {
                          ...input.setupCertificateInput.transport,
                          transportedObjects: [
                              ...(input.setupCertificateInput.transport
                                  .transportedObjects ?? []),
                              ...transportedObjects,
                          ],
                      },
        });
    }

    if (
        input.setupCommitmentSecurityCertificate === undefined ||
        input.setupTransportCertificate === undefined ||
        input.setupProofAccountingCertificate === undefined ||
        input.heSecurityCertificate === undefined
    ) {
        throw new Error(
            'setupCertificateInput or all setup certificate records are required.',
        );
    }

    return {
        setupCommitmentSecurityCertificate:
            input.setupCommitmentSecurityCertificate,
        setupTransportCertificate: input.setupTransportCertificate,
        setupProofAccountingCertificate: input.setupProofAccountingCertificate,
        heSecurityCertificate: input.heSecurityCertificate,
    };
};

const contextFieldsForCertificate = (
    setupContext: CollectiveBgvSetupContext,
): JsonRecord =>
    Object.fromEntries(
        contextFieldNames.map((fieldName) => [
            fieldName,
            setupContext[fieldName],
        ]),
    );

const qSharePrimesFromPublicKeyShares = (
    publicKeyShares: PublicKeyShareSet,
    expectedRnsLimbCount: number,
): readonly number[] => {
    const shareRecords = [...publicKeyShares.shareRecords].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (shareRecords.length !== publicKeyShares.participantCount) {
        throw new Error(
            'publicKeyShares.shareRecords must contain one record per participant.',
        );
    }
    const firstShareRecord = shareRecords[0];
    if (firstShareRecord === undefined) {
        throw new Error('publicKeyShares must contain at least one record.');
    }
    const qSharePrimes =
        firstShareRecord.shareCoefficientVectorHash512ByLimb.map(
            (coefficientVectorHash, rnsLimbIndex) => {
                if (
                    coefficientVectorHash.rnsLimbIndex !== rnsLimbIndex ||
                    coefficientVectorHash.component !== 'b_i' ||
                    !Number.isSafeInteger(coefficientVectorHash.rnsPrime) ||
                    coefficientVectorHash.rnsPrime <= 0
                ) {
                    throw new Error(
                        'publicKeyShares coefficient hash limbs must expose accepted Q_share primes in order.',
                    );
                }

                return coefficientVectorHash.rnsPrime;
            },
        );
    if (qSharePrimes.length !== expectedRnsLimbCount) {
        throw new Error('publicKeyShares RNS limbs must match material roots.');
    }
    shareRecords.forEach((shareRecord, expectedRosterPosition) => {
        if (
            shareRecord.trusteeRosterPosition !== expectedRosterPosition ||
            shareRecord.shareCoefficientVectorHash512ByLimb.length !==
                qSharePrimes.length
        ) {
            throw new Error(
                'publicKeyShares share records must have contiguous roster positions and complete RNS limbs.',
            );
        }
        shareRecord.shareCoefficientVectorHash512ByLimb.forEach(
            (coefficientVectorHash, rnsLimbIndex) => {
                if (
                    coefficientVectorHash.rnsLimbIndex !== rnsLimbIndex ||
                    coefficientVectorHash.component !== 'b_i' ||
                    coefficientVectorHash.rnsPrime !==
                        qSharePrimes[rnsLimbIndex]
                ) {
                    throw new Error(
                        'publicKeyShares share records must agree on Q_share primes.',
                    );
                }
            },
        );
    });

    return qSharePrimes;
};

export const derivedCollectivePublicKey = (
    input: SetupPackageInput,
): CollectivePublicKey => {
    if (
        Object.prototype.hasOwnProperty.call(input, 'collectivePublicKey') &&
        (input as Readonly<{ readonly collectivePublicKey?: unknown }>)
            .collectivePublicKey !== undefined
    ) {
        throw new Error(
            'collectivePublicKey is derived from accepted public-key material and must not be supplied by callers.',
        );
    }
    const publicKeyShareMaterial =
        input.publicKeyShareMaterial as SetupPackagePublicKeyShareMaterialSet;
    const qSharePrimes = qSharePrimesFromPublicKeyShares(
        input.publicKeyShares,
        publicKeyShareMaterial.rnsLimbCount,
    );
    const commonCollectivePublicKeyInput = {
        setupContext: input.setupContext,
        qSharePrimes,
        participantCount: input.publicKeyShares.participantCount,
        ringDegree: publicKeyShareMaterial.ringDegree,
        publicMatrixSeedHash: publicKeyShareMaterial.publicMatrixSeedHash,
        publicKeyCrpRoot: publicKeyShareMaterial.publicKeyCrpRoot,
        publicAPolynomialRoot: publicKeyShareMaterial.publicAPolynomialRoot,
        sameSecretConsistency: input.sameSecretConsistency,
        sameSecretProofs: input.sameSecretProofs as SameSecretProofSet,
        publicKeyShares: input.publicKeyShares,
        publicKeyShareProofs: input.publicKeyShareProofs,
        publicKeyShareMaterial,
        publicKeyShareSuccinctProofs:
            input.publicKeyShareSuccinctProofs as PublicKeyShareSuccinctProofSet,
    } as const;

    if (
        publicKeyShareMaterial.materialEncoding ===
        publicKeyShareMaterialTransportEncoding
    ) {
        if (input.transportedPublicKeyShareMaterial === undefined) {
            throw new Error(
                'transportedPublicKeyShareMaterial is required when publicKeyShareMaterial is binary-chunked.',
            );
        }

        return createCollectivePublicKeyFromTransportedPublicKeyShareMaterial({
            ...commonCollectivePublicKeyInput,
            publicKeyShareMaterial,
            transportedPublicKeyShareMaterial:
                input.transportedPublicKeyShareMaterial,
        });
    }

    return createCollectivePublicKey({
        ...commonCollectivePublicKeyInput,
        publicKeyShareMaterial,
    });
};

const galoisBatchRootEntries = (
    galoisKeyShareBatches: readonly GaloisKeyShareBatch[],
): readonly JsonRecord[] =>
    galoisKeyShareBatches.map((batch, batchIndex) => ({
        trusteeIdentity: batch.trusteeIdentity,
        trusteeRosterPosition: batch.trusteeRosterPosition,
        galoisKeyShareBatchRoot: hashField(
            batch,
            'galoisKeyShareBatchRoot',
            `galoisKeyShareBatches.${String(batchIndex)}`,
        ),
    }));

const setupKeyCorrectnessCertificateBody = (
    input: SetupPackageInputWithDerivedCollectivePublicKey,
    certificates: SetupPackageCertificateRecords,
): SetupKeyCorrectnessCertificateBody => {
    const collectivePublicKeyRoot = hashField(
        input.collectivePublicKey,
        'collectivePublicKeyRoot',
        'collectivePublicKey',
    );
    const evaluationKeySetHash = hashField(
        input.evaluationKeys,
        'evaluationKeySetHash',
        'evaluationKeys',
    );
    const publicKeyShareMaterialSetRoot = hashField(
        input.publicKeyShareMaterial,
        'publicKeyShareMaterialSetRoot',
        'publicKeyShareMaterial',
    );
    const publicKeyShareSuccinctProofSetRoot = hashField(
        input.publicKeyShareSuccinctProofs,
        'publicKeyShareSuccinctProofSetRoot',
        'publicKeyShareSuccinctProofs',
    );

    return {
        objectType: 'SetupKeyCorrectnessCertificate',
        objectVersion: 1,
        setupProfileId,
        ...contextFieldsForCertificate(input.setupContext),
        setupProofProfileBinding:
            'fixed-setup-proof-profile-bound-by-setup-proof-accounting-certificate',
        keyCorrectnessScope:
            'collective-public-key-and-public-evaluation-key-roots-derived-from-proof-bearing-setup-records',
        keyCorrectnessTheorem: {
            activeMaliciousPrototypeBoundary:
                'malformed roots, reordered trustee records, stale schedules, missing proof material, inconsistent collective public-key material, and unscheduled evaluation keys are refused before accepted runtime loading',
        },
        collectivePublicKey: {
            status: 'collective-public-key-coefficients-recomputed-from-public-key-share-material-and-succinct-proof-roots',
            collectivePublicKeyRoot,
            sourceRoots: {
                publicKeyShareSetRoot: hashField(
                    input.publicKeyShares,
                    'publicKeyShareSetRoot',
                    'publicKeyShares',
                ),
                publicKeyShareProofSetRoot: hashField(
                    input.publicKeyShareProofs,
                    'publicKeyShareProofSetRoot',
                    'publicKeyShareProofs',
                ),
                publicKeyShareMaterialSetRoot,
                publicKeyShareSuccinctProofSetRoot,
            },
        },
        publicEvaluationKeys: {
            status: 'public-evaluation-key-roots-recomputed-from-frozen-schedule-and-proof-bearing-relinearization-and-galois-records',
            evaluationKeySetHash,
            evaluatorKeyScheduleRoot: hashField(
                input.evaluatorKeySchedule,
                'evaluatorKeyScheduleRoot',
                'evaluatorKeySchedule',
            ),
            relinearizationKeyShareRoundsRoot: hashField(
                input.relinearizationKeyShareRounds,
                'relinearizationKeyShareRoundsRoot',
                'relinearizationKeyShareRounds',
            ),
            galoisKeyShareBatchRoots: galoisBatchRootEntries(
                input.galoisKeyShareBatches,
            ),
            requiredGaloisSetHash: hashField(
                input.evaluatorKeySchedule,
                'requiredGaloisSetHash',
                'evaluatorKeySchedule',
            ),
        },
        certificateDependencies: {
            setupProofAccountingCertificateHash: hashField(
                certificates.setupProofAccountingCertificate,
                'setupProofAccountingCertificateHash',
                'setupProofAccountingCertificate',
            ),
            heSecurityCertificateHash: hashField(
                certificates.heSecurityCertificate,
                'heSecurityCertificateHash',
                'heSecurityCertificate',
            ),
        },
    };
};

export const createSetupKeyCorrectnessCertificate = (
    input: SetupPackageInputWithDerivedCollectivePublicKey,
    certificates: SetupPackageCertificateRecords,
): SetupKeyCorrectnessCertificate => {
    const certificateBody = setupKeyCorrectnessCertificateBody(
        input,
        certificates,
    );

    return {
        ...certificateBody,
        setupKeyCorrectnessCertificateHash: deriveProtocolHash(
            'SetupKeyCorrectnessCertificateHash',
            certificateBody,
        ),
    };
};

const activeStaticSetupTheoremCertificateBody = (
    setupPackage: Readonly<Record<string, unknown>>,
): ActiveStaticSetupTheoremCertificateBody => {
    const setupContext = assertObjectRecord(
        setupPackage.setupContext,
        'setupPackage.setupContext',
    );

    return {
        objectType: 'ActiveStaticSetupTheoremCertificate',
        objectVersion: 1,
        setupProfileId,
        ...contextFieldsForCertificate(
            setupContext as unknown as CollectiveBgvSetupContext,
        ),
        adversaryModel: {
            secretConfidentialityCorruptTrusteeBound:
                firstProfileDecryptionThreshold - 1,
            fullRosterSetupCompletionRequired: true,
        },
        livenessModel: {
            model: 'secure-with-abort',
            setupCompletionQuorum: firstProfileSetupCompletionQuorum,
            participantCount: firstProfileParticipantCount,
        },
        dependencyHashes: {
            setupCommitmentSecurityCertificateHash: hashField(
                setupPackage,
                'setupCommitmentSecurityCertificateHash',
                'setupPackage',
            ),
            setupTransportCertificateHash: hashField(
                setupPackage,
                'setupTransportCertificateHash',
                'setupPackage',
            ),
            setupProofAccountingCertificateHash: hashField(
                setupPackage,
                'setupProofAccountingCertificateHash',
                'setupPackage',
            ),
            heSecurityCertificateHash: hashField(
                setupPackage,
                'heSecurityCertificateHash',
                'setupPackage',
            ),
            setupKeyCorrectnessCertificateHash: optionalTopLevelHashValue(
                setupPackage,
                'setupKeyCorrectnessCertificateHash',
            ),
        },
        terminalRoots: {
            thresholdShareCommitmentRoot: optionalTopLevelHashValue(
                setupPackage,
                'thresholdShareCommitmentRoot',
            ),
            sameSecretProofSetRoot: optionalNestedHashValue(
                setupPackage,
                'sameSecretProofs',
                'sameSecretProofSetRoot',
            ),
            publicKeyShareMaterialSetRoot: optionalNestedHashValue(
                setupPackage,
                'publicKeyShareMaterial',
                'publicKeyShareMaterialSetRoot',
            ),
            publicKeyShareSuccinctProofSetRoot: optionalNestedHashValue(
                setupPackage,
                'publicKeyShareSuccinctProofs',
                'publicKeyShareSuccinctProofSetRoot',
            ),
            collectivePublicKeyRoot: optionalNestedHashValue(
                setupPackage,
                'collectivePublicKey',
                'collectivePublicKeyRoot',
            ),
            evaluatorKeyScheduleRoot: optionalNestedHashValue(
                setupPackage,
                'evaluatorKeySchedule',
                'evaluatorKeyScheduleRoot',
            ),
            evaluationKeySetHash: optionalNestedHashValue(
                setupPackage,
                'evaluationKeys',
                'evaluationKeySetHash',
            ),
            publicEvaluationKeyMaterialRoot: optionalNestedHashValue(
                setupPackage,
                'evaluationKeys',
                'publicEvaluationKeyMaterialRoot',
            ),
        },
        claimBoundary: {
            remainingDependencies: [],
            integrationDependencies: [],
        },
    };
};

export const createActiveStaticSetupTheoremCertificate = (
    setupPackage: Readonly<Record<string, unknown>>,
): ActiveStaticSetupTheoremCertificate => {
    const certificateBody =
        activeStaticSetupTheoremCertificateBody(setupPackage);

    return {
        ...certificateBody,
        activeStaticSetupTheoremCertificateHash: deriveProtocolHash(
            'ActiveStaticSetupTheoremCertificateHash',
            certificateBody,
        ),
    };
};
