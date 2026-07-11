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
import { createSetupCertificates } from '../setup-certificates.js';

import { setupCertificateTransportedObjectsFromPackageInput } from './transported-material.js';
import type {
    SetupPackageCertificateRecords,
    SetupPackageInput,
} from './types.js';

export const resolveSetupCertificateRecords = (
    input: SetupPackageInput,
): SetupPackageCertificateRecords => {
    if (input.setupCertificateInput !== undefined) {
        if (input.setupTransportCertificate !== undefined) {
            throw new Error(
                'setupCertificateInput must not be mixed with prebuilt setup certificate records.',
            );
        }

        const transportedObjects =
            setupCertificateTransportedObjectsFromPackageInput(input);

        return createSetupCertificates({
            ...input.setupCertificateInput,
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

    if (input.setupTransportCertificate === undefined) {
        throw new Error(
            'setupCertificateInput or the setup transport certificate record is required.',
        );
    }

    return {
        setupTransportCertificate: input.setupTransportCertificate,
    };
};

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
