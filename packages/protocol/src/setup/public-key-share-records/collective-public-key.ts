import { deriveProtocolHash } from '@sealed-lattice/crypto';

import { setupProofProfileId } from '../same-secret-consistency-records.js';

import { transportedPublicKeyShareMaterialReader } from './binary-material-transport.js';
import {
    publicKeyShareMaterialEncoding,
    publicKeyShareProofFamily,
    type CollectivePublicKey,
    type CollectivePublicKeyCoefficientVectorMaterial,
    type CollectivePublicKeyInput,
    type CollectivePublicKeySourceBindingInput,
    type CollectivePublicKeySourceShareMaterialRoot,
    type PublicKeyShareCoefficientVectorMaterial,
    type PublicKeyShareMaterialRecord,
    type PublicKeyShareMaterialRootReference,
    type TransportedCollectivePublicKeyInput,
} from './constants-and-types.js';
import {
    assertContextMatches,
    assertPositiveSafeInteger,
    coefficientVectorFromLittleEndianHex,
    coefficientVectorHash512,
    coefficientVectorToLittleEndianHex,
    contextFields,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';

const assertCollectivePublicKeySourceBindings = (
    input: CollectivePublicKeySourceBindingInput,
): void => {
    validateCommonInput(input);
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareSuccinctProofs,
        'publicKeyShareSuccinctProofs',
    );
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot ||
        input.publicKeyShares.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareSuccinctProofs.sameSecretProofSetRoot !==
            input.sameSecretProofs.sameSecretProofSetRoot ||
        input.publicKeyShareSuccinctProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareSuccinctProofs.publicKeyShareProofSetRoot !==
            input.publicKeyShareProofs.publicKeyShareProofSetRoot ||
        input.publicKeyShareSuccinctProofs.publicKeyShareMaterialSetRoot !==
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot
    ) {
        throw new Error(
            'collective public key sources must bind the accepted public-key proof chain.',
        );
    }
    if (
        input.publicKeyShareMaterial.participantCount !==
            input.participantCount ||
        input.publicKeyShareMaterial.rnsLimbCount !==
            input.qSharePrimes.length ||
        input.publicKeyShareMaterial.ringDegree !== input.ringDegree ||
        input.publicKeyShareMaterial.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.publicKeyShareMaterial.publicKeyCrpRoot !==
            input.publicKeyCrpRoot ||
        input.publicKeyShareMaterial.publicAPolynomialRoot !==
            input.publicAPolynomialRoot
    ) {
        throw new Error(
            'publicKeyShareMaterial must bind the collective public-key profile and common randomness.',
        );
    }
};

const createCollectivePublicKeyFromAggregateCoefficients = (
    input: CollectivePublicKeySourceBindingInput & {
        readonly sourceShareMaterialRoots: readonly CollectivePublicKeySourceShareMaterialRoot[];
        readonly aggregateCoefficientsByLimb: readonly (readonly number[])[];
    },
): CollectivePublicKey => {
    const aggregateCoefficientVectorsByLimb =
        input.aggregateCoefficientsByLimb.map((coefficients, rnsLimbIndex) => {
            const rnsPrime = input.qSharePrimes[rnsLimbIndex];
            if (rnsPrime === undefined) {
                throw new Error('Q_share prime is missing for aggregate limb.');
            }

            return {
                rnsLimbIndex,
                rnsPrime,
                component: 'b',
                coefficientByteLength: input.ringDegree * 8,
                coefficientVectorHash512:
                    coefficientVectorHash512(coefficients),
                coefficientsLeHex:
                    coefficientVectorToLittleEndianHex(coefficients),
            } as const satisfies CollectivePublicKeyCoefficientVectorMaterial;
        });
    const collectivePublicKeyWithoutRoot = {
        objectType: 'CollectivePublicKey',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        materialEncoding: 'embedded-full-collective-public-key-coefficients',
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofSetRoot:
            input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        publicKeyShareMaterialSetRoot:
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        publicKeyShareSuccinctProofSetRoot:
            input.publicKeyShareSuccinctProofs
                .publicKeyShareSuccinctProofSetRoot,
        sourceShareMaterialRoots: input.sourceShareMaterialRoots,
        aggregateCoefficientVectorsByLimb,
    } as const satisfies Omit<CollectivePublicKey, 'collectivePublicKeyRoot'>;

    return {
        ...collectivePublicKeyWithoutRoot,
        collectivePublicKeyRoot: deriveProtocolHash(
            'CollectivePublicKeyRoot',
            collectivePublicKeyWithoutRoot,
        ),
    } satisfies CollectivePublicKey;
};

export const createCollectivePublicKey = (
    input: CollectivePublicKeyInput,
): CollectivePublicKey => {
    assertCollectivePublicKeySourceBindings(input);
    const materialRecords = sortedByRosterPosition(
        input.publicKeyShareMaterial.shareMaterialRecords,
    );
    if (materialRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterial must contain one material record per participant.',
        );
    }
    const aggregateCoefficientsByLimb = input.qSharePrimes.map(() =>
        Array.from({ length: input.ringDegree }, () => 0),
    );
    const sourceShareMaterialRoots = materialRecords.map(
        (materialRecord, expectedRosterPosition) => {
            if (
                materialRecord.trusteeRosterPosition !==
                    expectedRosterPosition ||
                materialRecord.rnsLimbCount !== input.qSharePrimes.length ||
                materialRecord.ringDegree !== input.ringDegree ||
                materialRecord.shareCoefficientVectorsByLimb.length !==
                    input.qSharePrimes.length
            ) {
                throw new Error(
                    'publicKeyShareMaterial records must match the collective public-key profile.',
                );
            }
            materialRecord.shareCoefficientVectorsByLimb.forEach(
                (coefficientVector, rnsLimbIndex) => {
                    const rnsPrime = input.qSharePrimes[rnsLimbIndex];
                    const aggregateCoefficients =
                        aggregateCoefficientsByLimb[rnsLimbIndex];
                    if (
                        rnsPrime === undefined ||
                        aggregateCoefficients === undefined ||
                        coefficientVector.rnsLimbIndex !== rnsLimbIndex ||
                        coefficientVector.rnsPrime !== rnsPrime ||
                        coefficientVector.component !== 'b_i' ||
                        coefficientVector.coefficientByteLength !==
                            input.ringDegree * 8
                    ) {
                        throw new Error(
                            'publicKeyShareMaterial coefficient vector metadata must match Q_share order.',
                        );
                    }
                    const coefficients = coefficientVectorFromLittleEndianHex(
                        coefficientVector.coefficientsLeHex,
                        input.ringDegree,
                        'publicKeyShareMaterial.shareCoefficientVectorsByLimb.coefficientsLeHex',
                    );
                    if (
                        coefficients.some(
                            (coefficient) => coefficient >= rnsPrime,
                        ) ||
                        coefficientVector.coefficientVectorHash512 !==
                            coefficientVectorHash512(coefficients)
                    ) {
                        throw new Error(
                            'publicKeyShareMaterial coefficient vectors must be canonical and hash-bound.',
                        );
                    }
                    coefficients.forEach((coefficient, coefficientIndex) => {
                        aggregateCoefficients[coefficientIndex] =
                            (aggregateCoefficients[coefficientIndex] +
                                coefficient) %
                            rnsPrime;
                    });
                },
            );

            return {
                trusteeIdentity: materialRecord.trusteeIdentity,
                trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                publicKeyShareRoot: materialRecord.publicKeyShareRoot,
                publicKeyShareMaterialRoot:
                    materialRecord.publicKeyShareMaterialRoot,
            };
        },
    );
    return createCollectivePublicKeyFromAggregateCoefficients({
        ...input,
        sourceShareMaterialRoots,
        aggregateCoefficientsByLimb,
    });
};

export const createCollectivePublicKeyFromTransportedPublicKeyShareMaterial = (
    input: TransportedCollectivePublicKeyInput,
): CollectivePublicKey => {
    assertCollectivePublicKeySourceBindings(input);
    const { reader, shareRecords } = transportedPublicKeyShareMaterialReader({
        setupContext: input.setupContext,
        publicKeyShares: input.publicKeyShares,
        materialSet: input.publicKeyShareMaterial,
        transportedPublicKeyShareMaterial:
            input.transportedPublicKeyShareMaterial,
    });
    const aggregateCoefficientsByLimb = input.qSharePrimes.map(() =>
        Array.from({ length: input.ringDegree }, () => 0),
    );
    const materialRootReferences: PublicKeyShareMaterialRootReference[] = [];
    const sourceShareMaterialRoots: CollectivePublicKeySourceShareMaterialRoot[] =
        [];
    for (
        let expectedRosterPosition = 0;
        expectedRosterPosition < input.publicKeyShareMaterial.participantCount;
        expectedRosterPosition += 1
    ) {
        if (
            reader.readVaruint('trusteeRosterPosition') !==
            expectedRosterPosition
        ) {
            throw new Error(
                'transported public-key share material trustee order is not canonical.',
            );
        }
        const shareRecord = shareRecords.get(expectedRosterPosition);
        if (shareRecord === undefined) {
            throw new Error(
                'transported public-key share material must reference an accepted share record.',
            );
        }
        const shareCoefficientVectorsByLimb =
            shareRecord.shareCoefficientVectorHash512ByLimb.map(
                (shareCoefficientHash, rnsLimbIndex) => {
                    if (reader.readVaruint('rnsLimbIndex') !== rnsLimbIndex) {
                        throw new Error(
                            'transported public-key share material RNS limb order is not canonical.',
                        );
                    }
                    const rnsPrime = reader.readU64('rnsPrime');
                    const aggregateCoefficients =
                        aggregateCoefficientsByLimb[rnsLimbIndex];
                    if (
                        aggregateCoefficients === undefined ||
                        shareCoefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                        shareCoefficientHash.rnsPrime !== rnsPrime ||
                        shareCoefficientHash.component !== 'b_i'
                    ) {
                        throw new Error(
                            'transported public-key share material limb metadata must match publicKeyShares.',
                        );
                    }
                    const coefficients = Array.from(
                        { length: input.publicKeyShareMaterial.ringDegree },
                        () => {
                            const coefficient = reader.readU64(
                                'public-key share coefficient',
                            );
                            if (coefficient >= rnsPrime) {
                                throw new Error(
                                    'transported public-key share coefficient is not a canonical residue.',
                                );
                            }

                            return coefficient;
                        },
                    );
                    const coefficientVectorHash =
                        coefficientVectorHash512(coefficients);
                    if (
                        shareCoefficientHash.coefficientVectorHash512 !==
                        coefficientVectorHash
                    ) {
                        throw new Error(
                            'transported public-key share coefficient hash must match publicKeyShares.',
                        );
                    }
                    coefficients.forEach((coefficient, coefficientIndex) => {
                        aggregateCoefficients[coefficientIndex] =
                            (aggregateCoefficients[coefficientIndex] +
                                coefficient) %
                            rnsPrime;
                    });

                    return {
                        rnsLimbIndex,
                        rnsPrime,
                        component: 'b_i',
                        coefficientByteLength:
                            input.publicKeyShareMaterial.ringDegree * 8,
                        coefficientVectorHash512: coefficientVectorHash,
                        coefficientsLeHex:
                            coefficientVectorToLittleEndianHex(coefficients),
                    } as const satisfies PublicKeyShareCoefficientVectorMaterial;
                },
            );
        const materialRecordWithoutRoot = {
            objectType: 'PublicKeyShareMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: publicKeyShareProofFamily,
            materialEncoding: publicKeyShareMaterialEncoding,
            ...contextFields(input.setupContext),
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            rnsLimbCount: input.publicKeyShareMaterial.rnsLimbCount,
            ringDegree: input.publicKeyShareMaterial.ringDegree,
            publicMatrixSeedHash:
                input.publicKeyShareMaterial.publicMatrixSeedHash,
            publicKeyCrpRoot: input.publicKeyShareMaterial.publicKeyCrpRoot,
            publicAPolynomialRoot:
                input.publicKeyShareMaterial.publicAPolynomialRoot,
            publicKeyShareRoot: shareRecord.publicKeyShareRoot,
            shareCoefficientVectorsByLimb,
        } as const satisfies Omit<
            PublicKeyShareMaterialRecord,
            'publicKeyShareMaterialRoot'
        >;
        const publicKeyShareMaterialRoot = deriveProtocolHash(
            'PublicKeyShareRoot',
            materialRecordWithoutRoot,
        );
        materialRootReferences.push({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            publicKeyShareMaterialRoot,
        });
        sourceShareMaterialRoots.push({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            publicKeyShareRoot: shareRecord.publicKeyShareRoot,
            publicKeyShareMaterialRoot,
        });
    }
    if (!reader.isFinished()) {
        throw new Error(
            'transported public-key share material has trailing bytes.',
        );
    }
    if (
        JSON.stringify(materialRootReferences) !==
        JSON.stringify(input.publicKeyShareMaterial.publicKeyShareMaterialRoots)
    ) {
        throw new Error(
            'transported public-key share material roots must match material set references.',
        );
    }

    return createCollectivePublicKeyFromAggregateCoefficients({
        ...input,
        sourceShareMaterialRoots,
        aggregateCoefficientsByLimb,
    });
};
