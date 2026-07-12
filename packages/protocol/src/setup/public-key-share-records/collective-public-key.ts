import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import { aggregateTransportedPublicKeyShareMaterial } from './binary-material-transport.js';
import {
    publicKeyShareProofFamily,
    type CollectivePublicKey,
    type CollectivePublicKeyCoefficientVectorMaterial,
    type CollectivePublicKeyInput,
    type CollectivePublicKeySourceBindingInput,
    type CollectivePublicKeySourceShareMaterialRoot,
    type PublicKeyShareMaterialRecord,
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
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
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
            'publicKeyShareMaterial must bind the collective public-key parameters and common randomness.',
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
        proofFamily: publicKeyShareProofFamily,
        materialEncoding: 'embedded-full-collective-public-key-coefficients',
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
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
        collectivePublicKeyRoot: deriveCanonicalObjectHash(
            collectivePublicKeyWithoutRoot,
        ),
    } satisfies CollectivePublicKey;
};

const createCollectivePublicKeyFromMaterialRecords = (
    input: CollectivePublicKeySourceBindingInput,
    materialRecords: readonly PublicKeyShareMaterialRecord[],
): CollectivePublicKey => {
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
                    'publicKeyShareMaterial records must match the collective public-key parameters.',
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

export const createCollectivePublicKey = (
    input: CollectivePublicKeyInput,
): CollectivePublicKey => {
    assertCollectivePublicKeySourceBindings(input);

    return createCollectivePublicKeyFromMaterialRecords(
        input,
        sortedByRosterPosition(
            input.publicKeyShareMaterial.shareMaterialRecords,
        ),
    );
};

export const createCollectivePublicKeyFromTransportedPublicKeyShareMaterial =
    async (
        input: TransportedCollectivePublicKeyInput,
    ): Promise<CollectivePublicKey> => {
        assertCollectivePublicKeySourceBindings(input);

        const aggregate = await aggregateTransportedPublicKeyShareMaterial({
            setupContext: input.setupContext,
            publicKeyShares: input.publicKeyShares,
            materialSet: input.publicKeyShareMaterial,
            publicKeyShareMaterialChunkSource:
                input.publicKeyShareMaterialChunkSource,
        });

        return createCollectivePublicKeyFromAggregateCoefficients({
            ...input,
            ...aggregate,
        });
    };
