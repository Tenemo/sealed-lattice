import { requireFoundationRosterParameters } from '../common-fields.js';

import {
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
    type VssSourceTrusteeCoefficientOpeningStateGenerationInput,
} from './constants-and-types.js';
import {
    RandomByteSampler,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    assertResidueVector,
    centeredIntegerToResidue,
    sampleCenteredTernaryVector,
    sampleUniformResidueVector,
    webCryptoRandomBytes,
} from './encoding.js';

class CoefficientOpeningCleanupError extends Error {
    public readonly cleanupFailures: readonly unknown[];
    public readonly operationFailure: unknown;

    public constructor(
        operationFailure: unknown,
        cleanupFailures: readonly unknown[],
    ) {
        super(
            'Coefficient-opening generation failed and worker-owned openings could not all be released.',
        );
        this.name = 'CoefficientOpeningCleanupError';
        this.operationFailure = operationFailure;
        this.cleanupFailures = Object.freeze([...cleanupFailures]);
    }
}

export const openingCoordinateKey = (
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): string => `${String(rnsLimbIndex)}:${String(shamirCoefficientIndex)}`;

export const openingStateByCoordinate = (
    sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    qSharePrimes: readonly number[],
    ringDegree: number,
    thresholdDegree: number,
): ReadonlyMap<string, VssCoefficientOpeningInput> => {
    const expectedOpeningCount = qSharePrimes.length * thresholdDegree;
    if (
        sourceTrusteeState.coefficientOpenings.length !== expectedOpeningCount
    ) {
        throw new Error(
            'source trustee coefficientOpenings must cover every Q_share limb and Shamir coefficient.',
        );
    }
    const openingsByCoordinate = new Map<string, VssCoefficientOpeningInput>();
    sourceTrusteeState.coefficientOpenings.forEach(
        (openingState, openingIndex) => {
            assertNonNegativeSafeInteger(
                openingState.rnsLimbIndex,
                `coefficientOpenings.${String(openingIndex)}.rnsLimbIndex`,
            );
            assertNonNegativeSafeInteger(
                openingState.shamirCoefficientIndex,
                `coefficientOpenings.${String(openingIndex)}.shamirCoefficientIndex`,
            );
            const expectedPrime = qSharePrimes[openingState.rnsLimbIndex];
            if (expectedPrime === undefined) {
                throw new Error(
                    'coefficient opening rnsLimbIndex is outside Q_share.',
                );
            }
            if (openingState.shamirCoefficientIndex >= thresholdDegree) {
                throw new Error(
                    'coefficient opening shamirCoefficientIndex is outside thresholdDegree.',
                );
            }
            assertResidueVector(
                openingState.coefficientMessage,
                expectedPrime,
                ringDegree,
                `coefficientOpenings.${String(openingIndex)}.coefficientMessage`,
            );
            if (
                typeof openingState.openingCapability !== 'object' ||
                openingState.openingCapability === null
            ) {
                throw new Error(
                    'coefficient opening must carry an opaque worker-owned opening capability.',
                );
            }
            const coordinateKey = openingCoordinateKey(
                openingState.rnsLimbIndex,
                openingState.shamirCoefficientIndex,
            );
            if (openingsByCoordinate.has(coordinateKey)) {
                throw new Error(
                    'source trustee coefficientOpenings must have distinct limb/coefficient coordinates.',
                );
            }
            openingsByCoordinate.set(coordinateKey, openingState);
        },
    );

    return openingsByCoordinate;
};

export const createVssSourceTrusteeCoefficientOpeningState = (
    input: VssSourceTrusteeCoefficientOpeningStateGenerationInput,
): VssSourceTrusteeCoefficientOpeningState => {
    assertNonEmptyString(input.sourceTrusteeIdentity, 'sourceTrusteeIdentity');
    assertNonNegativeSafeInteger(
        input.sourceTrusteeRosterPosition,
        'sourceTrusteeRosterPosition',
    );
    const rosterParameters = requireFoundationRosterParameters(
        input.participantCount,
        'participantCount',
    );
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    if (input.thresholdDegree !== rosterParameters.reconstructionThreshold) {
        throw new RangeError(
            `thresholdDegree must equal ${String(rosterParameters.reconstructionThreshold)} for participantCount.`,
        );
    }
    assertProtocolHash(
        input.sourceSetupIntentObjectHash,
        'sourceSetupIntentObjectHash',
    );
    if (input.sourceTrusteeRosterPosition >= input.participantCount) {
        throw new Error(
            'sourceTrusteeRosterPosition must be inside the accepted participant count.',
        );
    }
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });

    const sampler = new RandomByteSampler(webCryptoRandomBytes);
    const shortSecretCoefficients = sampleCenteredTernaryVector(
        sampler,
        input.ringDegree,
    );
    const coefficientOpenings: VssCoefficientOpeningInput[] = [];
    const createdCapabilities: VssCoefficientOpeningInput['openingCapability'][] =
        [];
    try {
        input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
            for (
                let shamirCoefficientIndex = 0;
                shamirCoefficientIndex < input.thresholdDegree;
                shamirCoefficientIndex += 1
            ) {
                const openingCapability =
                    input.structuredCommitmentOpenings.create({
                        shamirCoefficientIndex,
                        sourceRnsLimbIndex: rnsLimbIndex,
                        sourceRosterPosition: input.sourceTrusteeRosterPosition,
                        sourceSetupIntentObjectHash:
                            input.sourceSetupIntentObjectHash,
                    });
                createdCapabilities.push(openingCapability);
                coefficientOpenings.push(
                    Object.freeze({
                        coefficientMessage: Object.freeze(
                            shamirCoefficientIndex === 0
                                ? shortSecretCoefficients.map((coefficient) =>
                                      centeredIntegerToResidue(
                                          coefficient,
                                          rnsPrime,
                                      ),
                                  )
                                : sampleUniformResidueVector(
                                      sampler,
                                      rnsPrime,
                                      input.ringDegree,
                                  ),
                        ),
                        openingCapability,
                        rnsLimbIndex,
                        shamirCoefficientIndex,
                    }),
                );
            }
        });
    } catch (operationFailure) {
        const cleanupFailures: unknown[] = [];
        for (const capability of createdCapabilities.reverse()) {
            try {
                input.structuredCommitmentOpenings.release(capability);
            } catch (cleanupFailure) {
                cleanupFailures.push(cleanupFailure);
            }
        }
        if (cleanupFailures.length !== 0) {
            throw new CoefficientOpeningCleanupError(
                operationFailure,
                cleanupFailures,
            );
        }
        throw operationFailure;
    }

    return Object.freeze({
        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        coefficientOpenings: Object.freeze(coefficientOpenings),
    });
};
