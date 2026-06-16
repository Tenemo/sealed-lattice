// Per-source-trustee VSS coefficient opening-state generation and the provider
// indirection: reference sorting and full-coverage checks, the coordinate index
// over a trustee opening state, and the deterministic opening-state and
// opening-state-provider constructors.
import {
    type VssCoefficientCommitmentBundleInput,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
    type VssSourceTrusteeCoefficientOpeningStateGenerationInput,
    type VssSourceTrusteeCoefficientOpeningStateProvider,
    type VssSourceTrusteeCoefficientOpeningStateProviderInput,
    type VssSourceTrusteeCoefficientOpeningStateReference,
} from './constants-and-types.js';
import {
    RandomByteSampler,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertRandomness,
    assertResidueVector,
    centeredIntegerToResidue,
    defaultRandomBytes,
    sampleCenteredTernaryVector,
    sampleCommitmentOpeningRandomness,
    sampleUniformResidueVector,
} from './encoding.js';

const sourceTrusteeReferenceFromOpeningState = (
    sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState,
): VssSourceTrusteeCoefficientOpeningStateReference => ({
    sourceTrusteeIdentity: sourceTrusteeOpeningState.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition:
        sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
});

export const sortedSourceTrusteeReferences = (
    sourceTrusteeReferences: readonly VssSourceTrusteeCoefficientOpeningStateReference[],
): VssSourceTrusteeCoefficientOpeningStateReference[] =>
    [...sourceTrusteeReferences].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );

export const assertFullSourceTrusteeReferenceCoverage = (
    sourceTrusteeReferences: readonly VssSourceTrusteeCoefficientOpeningStateReference[],
    participantCount: number,
): void => {
    if (sourceTrusteeReferences.length !== participantCount) {
        throw new Error(
            'source trustee opening references must contain every accepted participant.',
        );
    }
    sourceTrusteeReferences.forEach(
        (sourceTrusteeReference, expectedRosterPosition) => {
            if (
                sourceTrusteeReference.sourceTrusteeRosterPosition !==
                expectedRosterPosition
            ) {
                throw new Error(
                    'source trustee opening reference roster positions must be contiguous from zero.',
                );
            }
            assertNonEmptyString(
                sourceTrusteeReference.sourceTrusteeIdentity,
                'sourceTrusteeIdentity',
            );
        },
    );
};

export const sourceTrusteeOpeningStateProviderFromInput = (
    input: Pick<
        VssCoefficientCommitmentBundleInput,
        'sourceTrusteeOpeningStateProvider' | 'sourceTrusteeOpeningStates'
    >,
): VssSourceTrusteeCoefficientOpeningStateProvider => {
    if (
        input.sourceTrusteeOpeningStates !== undefined &&
        input.sourceTrusteeOpeningStateProvider !== undefined
    ) {
        throw new Error(
            'provide sourceTrusteeOpeningStates or sourceTrusteeOpeningStateProvider, not both.',
        );
    }
    if (input.sourceTrusteeOpeningStateProvider !== undefined) {
        return input.sourceTrusteeOpeningStateProvider;
    }
    if (input.sourceTrusteeOpeningStates === undefined) {
        throw new Error(
            'sourceTrusteeOpeningStates or sourceTrusteeOpeningStateProvider is required.',
        );
    }

    const sourceTrusteeStatesByRosterPosition = new Map<
        number,
        VssSourceTrusteeCoefficientOpeningState
    >();
    input.sourceTrusteeOpeningStates.forEach((sourceTrusteeOpeningState) => {
        sourceTrusteeStatesByRosterPosition.set(
            sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
            sourceTrusteeOpeningState,
        );
    });

    return {
        sourceTrusteeReferences: input.sourceTrusteeOpeningStates.map(
            sourceTrusteeReferenceFromOpeningState,
        ),
        loadSourceTrusteeOpeningState: (sourceTrusteeReference) => {
            const sourceTrusteeOpeningState =
                sourceTrusteeStatesByRosterPosition.get(
                    sourceTrusteeReference.sourceTrusteeRosterPosition,
                );
            if (sourceTrusteeOpeningState === undefined) {
                throw new Error(
                    'source trustee opening provider is missing the requested roster position.',
                );
            }

            return sourceTrusteeOpeningState;
        },
    };
};

export const loadSourceTrusteeOpeningState = (
    sourceTrusteeOpeningStateProvider: VssSourceTrusteeCoefficientOpeningStateProvider,
    sourceTrusteeReference: VssSourceTrusteeCoefficientOpeningStateReference,
): VssSourceTrusteeCoefficientOpeningState => {
    const sourceTrusteeOpeningState =
        sourceTrusteeOpeningStateProvider.loadSourceTrusteeOpeningState(
            sourceTrusteeReference,
        );
    if (
        sourceTrusteeOpeningState.sourceTrusteeIdentity !==
            sourceTrusteeReference.sourceTrusteeIdentity ||
        sourceTrusteeOpeningState.sourceTrusteeRosterPosition !==
            sourceTrusteeReference.sourceTrusteeRosterPosition
    ) {
        throw new Error(
            'loaded source trustee opening state must match the requested source trustee reference.',
        );
    }

    return sourceTrusteeOpeningState;
};

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
            if (openingState.rnsPrime !== expectedPrime) {
                throw new Error(
                    'coefficient opening rnsPrime must match Q_share at rnsLimbIndex.',
                );
            }
            if (openingState.shamirCoefficientIndex >= thresholdDegree) {
                throw new Error(
                    'coefficient opening shamirCoefficientIndex is outside thresholdDegree.',
                );
            }
            assertResidueVector(
                openingState.coefficientMessage,
                openingState.rnsPrime,
                ringDegree,
                `coefficientOpenings.${String(openingIndex)}.coefficientMessage`,
            );
            assertRandomness(
                openingState.randomnessByColumn,
                ringDegree,
                `coefficientOpenings.${String(openingIndex)}.randomnessByColumn`,
            );
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
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
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

    const sampler = new RandomByteSampler(
        input.randomBytes ?? defaultRandomBytes,
    );
    const shortSecretCoefficients = sampleCenteredTernaryVector(
        sampler,
        input.ringDegree,
    );
    const coefficientOpenings = input.qSharePrimes.flatMap(
        (rnsPrime, rnsLimbIndex) =>
            Array.from(
                { length: input.thresholdDegree },
                (_unused, shamirCoefficientIndex) => ({
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex,
                    coefficientMessage:
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
                    randomnessByColumn: sampleCommitmentOpeningRandomness(
                        sampler,
                        input.ringDegree,
                    ),
                }),
            ),
    );

    return {
        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        coefficientOpenings,
    };
};

export const createVssSourceTrusteeCoefficientOpeningStateProvider = (
    input: VssSourceTrusteeCoefficientOpeningStateProviderInput,
): VssSourceTrusteeCoefficientOpeningStateProvider => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    const sourceTrusteeReferences = input.sourceTrustees.map(
        (sourceTrusteeReference) => {
            assertNonEmptyString(
                sourceTrusteeReference.sourceTrusteeIdentity,
                'sourceTrusteeIdentity',
            );
            assertNonNegativeSafeInteger(
                sourceTrusteeReference.sourceTrusteeRosterPosition,
                'sourceTrusteeRosterPosition',
            );
            if (
                sourceTrusteeReference.sourceTrusteeRosterPosition >=
                input.participantCount
            ) {
                throw new Error(
                    'sourceTrusteeRosterPosition must be inside the accepted participant count.',
                );
            }

            return sourceTrusteeReference;
        },
    );
    const sortedReferences = sortedSourceTrusteeReferences(
        sourceTrusteeReferences,
    );
    assertFullSourceTrusteeReferenceCoverage(
        sortedReferences,
        input.participantCount,
    );

    return {
        sourceTrusteeReferences,
        loadSourceTrusteeOpeningState: (sourceTrusteeReference) =>
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity:
                    sourceTrusteeReference.sourceTrusteeIdentity,
                sourceTrusteeRosterPosition:
                    sourceTrusteeReference.sourceTrusteeRosterPosition,
                participantCount: input.participantCount,
                qSharePrimes: input.qSharePrimes,
                ringDegree: input.ringDegree,
                thresholdDegree: input.thresholdDegree,
                randomBytes: input.randomBytesForSourceTrustee(
                    sourceTrusteeReference,
                ),
            }),
    };
};
