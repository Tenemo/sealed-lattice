import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import {
    type VssCoefficientCommitmentBundle,
    type VssCoefficientCommitmentBundleInput,
    type VssCoefficientCommitmentMaterialRecord,
    type VssCoefficientCommitmentRecord,
    type VssCoefficientCommitmentSet,
    type VssCoefficientOpeningMaterial,
    type VssSourceTrusteeCoefficientCommitmentContributionInput,
    type VssSourceTrusteeCoefficientCommitmentRecord,
    type VssSourceTrusteeOpeningMaterial,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    deriveCollectiveBgvSetupContextHash,
} from './encoding.js';
import {
    assertFullSourceTrusteeReferenceCoverage,
    loadSourceTrusteeOpeningState,
    openingCoordinateKey,
    openingStateByCoordinate,
    sortedSourceTrusteeReferences,
    sourceTrusteeOpeningStateProviderFromInput,
} from './opening-state.js';

const validateCommitmentCommonInput = (
    input: Omit<
        VssCoefficientCommitmentBundleInput,
        'sourceTrusteeOpeningStates'
    >,
): void => {
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(
        input.setupContext.participantCount,
        'setupContext.participantCount',
    );
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
};

const createVssSourceTrusteeCoefficientCommitmentContribution = (
    input: VssSourceTrusteeCoefficientCommitmentContributionInput,
): VssSourceTrusteeOpeningMaterial => {
    validateCommitmentCommonInput(input);
    const sourceTrusteeState = input.sourceTrusteeOpeningState;
    assertNonEmptyString(
        sourceTrusteeState.sourceTrusteeIdentity,
        'sourceTrusteeIdentity',
    );
    assertNonNegativeSafeInteger(
        sourceTrusteeState.sourceTrusteeRosterPosition,
        'sourceTrusteeRosterPosition',
    );
    if (
        sourceTrusteeState.sourceTrusteeRosterPosition >=
        input.setupContext.participantCount
    ) {
        throw new Error(
            'sourceTrusteeRosterPosition must be inside the accepted participant count.',
        );
    }
    const openingsByCoordinate = openingStateByCoordinate(
        sourceTrusteeState,
        input.qSharePrimes,
        input.ringDegree,
        input.thresholdDegree,
    );
    const materialRecords: VssCoefficientCommitmentMaterialRecord[] = [];
    const coefficientCommitments: VssCoefficientCommitmentRecord[] = [];
    const sourceTrusteePrivateOpenings: VssCoefficientOpeningMaterial[] = [];
    input.qSharePrimes.forEach((_rnsPrime, rnsLimbIndex) => {
        for (
            let shamirCoefficientIndex = 0;
            shamirCoefficientIndex < input.thresholdDegree;
            shamirCoefficientIndex += 1
        ) {
            const openingState = openingsByCoordinate.get(
                openingCoordinateKey(rnsLimbIndex, shamirCoefficientIndex),
            );
            if (openingState === undefined) {
                throw new Error(
                    'source trustee coefficientOpenings must cover every declared coordinate.',
                );
            }
            const commitmentComputation = input.setupCommitmentComputer({
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                sourceRnsLimbIndex: rnsLimbIndex,
                shamirCoefficientIndex,
                messageCoefficients: openingState.coefficientMessage,
                randomnessByColumn: openingState.randomnessByColumn,
                ringDegree: input.ringDegree,
            });
            const commitmentRoot = deriveCanonicalObjectHash(
                commitmentComputation.commitment,
            );
            sourceTrusteePrivateOpenings.push({
                ...openingState,
                commitmentRoot,
            });
            coefficientCommitments.push({
                objectType: 'VssCoefficientCommitment',
                commitmentRoot,
            });
            const materialRecord = {
                objectType: 'VssCoefficientCommitmentMaterial',
                commitment: commitmentComputation.commitment,
            } satisfies VssCoefficientCommitmentMaterialRecord;
            materialRecords.push(materialRecord);
        }
    });
    const sourceTrusteeRecord = {
        objectType: 'VssSourceTrusteeCoefficientCommitments',
        sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition:
            sourceTrusteeState.sourceTrusteeRosterPosition,
        coefficientCommitments,
    } as const satisfies VssSourceTrusteeCoefficientCommitmentRecord;

    return {
        sourceTrusteeCoefficientCommitmentRecord: sourceTrusteeRecord,
        sourceTrusteeCoefficientCommitmentMaterialRecords: materialRecords,
        coefficientOpenings: sourceTrusteePrivateOpenings,
    };
};

export const createVssCoefficientCommitmentBundle = (
    input: VssCoefficientCommitmentBundleInput,
): VssCoefficientCommitmentBundle => {
    validateCommitmentCommonInput(input);
    const setupContextHash = deriveCollectiveBgvSetupContextHash(
        input.setupContext,
    );
    const sourceTrusteeOpeningStateProvider =
        sourceTrusteeOpeningStateProviderFromInput(input);
    const sortedReferences = sortedSourceTrusteeReferences(
        sourceTrusteeOpeningStateProvider.sourceTrusteeReferences,
    );
    assertFullSourceTrusteeReferenceCoverage(
        sortedReferences,
        input.setupContext.participantCount,
    );

    const sourceTrusteeContributions = sortedReferences.map(
        (sourceTrusteeReference) =>
            createVssSourceTrusteeCoefficientCommitmentContribution({
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                setupCommitmentComputer: input.setupCommitmentComputer,
                qSharePrimes: input.qSharePrimes,
                ringDegree: input.ringDegree,
                thresholdDegree: input.thresholdDegree,
                sourceTrusteeOpeningState: loadSourceTrusteeOpeningState(
                    sourceTrusteeOpeningStateProvider,
                    sourceTrusteeReference,
                ),
            }),
    );
    const sourceTrusteeRecords = sourceTrusteeContributions.map(
        (contribution) => contribution.sourceTrusteeCoefficientCommitmentRecord,
    );
    const privateOpeningMaterialBySourceTrustee = sourceTrusteeContributions;

    const commitmentSet = {
        objectType: 'VssCoefficientCommitmentSet',
        setupContextHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceTrusteeRecords,
    } as const satisfies VssCoefficientCommitmentSet;
    return {
        commitmentSet,
        privateOpeningMaterialBySourceTrustee,
    };
};
