// VSS coefficient-commitment bundle assembly: common input validation, the
// per-source-trustee contribution builder and its retained and provider-backed
// opening-material sources, and the embedded bundle constructor.
import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import { createBinaryChunkedVssCoefficientCommitmentMaterialTransport } from './binary-transport.js';
import { computeSetupCommitmentWithKernel } from './commitment-values.js';
import {
    acceptedBgvFullRingDegree,
    type BinaryChunkedVssCoefficientCommitmentBundle,
    type SetupTransportedVssCoefficientCommitmentMaterialReference,
    type StreamingBinaryChunkedVssCoefficientCommitmentBundle,
    type ThresholdShareCommitmentTransportStreamComputer,
    type VssCoefficientCommitmentBundle,
    type VssCoefficientCommitmentBundleInput,
    type VssCoefficientCommitmentMaterialRecord,
    type VssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentRecord,
    type VssCoefficientCommitmentSet,
    type VssCoefficientOpeningMaterial,
    type VssSourceTrusteeCoefficientCommitmentContribution,
    type VssSourceTrusteeCoefficientCommitmentContributionInput,
    type VssSourceTrusteeCoefficientCommitmentContributionOptions,
    type VssSourceTrusteeCoefficientCommitmentRecord,
    type VssSourceTrusteeOpeningMaterial,
    type VssSourceTrusteeOpeningMaterialReference,
    type VssSourceTrusteeOpeningMaterialSource,
} from './constants-and-types.js';
import {
    assertHashLike,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    contextFields,
    setupContextFieldNames,
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
    assertHashLike(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    for (const fieldName of setupContextFieldNames) {
        const value = input.setupContext[fieldName];
        if (typeof value !== 'string' || value.length === 0) {
            throw new TypeError(`setupContext.${fieldName} must be non-empty.`);
        }
    }
};

const createVssSourceTrusteeCoefficientCommitmentContributionWithOptions = (
    input: VssSourceTrusteeCoefficientCommitmentContributionInput,
    options: VssSourceTrusteeCoefficientCommitmentContributionOptions,
): VssSourceTrusteeCoefficientCommitmentContribution => {
    validateCommitmentCommonInput(input);
    const context = contextFields(input.setupContext);
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
        sourceTrusteeState.sourceTrusteeRosterPosition >= input.participantCount
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
    input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
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
            const commitmentComputation = computeSetupCommitmentWithKernel({
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                sourceRnsLimbIndex: rnsLimbIndex,
                sourceMessageModulus: rnsPrime,
                shamirCoefficientIndex,
                messageCoefficients: openingState.coefficientMessage,
                randomnessByColumn: openingState.randomnessByColumn,
                ringDegree: input.ringDegree,
                setupCommitmentComputer: options.setupCommitmentComputer,
            });
            sourceTrusteePrivateOpenings.push({
                ...openingState,
                commitmentRoot: commitmentComputation.commitmentRoot,
            });
            coefficientCommitments.push({
                objectType: 'VssCoefficientCommitment',
                objectVersion: 1,
                ...context,
                sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
                sourceTrusteeRosterPosition:
                    sourceTrusteeState.sourceTrusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex,
                commitmentRoot: commitmentComputation.commitmentRoot,
            });
            const materialRecord = {
                objectType: 'VssCoefficientCommitmentMaterial',
                objectVersion: 1,
                ...context,
                sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
                sourceTrusteeRosterPosition:
                    sourceTrusteeState.sourceTrusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex,
                commitmentRoot: commitmentComputation.commitmentRoot,
                commitment: commitmentComputation.commitment,
            } satisfies VssCoefficientCommitmentMaterialRecord;
            options.consumeMaterialRecord?.(materialRecord);
            if (options.retainMaterialRecords) {
                materialRecords.push(materialRecord);
            }
        }
    });
    const sourceTrusteeRecordWithoutRoot = {
        objectType: 'VssSourceTrusteeCoefficientCommitments',
        objectVersion: 1,
        ...context,
        sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition:
            sourceTrusteeState.sourceTrusteeRosterPosition,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        coefficientCommitments,
    } as const satisfies Omit<
        VssSourceTrusteeCoefficientCommitmentRecord,
        'sourceTrusteeCommitmentRoot'
    >;
    const sourceTrusteeRecord = {
        ...sourceTrusteeRecordWithoutRoot,
        sourceTrusteeCommitmentRoot: deriveCanonicalObjectHash(
            sourceTrusteeRecordWithoutRoot,
        ),
    } satisfies VssSourceTrusteeCoefficientCommitmentRecord;

    return {
        sourceTrusteeRecord,
        materialRecords,
        privateOpeningMaterial: {
            sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                sourceTrusteeState.sourceTrusteeRosterPosition,
            sourceTrusteeCommitmentRoot:
                sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
            sourceTrusteeCoefficientCommitmentRecord: sourceTrusteeRecord,
            sourceTrusteeCoefficientCommitmentMaterialRecords: materialRecords,
            coefficientOpenings: sourceTrusteePrivateOpenings,
        },
    };
};

export const createVssSourceTrusteeCoefficientCommitmentContribution = (
    input: VssSourceTrusteeCoefficientCommitmentContributionInput,
): VssSourceTrusteeCoefficientCommitmentContribution =>
    createVssSourceTrusteeCoefficientCommitmentContributionWithOptions(input, {
        retainMaterialRecords: true,
        setupCommitmentComputer: input.setupCommitmentComputer,
    });

const sourceTrusteeOpeningMaterialReferenceFromMaterial = (
    sourceTrusteeOpeningMaterial: VssSourceTrusteeOpeningMaterial,
): VssSourceTrusteeOpeningMaterialReference => ({
    sourceTrusteeIdentity: sourceTrusteeOpeningMaterial.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition:
        sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
    sourceTrusteeCommitmentRoot:
        sourceTrusteeOpeningMaterial.sourceTrusteeCommitmentRoot,
});

const retainedSourceTrusteeOpeningMaterialSource = (
    privateOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[],
): VssSourceTrusteeOpeningMaterialSource => {
    const materialByRosterPosition = new Map<
        number,
        VssSourceTrusteeOpeningMaterial
    >();
    privateOpeningMaterialBySourceTrustee.forEach(
        (sourceTrusteeOpeningMaterial) => {
            materialByRosterPosition.set(
                sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
                sourceTrusteeOpeningMaterial,
            );
        },
    );

    return {
        sourceTrusteeReferences: privateOpeningMaterialBySourceTrustee.map(
            sourceTrusteeOpeningMaterialReferenceFromMaterial,
        ),
        loadSourceTrusteeOpeningMaterial: (sourceTrusteeReference) => {
            const sourceTrusteeOpeningMaterial = materialByRosterPosition.get(
                sourceTrusteeReference.sourceTrusteeRosterPosition,
            );
            if (sourceTrusteeOpeningMaterial === undefined) {
                throw new Error(
                    'source trustee opening material source is missing the requested roster position.',
                );
            }
            if (
                sourceTrusteeOpeningMaterial.sourceTrusteeIdentity !==
                    sourceTrusteeReference.sourceTrusteeIdentity ||
                sourceTrusteeOpeningMaterial.sourceTrusteeCommitmentRoot !==
                    sourceTrusteeReference.sourceTrusteeCommitmentRoot
            ) {
                throw new Error(
                    'loaded source trustee opening material must match the requested source trustee reference.',
                );
            }

            return sourceTrusteeOpeningMaterial;
        },
    };
};

const sourceTrusteeOpeningMaterialSourceFromProvider = (
    input: VssCoefficientCommitmentBundleInput,
    sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[],
): VssSourceTrusteeOpeningMaterialSource => {
    const sourceTrusteeOpeningStateProvider =
        sourceTrusteeOpeningStateProviderFromInput(input);
    const sourceTrusteeRecordByRosterPosition = new Map<
        number,
        VssSourceTrusteeCoefficientCommitmentRecord
    >();
    sourceTrusteeRecords.forEach((sourceTrusteeRecord) => {
        sourceTrusteeRecordByRosterPosition.set(
            sourceTrusteeRecord.sourceTrusteeRosterPosition,
            sourceTrusteeRecord,
        );
    });
    const sourceTrusteeReferences = sourceTrusteeRecords.map(
        (sourceTrusteeRecord) => ({
            sourceTrusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                sourceTrusteeRecord.sourceTrusteeRosterPosition,
            sourceTrusteeCommitmentRoot:
                sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
        }),
    );

    return {
        sourceTrusteeReferences,
        loadSourceTrusteeOpeningMaterial: (sourceTrusteeReference) => {
            const sourceTrusteeRecord = sourceTrusteeRecordByRosterPosition.get(
                sourceTrusteeReference.sourceTrusteeRosterPosition,
            );
            if (sourceTrusteeRecord === undefined) {
                throw new Error(
                    'source trustee commitment record is missing for the requested opening material.',
                );
            }
            if (
                sourceTrusteeRecord.sourceTrusteeIdentity !==
                    sourceTrusteeReference.sourceTrusteeIdentity ||
                sourceTrusteeRecord.sourceTrusteeCommitmentRoot !==
                    sourceTrusteeReference.sourceTrusteeCommitmentRoot
            ) {
                throw new Error(
                    'source trustee commitment record must match the requested opening material reference.',
                );
            }
            const sourceTrusteeOpeningState = loadSourceTrusteeOpeningState(
                sourceTrusteeOpeningStateProvider,
                sourceTrusteeReference,
            );
            const contribution =
                createVssSourceTrusteeCoefficientCommitmentContributionWithOptions(
                    {
                        setupContext: input.setupContext,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        setupCommitmentComputer: input.setupCommitmentComputer,
                        qSharePrimes: input.qSharePrimes,
                        ringDegree: input.ringDegree,
                        participantCount: input.participantCount,
                        thresholdDegree: input.thresholdDegree,
                        sourceTrusteeOpeningState,
                    },
                    {
                        retainMaterialRecords: true,
                        setupCommitmentComputer: input.setupCommitmentComputer,
                    },
                );
            if (
                contribution.sourceTrusteeRecord.sourceTrusteeCommitmentRoot !==
                sourceTrusteeReference.sourceTrusteeCommitmentRoot
            ) {
                throw new Error(
                    'loaded source trustee opening material must rebuild the accepted source trustee commitment root.',
                );
            }

            return contribution.privateOpeningMaterial;
        },
    };
};

export const createVssCoefficientCommitmentBundle = (
    input: VssCoefficientCommitmentBundleInput,
): VssCoefficientCommitmentBundle => {
    validateCommitmentCommonInput(input);
    const context = contextFields(input.setupContext);
    const sourceTrusteeOpeningStateProvider =
        sourceTrusteeOpeningStateProviderFromInput(input);
    const sortedReferences = sortedSourceTrusteeReferences(
        sourceTrusteeOpeningStateProvider.sourceTrusteeReferences,
    );
    assertFullSourceTrusteeReferenceCoverage(
        sortedReferences,
        input.participantCount,
    );

    const sourceTrusteeContributions = sortedReferences.map(
        (sourceTrusteeReference) =>
            createVssSourceTrusteeCoefficientCommitmentContributionWithOptions(
                {
                    setupContext: input.setupContext,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    setupCommitmentComputer: input.setupCommitmentComputer,
                    qSharePrimes: input.qSharePrimes,
                    ringDegree: input.ringDegree,
                    participantCount: input.participantCount,
                    thresholdDegree: input.thresholdDegree,
                    sourceTrusteeOpeningState: loadSourceTrusteeOpeningState(
                        sourceTrusteeOpeningStateProvider,
                        sourceTrusteeReference,
                    ),
                },
                {
                    retainMaterialRecords: true,
                    setupCommitmentComputer: input.setupCommitmentComputer,
                },
            ),
    );
    const sourceTrusteeRecords = sourceTrusteeContributions.map(
        (contribution) => contribution.sourceTrusteeRecord,
    );
    const coefficientCommitmentMaterial = sourceTrusteeContributions.flatMap(
        (contribution) => contribution.materialRecords,
    );
    const privateOpeningMaterialBySourceTrustee =
        sourceTrusteeContributions.map(
            (contribution) => contribution.privateOpeningMaterial,
        );

    const commitmentSetWithoutRoot = {
        objectType: 'VssCoefficientCommitmentSet',
        objectVersion: 1,
        ...context,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceTrusteeRecords,
    } as const satisfies Omit<
        VssCoefficientCommitmentSet,
        'vssCoefficientCommitmentRoot'
    >;
    const commitmentSet = {
        ...commitmentSetWithoutRoot,
        vssCoefficientCommitmentRoot: deriveCanonicalObjectHash(
            commitmentSetWithoutRoot,
        ),
    } satisfies VssCoefficientCommitmentSet;
    const materialSetWithoutRoot = {
        objectType: 'VssCoefficientCommitmentMaterialSet',
        objectVersion: 1,
        ...context,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot:
            commitmentSet.vssCoefficientCommitmentRoot,
        materialEncoding: 'full-public-setup-commitment-values',
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        ringDegreeStatus:
            input.ringDegree === acceptedBgvFullRingDegree
                ? 'full-ring'
                : 'development-reduced-ring',
        materialRecordCount: coefficientCommitmentMaterial.length,
        coefficientCommitments: coefficientCommitmentMaterial,
    } as const satisfies Omit<
        VssCoefficientCommitmentMaterialSet,
        'vssCoefficientCommitmentMaterialRoot'
    >;
    const materialSet = {
        ...materialSetWithoutRoot,
        vssCoefficientCommitmentMaterialRoot: deriveCanonicalObjectHash(
            materialSetWithoutRoot,
        ),
    } satisfies VssCoefficientCommitmentMaterialSet;

    return {
        commitmentSet,
        materialSet,
        privateOpeningMaterialBySourceTrustee,
        sourceTrusteeOpeningMaterialSource:
            retainedSourceTrusteeOpeningMaterialSource(
                privateOpeningMaterialBySourceTrustee,
            ),
    };
};

const stripMaterialRecordsFromOpeningMaterial = (
    sourceTrusteeOpeningMaterial: VssSourceTrusteeOpeningMaterial,
): VssSourceTrusteeOpeningMaterial => ({
    ...sourceTrusteeOpeningMaterial,
    sourceTrusteeCoefficientCommitmentMaterialRecords: [],
});

const transportedMaterialReference = (
    transportedMaterial: BinaryChunkedVssCoefficientCommitmentBundle['transportedVssCoefficientCommitmentMaterial'],
): SetupTransportedVssCoefficientCommitmentMaterialReference => {
    const { chunks: _chunks, ...reference } = transportedMaterial;

    return reference;
};

export const createBinaryChunkedVssCoefficientCommitmentBundle = (
    input: VssCoefficientCommitmentBundleInput,
): BinaryChunkedVssCoefficientCommitmentBundle => {
    const embeddedBundle = createVssCoefficientCommitmentBundle(input);
    const materialTransport =
        createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
            embeddedBundle.materialSet,
        );
    const privateOpeningMaterialBySourceTrustee =
        input.sourceTrusteeOpeningStateProvider === undefined
            ? embeddedBundle.privateOpeningMaterialBySourceTrustee.map(
                  stripMaterialRecordsFromOpeningMaterial,
              )
            : [];

    return {
        commitmentSet: embeddedBundle.commitmentSet,
        materialSet: materialTransport.materialSet,
        transportedVssCoefficientCommitmentMaterial:
            materialTransport.transportedVssCoefficientCommitmentMaterial,
        privateOpeningMaterialBySourceTrustee,
        sourceTrusteeOpeningMaterialSource:
            input.sourceTrusteeOpeningStateProvider === undefined
                ? retainedSourceTrusteeOpeningMaterialSource(
                      privateOpeningMaterialBySourceTrustee,
                  )
                : sourceTrusteeOpeningMaterialSourceFromProvider(
                      input,
                      embeddedBundle.commitmentSet.sourceTrusteeRecords,
                  ),
    };
};

export const createStreamingBinaryChunkedVssCoefficientCommitmentBundle = (
    input: VssCoefficientCommitmentBundleInput & {
        readonly thresholdShareCommitmentTransportStreamer: ThresholdShareCommitmentTransportStreamComputer;
    },
): StreamingBinaryChunkedVssCoefficientCommitmentBundle => {
    const binaryBundle =
        createBinaryChunkedVssCoefficientCommitmentBundle(input);
    const derivationId =
        binaryBundle.materialSet.vssCoefficientCommitmentMaterialRoot;
    const transportedReference = transportedMaterialReference(
        binaryBundle.transportedVssCoefficientCommitmentMaterial,
    );
    input.thresholdShareCommitmentTransportStreamer.beginThresholdShareCommitmentsFromTransportStream(
        {
            derivationId,
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            transportedVssCoefficientCommitmentMaterial: transportedReference,
        },
    );
    for (const chunk of binaryBundle.transportedVssCoefficientCommitmentMaterial
        .chunks) {
        input.thresholdShareCommitmentTransportStreamer.absorbThresholdShareCommitmentsFromTransportStreamChunk(
            {
                derivationId,
                chunkIndex: chunk.chunkIndex,
                bytesHex: chunk.bytesHex,
            },
        );
    }
    const streamResult =
        input.thresholdShareCommitmentTransportStreamer.finishThresholdShareCommitmentsFromTransportStream(
            {
                derivationId,
                vssCoefficientCommitmentRoot:
                    binaryBundle.commitmentSet.vssCoefficientCommitmentRoot,
                sourceTrusteeCoefficientCommitmentRecords:
                    binaryBundle.commitmentSet.sourceTrusteeRecords,
            },
        );

    return {
        commitmentSet: binaryBundle.commitmentSet,
        materialSet: binaryBundle.materialSet,
        transportedVssCoefficientCommitmentMaterial: transportedReference,
        verifiedVssCoefficientCommitmentMaterial:
            streamResult.verifiedVssCoefficientCommitmentMaterial,
        privateOpeningMaterialBySourceTrustee:
            binaryBundle.privateOpeningMaterialBySourceTrustee,
        sourceTrusteeOpeningMaterialSource:
            binaryBundle.sourceTrusteeOpeningMaterialSource,
        thresholdShareCommitments: streamResult.thresholdShareCommitments,
    };
};
