// VSS coefficient-commitment bundle assembly: common input validation, the
// per-source-trustee contribution builder and its retained and provider-backed
// opening-material sources, and the embedded, binary-chunked, and kernel-streamed
// bundle constructors.
import { deriveProtocolHash } from '@sealed-lattice/crypto';

import {
    buildBinaryVssCoefficientCommitmentMaterialSet,
    createVssBinaryChunkWriter,
    setupTransportedVssCoefficientCommitmentMaterialTemplate,
    transportedVssCoefficientCommitmentMaterialFromChunks,
    transportedVssCoefficientCommitmentMaterialReferenceFromWriterResult,
    writeSetupCommitment,
    writeVssCoefficientCommitmentMaterialHeader,
} from './binary-transport.js';
import { computeSetupCommitmentWithKernel } from './commitment-values.js';
import {
    acceptedBgvFullRingDegree,
    setupTransportChunkSizeBytes,
    type BinaryChunkedVssCoefficientCommitmentBundle,
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
    binaryVssCoefficientCommitmentMaterialByteLength,
    bytesToHex,
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

let vssTransportDerivationCounter = 0;

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
                commitmentChunkRoot: commitmentComputation.commitmentChunkRoot,
                coefficientVectorHash512:
                    commitmentComputation.coefficientVectorHash512,
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
        sourceTrusteeCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
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
        vssCoefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
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
        vssCoefficientCommitmentMaterialRoot: deriveProtocolHash(
            'VssCoefficientCommitmentMaterialRoot',
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

export const createBinaryChunkedVssCoefficientCommitmentBundle = (
    input: VssCoefficientCommitmentBundleInput,
): BinaryChunkedVssCoefficientCommitmentBundle => {
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

    const vssBinaryChunkWriter = createVssBinaryChunkWriter();
    const writer = vssBinaryChunkWriter.writer;
    writeVssCoefficientCommitmentMaterialHeader(writer, {
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
    });

    const sourceTrusteeRecords: VssSourceTrusteeCoefficientCommitmentRecord[] =
        [];
    const privateOpeningMaterialBySourceTrustee: VssSourceTrusteeOpeningMaterial[] =
        [];
    const shouldRetainPrivateOpeningMaterial =
        input.sourceTrusteeOpeningStateProvider === undefined;
    let materialRecordCount = 0;
    sortedReferences.forEach((sourceTrusteeReference) => {
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
                    sourceTrusteeOpeningState: loadSourceTrusteeOpeningState(
                        sourceTrusteeOpeningStateProvider,
                        sourceTrusteeReference,
                    ),
                },
                {
                    retainMaterialRecords: false,
                    setupCommitmentComputer: input.setupCommitmentComputer,
                    consumeMaterialRecord: (materialRecord) => {
                        writeSetupCommitment(writer, materialRecord);
                        materialRecordCount += 1;
                    },
                },
            );
        sourceTrusteeRecords.push(contribution.sourceTrusteeRecord);
        if (shouldRetainPrivateOpeningMaterial) {
            privateOpeningMaterialBySourceTrustee.push(
                contribution.privateOpeningMaterial,
            );
        }
    });

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
        vssCoefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            commitmentSetWithoutRoot,
        ),
    } satisfies VssCoefficientCommitmentSet;

    const writerResult = vssBinaryChunkWriter.finish();
    const chunks = writerResult.chunks;
    const transportedMaterial =
        transportedVssCoefficientCommitmentMaterialFromChunks(chunks);
    const materialSet = buildBinaryVssCoefficientCommitmentMaterialSet({
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot:
            commitmentSet.vssCoefficientCommitmentRoot,
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        materialRecordCount,
        transportHashes: writerResult.transportHashes,
        chunkCount: writerResult.chunkCount,
    });

    return {
        commitmentSet,
        materialSet,
        transportedVssCoefficientCommitmentMaterial: transportedMaterial,
        privateOpeningMaterialBySourceTrustee,
        sourceTrusteeOpeningMaterialSource: shouldRetainPrivateOpeningMaterial
            ? retainedSourceTrusteeOpeningMaterialSource(
                  privateOpeningMaterialBySourceTrustee,
              )
            : sourceTrusteeOpeningMaterialSourceFromProvider(
                  input,
                  sourceTrusteeRecords,
              ),
    };
};

export const createStreamingBinaryChunkedVssCoefficientCommitmentBundle = (
    input: VssCoefficientCommitmentBundleInput &
        Readonly<{
            readonly thresholdShareCommitmentTransportStreamer: ThresholdShareCommitmentTransportStreamComputer;
            readonly derivationId?: string;
        }>,
): StreamingBinaryChunkedVssCoefficientCommitmentBundle => {
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
    const totalByteLength = binaryVssCoefficientCommitmentMaterialByteLength({
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
    });
    const chunkCount = Math.ceil(
        totalByteLength / setupTransportChunkSizeBytes,
    );
    const transportedMaterialTemplate =
        setupTransportedVssCoefficientCommitmentMaterialTemplate({
            chunkCount,
            totalByteLength,
        });
    const derivationId =
        input.derivationId ??
        `vss-transport-${(vssTransportDerivationCounter += 1)}`;
    input.thresholdShareCommitmentTransportStreamer.beginThresholdShareCommitmentsFromTransportStream(
        {
            derivationId,
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            transportedVssCoefficientCommitmentMaterial:
                transportedMaterialTemplate,
        },
    );
    const vssBinaryChunkWriter = createVssBinaryChunkWriter({
        expectedTotalByteLength: totalByteLength,
        retainChunks: false,
        consumeChunk: (chunkIndex, chunk) => {
            input.thresholdShareCommitmentTransportStreamer.absorbThresholdShareCommitmentsFromTransportStreamChunk(
                {
                    derivationId,
                    chunkIndex,
                    bytesHex: bytesToHex(chunk),
                },
            );
        },
    });
    const writer = vssBinaryChunkWriter.writer;
    writeVssCoefficientCommitmentMaterialHeader(writer, {
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
    });

    const sourceTrusteeRecords: VssSourceTrusteeCoefficientCommitmentRecord[] =
        [];
    const privateOpeningMaterialBySourceTrustee: VssSourceTrusteeOpeningMaterial[] =
        [];
    const shouldRetainPrivateOpeningMaterial =
        input.sourceTrusteeOpeningStateProvider === undefined;
    let materialRecordCount = 0;
    sortedReferences.forEach((sourceTrusteeReference) => {
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
                    sourceTrusteeOpeningState: loadSourceTrusteeOpeningState(
                        sourceTrusteeOpeningStateProvider,
                        sourceTrusteeReference,
                    ),
                },
                {
                    retainMaterialRecords: false,
                    setupCommitmentComputer: input.setupCommitmentComputer,
                    consumeMaterialRecord: (materialRecord) => {
                        writeSetupCommitment(writer, materialRecord);
                        materialRecordCount += 1;
                    },
                },
            );
        sourceTrusteeRecords.push(contribution.sourceTrusteeRecord);
        if (shouldRetainPrivateOpeningMaterial) {
            privateOpeningMaterialBySourceTrustee.push(
                contribution.privateOpeningMaterial,
            );
        }
    });

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
        vssCoefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            commitmentSetWithoutRoot,
        ),
    } satisfies VssCoefficientCommitmentSet;
    const writerResult = vssBinaryChunkWriter.finish();
    const transportedMaterialReference =
        transportedVssCoefficientCommitmentMaterialReferenceFromWriterResult(
            writerResult,
        );
    const materialSet = buildBinaryVssCoefficientCommitmentMaterialSet({
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot:
            commitmentSet.vssCoefficientCommitmentRoot,
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        materialRecordCount,
        transportHashes: writerResult.transportHashes,
        chunkCount: writerResult.chunkCount,
    });
    const streamDerivation =
        input.thresholdShareCommitmentTransportStreamer.finishThresholdShareCommitmentsFromTransportStream(
            {
                derivationId,
                vssCoefficientCommitmentRoot:
                    commitmentSet.vssCoefficientCommitmentRoot,
                sourceTrusteeCoefficientCommitmentRecords:
                    commitmentSet.sourceTrusteeRecords,
            },
        );
    const derivedMaterialRoot =
        streamDerivation.vssCoefficientCommitmentMaterial
            .vssCoefficientCommitmentMaterialRoot;
    if (
        derivedMaterialRoot !== materialSet.vssCoefficientCommitmentMaterialRoot
    ) {
        throw new Error(
            'kernel-streamed VSS material root must match the setup package material root.',
        );
    }
    if (
        streamDerivation.thresholdShareCommitments
            .thresholdShareCommitmentRoot !==
        streamDerivation.thresholdShareCommitmentRoot
    ) {
        throw new Error(
            'kernel-streamed threshold-share commitment root must match the returned threshold-share commitments.',
        );
    }

    return {
        commitmentSet,
        materialSet,
        transportedVssCoefficientCommitmentMaterial:
            transportedMaterialReference,
        verifiedVssCoefficientCommitmentMaterial:
            streamDerivation.verifiedVssCoefficientCommitmentMaterial,
        privateOpeningMaterialBySourceTrustee,
        sourceTrusteeOpeningMaterialSource: shouldRetainPrivateOpeningMaterial
            ? retainedSourceTrusteeOpeningMaterialSource(
                  privateOpeningMaterialBySourceTrustee,
              )
            : sourceTrusteeOpeningMaterialSourceFromProvider(
                  input,
                  sourceTrusteeRecords,
              ),
        thresholdShareCommitments: streamDerivation.thresholdShareCommitments,
    };
};
