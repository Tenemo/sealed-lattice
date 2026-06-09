import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    computeSetupCommitmentFromOpening,
    createBinaryChunkedVssCoefficientCommitmentBundle,
    createBinaryChunkedVssCoefficientCommitmentMaterialTransport,
    createStreamingBinaryChunkedVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientOpeningState,
    createVssSourceTrusteeCoefficientOpeningStateProvider,
    createVssSourceTrusteeCoefficientCommitmentContribution,
    createVssCoefficientCommitmentBundle,
    deriveThresholdShareCommitments,
    materialRecordsFromTransportedVssCoefficientCommitmentMaterial,
    setupTransportChunkSizeBytes,
    setupCommitmentRandomnessWidth,
    setupCommitmentRootPayload,
    vssCoefficientCommitmentMaterialBinaryFormat,
    type CollectiveBgvSetupContext,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
    type VssOpeningRandomByteSource,
} from '#packages/protocol/src/index';

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-vss-coefficient-commitments',
        label,
    });

const deterministicRandomBytes = (
    seedLabel: string,
): VssOpeningRandomByteSource => {
    const textEncoder = new TextEncoder();
    let blockIndex = 0;
    let bufferedBytes = new Uint8Array(0);
    let bufferedOffset = 0;

    return (byteLength) => {
        const outputBytes = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < byteLength) {
            if (bufferedOffset >= bufferedBytes.byteLength) {
                const blockHex = deriveProtocolHash('ActionContextHash', {
                    fixture: 'setup-vss-coefficient-commitments',
                    seedLabel,
                    blockIndex,
                });
                bufferedBytes = textEncoder.encode(blockHex);
                bufferedOffset = 0;
                blockIndex += 1;
            }
            const copyLength = Math.min(
                byteLength - outputOffset,
                bufferedBytes.byteLength - bufferedOffset,
            );
            outputBytes.set(
                bufferedBytes.subarray(
                    bufferedOffset,
                    bufferedOffset + copyLength,
                ),
                outputOffset,
            );
            bufferedOffset += copyLength;
            outputOffset += copyLength;
        }

        return outputBytes;
    };
};

const setupContext = {
    ceremonyId: 'ceremony-1',
    manifestHash: fixtureHash('manifest'),
    rosterHash: fixtureHash('roster'),
    setupProfileHash: fixtureHash('setup-profile'),
    qShareHash: fixtureHash('q-share'),
    carryAwareVssShareRelationProfileHash: fixtureHash(
        'carry-aware-vss-share-relation-profile',
    ),
    commitmentProfileHash: fixtureHash('commitment-profile'),
    setupEpoch: 'setup-epoch-1',
} satisfies CollectiveBgvSetupContext;

const coefficientMessage = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    rnsPrime: number,
): number[] =>
    Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        const value =
            (sourceTrusteeRosterPosition + 1) * 19 +
            (rnsLimbIndex + 1) * 7 +
            (shamirCoefficientIndex + 1) * 5 +
            coefficientIndex;

        return value % rnsPrime;
    });

const randomnessByColumn = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): number[][] =>
    Array.from({ length: 5 }, (_unusedColumn, randomnessColumnIndex) =>
        Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
            const selector =
                (sourceTrusteeRosterPosition +
                    rnsLimbIndex +
                    shamirCoefficientIndex +
                    randomnessColumnIndex +
                    coefficientIndex) %
                3;

            return selector === 0 ? -1 : selector === 1 ? 0 : 1;
        }),
    );

const opening = (
    sourceTrusteeRosterPosition: number,
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => ({
    rnsLimbIndex,
    rnsPrime,
    shamirCoefficientIndex,
    coefficientMessage: coefficientMessage(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        rnsPrime,
    ),
    randomnessByColumn: randomnessByColumn(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
    ),
});

const sourceTrusteeOpeningState = (
    sourceTrusteeRosterPosition: number,
): VssSourceTrusteeCoefficientOpeningState => ({
    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
    sourceTrusteeRosterPosition,
    coefficientOpenings: qSharePrimes.flatMap((rnsPrime, rnsLimbIndex) =>
        Array.from({ length: thresholdDegree }, (_unused, coefficientIndex) =>
            opening(
                sourceTrusteeRosterPosition,
                rnsPrime,
                rnsLimbIndex,
                coefficientIndex,
            ),
        ),
    ),
});

const requiredOpening = (
    sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    openingIndex: number,
): VssCoefficientOpeningInput => {
    const openingState = sourceTrusteeState.coefficientOpenings[openingIndex];
    if (openingState === undefined) {
        throw new Error('fixture opening is missing');
    }

    return openingState;
};

const requiredRandomnessColumn = (
    openingState: VssCoefficientOpeningInput,
    randomnessColumnIndex: number,
): readonly number[] => {
    const randomnessColumn =
        openingState.randomnessByColumn[randomnessColumnIndex];
    if (randomnessColumn === undefined) {
        throw new Error('fixture randomness column is missing');
    }

    return randomnessColumn;
};

const requiredOpeningByCoordinate = (
    sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => {
    const openingState = sourceTrusteeState.coefficientOpenings.find(
        (candidateOpening) =>
            candidateOpening.rnsLimbIndex === rnsLimbIndex &&
            candidateOpening.shamirCoefficientIndex === shamirCoefficientIndex,
    );
    if (openingState === undefined) {
        throw new Error('fixture opening coordinate is missing');
    }

    return openingState;
};

const decodeShortSecretResidues = (
    openingState: VssCoefficientOpeningInput,
): readonly (-1 | 0 | 1)[] =>
    openingState.coefficientMessage.map((coefficient) => {
        if (coefficient === 0) {
            return 0;
        }
        if (coefficient === 1) {
            return 1;
        }
        if (coefficient === openingState.rnsPrime - 1) {
            return -1;
        }
        throw new Error(
            'constant Shamir coefficient is not a centered ternary residue',
        );
    });

describe('VSS coefficient commitment builders', () => {
    it('generates local openings with one short secret shared across RNS limbs', () => {
        const generatedSourceTrusteeState =
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytes: deterministicRandomBytes('trustee-0'),
            });
        const constantSecretForFirstLimb = decodeShortSecretResidues(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0),
        );
        const constantSecretForSecondLimb = decodeShortSecretResidues(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 1, 0),
        );
        const nonConstantOpening = requiredOpeningByCoordinate(
            generatedSourceTrusteeState,
            0,
            1,
        );
        const firstRandomnessColumn = requiredRandomnessColumn(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0),
            0,
        );
        const contribution =
            createVssSourceTrusteeCoefficientCommitmentContribution({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningState: generatedSourceTrusteeState,
            });

        expect(generatedSourceTrusteeState.coefficientOpenings).toHaveLength(
            qSharePrimes.length * thresholdDegree,
        );
        expect(constantSecretForSecondLimb).toEqual(constantSecretForFirstLimb);
        expect(
            nonConstantOpening.coefficientMessage.every(
                (coefficient) =>
                    coefficient >= 0 &&
                    coefficient < nonConstantOpening.rnsPrime,
            ),
        ).toBe(true);
        expect(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0)
                .randomnessByColumn,
        ).toHaveLength(setupCommitmentRandomnessWidth);
        expect(
            firstRandomnessColumn.every(
                (coefficient) =>
                    coefficient === -1 ||
                    coefficient === 0 ||
                    coefficient === 1,
            ),
        ).toBe(true);
        expect(
            contribution.privateOpeningMaterial.coefficientOpenings[0]
                ?.commitmentRoot,
        ).toMatch(/^[0-9a-f]{128}$/u);
    });

    it('loads deterministic source openings through a provider without retained binary material', () => {
        const sourceTrusteeReferences = [
            {
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
            },
            {
                sourceTrusteeIdentity: 'trustee-1',
                sourceTrusteeRosterPosition: 1,
            },
        ] as const;
        const sourceTrusteeOpeningStateProvider =
            createVssSourceTrusteeCoefficientOpeningStateProvider({
                sourceTrustees: sourceTrusteeReferences,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytesForSourceTrustee: (sourceTrusteeReference) =>
                    deterministicRandomBytes(
                        `provider-${sourceTrusteeReference.sourceTrusteeIdentity}`,
                    ),
            });

        expect(
            sourceTrusteeOpeningStateProvider.loadSourceTrusteeOpeningState(
                sourceTrusteeReferences[0],
            ),
        ).toEqual(
            sourceTrusteeOpeningStateProvider.loadSourceTrusteeOpeningState(
                sourceTrusteeReferences[0],
            ),
        );

        const bundle = createBinaryChunkedVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStateProvider,
        });
        const firstSourceTrusteeRecord =
            bundle.commitmentSet.sourceTrusteeRecords[0];
        if (firstSourceTrusteeRecord === undefined) {
            throw new Error('Expected first source trustee record.');
        }

        expect(bundle.privateOpeningMaterialBySourceTrustee).toEqual([]);
        expect(
            bundle.sourceTrusteeOpeningMaterialSource.loadSourceTrusteeOpeningMaterial(
                {
                    sourceTrusteeIdentity:
                        firstSourceTrusteeRecord.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        firstSourceTrusteeRecord.sourceTrusteeRosterPosition,
                    sourceTrusteeCommitmentRoot:
                        firstSourceTrusteeRecord.sourceTrusteeCommitmentRoot,
                },
            ).sourceTrusteeCoefficientCommitmentRecord,
        ).toEqual(firstSourceTrusteeRecord);
        expect(() =>
            createVssSourceTrusteeCoefficientOpeningStateProvider({
                sourceTrustees: [
                    sourceTrusteeReferences[0],
                    sourceTrusteeReferences[0],
                ],
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytesForSourceTrustee: () =>
                    deterministicRandomBytes('duplicate-source'),
            }),
        ).toThrow(/contiguous from zero/u);
    });

    it('creates deterministic root-bound commitment material from local openings', () => {
        const bundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates: [
                sourceTrusteeOpeningState(1),
                sourceTrusteeOpeningState(0),
            ],
        });
        const { vssCoefficientCommitmentRoot, ...commitmentSetWithoutRoot } =
            bundle.commitmentSet;
        const {
            vssCoefficientCommitmentMaterialRoot,
            ...materialSetWithoutRoot
        } = bundle.materialSet;
        const firstMaterialRecord =
            bundle.materialSet.coefficientCommitments[0];
        const firstOpening = requiredOpening(sourceTrusteeOpeningState(0), 0);
        const firstSourceTrusteeContribution =
            createVssSourceTrusteeCoefficientCommitmentContribution({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningState: sourceTrusteeOpeningState(0),
            });

        expect(
            bundle.commitmentSet.sourceTrusteeRecords.map(
                (record) => record.sourceTrusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(bundle.materialSet.materialRecordCount).toBe(
            participantCount * qSharePrimes.length * thresholdDegree,
        );
        expect(vssCoefficientCommitmentRoot).toBe(
            deriveProtocolHash(
                'VssCoefficientCommitmentRoot',
                commitmentSetWithoutRoot,
            ),
        );
        expect(vssCoefficientCommitmentMaterialRoot).toBe(
            deriveProtocolHash(
                'VssCoefficientCommitmentMaterialRoot',
                materialSetWithoutRoot,
            ),
        );
        expect(firstMaterialRecord?.commitmentRoot).toBe(
            deriveProtocolHash(
                'SetupCommitmentRoot',
                setupCommitmentRootPayload(
                    computeSetupCommitmentFromOpening({
                        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                        qSharePrimes,
                        sourceRnsLimbIndex: firstOpening.rnsLimbIndex,
                        sourceMessageModulus: firstOpening.rnsPrime,
                        shamirCoefficientIndex:
                            firstOpening.shamirCoefficientIndex,
                        messageCoefficients: firstOpening.coefficientMessage,
                        randomnessByColumn: firstOpening.randomnessByColumn,
                        ringDegree,
                    }),
                ),
            ),
        );
        expect(
            bundle.privateOpeningMaterialBySourceTrustee[0]
                ?.coefficientOpenings[0]?.commitmentRoot,
        ).toBe(firstMaterialRecord?.commitmentRoot);
        expect(firstSourceTrusteeContribution.sourceTrusteeRecord).toEqual(
            bundle.commitmentSet.sourceTrusteeRecords[0],
        );
        expect(firstSourceTrusteeContribution.materialRecords).toEqual(
            bundle.materialSet.coefficientCommitments.slice(
                0,
                qSharePrimes.length * thresholdDegree,
            ),
        );
        expect(
            bundle.commitmentSet.sourceTrusteeRecords[0]
                ?.coefficientCommitments[0]?.coefficientVectorHash512,
        ).toMatch(/^[0-9a-f]{128}$/u);
    });

    it('builds binary-chunked transport for public coefficient material', () => {
        const bundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates: [0, 1].map((rosterPosition) =>
                sourceTrusteeOpeningState(rosterPosition),
            ),
        });
        const transport =
            createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
                bundle.materialSet,
            );
        const {
            vssCoefficientCommitmentMaterialRoot,
            ...materialSetWithoutRoot
        } = transport.materialSet;
        const reconstructedMaterialRecords =
            materialRecordsFromTransportedVssCoefficientCommitmentMaterial({
                setupContext,
                vssCoefficientCommitments: bundle.commitmentSet,
                materialSet: transport.materialSet,
                transportedVssCoefficientCommitmentMaterial:
                    transport.transportedVssCoefficientCommitmentMaterial,
            });

        expect(transport.materialSet).toMatchObject({
            objectType: 'VssCoefficientCommitmentMaterialSet',
            setupProfileId: 'CollectiveBgvSetup-v1',
            materialEncoding:
                'binary-chunked-full-public-setup-commitment-values',
            binaryFormat: vssCoefficientCommitmentMaterialBinaryFormat,
            materialRecordCount: bundle.materialSet.materialRecordCount,
            transport: {
                transportProfileId:
                    'sealed-lattice-setup-binary-chunked-transport-v1',
                chunkSizeBytes: setupTransportChunkSizeBytes,
                chunkCount:
                    transport.transportedVssCoefficientCommitmentMaterial
                        .chunkCount,
                fullObjectHash:
                    transport.transportedVssCoefficientCommitmentMaterial
                        .fullObjectHash,
                chunkRoot:
                    transport.transportedVssCoefficientCommitmentMaterial
                        .chunkRoot,
            },
        });
        expect(transport.materialSet).not.toHaveProperty(
            'coefficientCommitments',
        );
        expect(vssCoefficientCommitmentMaterialRoot).toBe(
            deriveProtocolHash(
                'VssCoefficientCommitmentMaterialRoot',
                materialSetWithoutRoot,
            ),
        );
        expect(
            transport.transportedVssCoefficientCommitmentMaterial,
        ).toMatchObject({
            objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
            binaryFormat: vssCoefficientCommitmentMaterialBinaryFormat,
            chunkSizeBytes: setupTransportChunkSizeBytes,
        });
        expect(
            transport.transportedVssCoefficientCommitmentMaterial.chunks,
        ).toHaveLength(
            transport.transportedVssCoefficientCommitmentMaterial.chunkCount,
        );
        expect(reconstructedMaterialRecords).toEqual(
            bundle.materialSet.coefficientCommitments,
        );
    });

    it('builds direct binary-chunked commitment material without an embedded material set', () => {
        const sourceTrusteeOpeningStates = [0, 1].map((rosterPosition) =>
            sourceTrusteeOpeningState(rosterPosition),
        );
        const embeddedBundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates,
        });
        const embeddedTransport =
            createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
                embeddedBundle.materialSet,
            );
        const directBundle = createBinaryChunkedVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates,
        });
        const reconstructedMaterialRecords =
            materialRecordsFromTransportedVssCoefficientCommitmentMaterial({
                setupContext,
                vssCoefficientCommitments: directBundle.commitmentSet,
                materialSet: directBundle.materialSet,
                transportedVssCoefficientCommitmentMaterial:
                    directBundle.transportedVssCoefficientCommitmentMaterial,
            });

        expect(directBundle.commitmentSet).toEqual(
            embeddedBundle.commitmentSet,
        );
        expect(directBundle.materialSet).toEqual(embeddedTransport.materialSet);
        expect(directBundle.materialSet).not.toHaveProperty(
            'coefficientCommitments',
        );
        expect(
            directBundle.transportedVssCoefficientCommitmentMaterial,
        ).toEqual(
            embeddedTransport.transportedVssCoefficientCommitmentMaterial,
        );
        expect(reconstructedMaterialRecords).toEqual(
            embeddedBundle.materialSet.coefficientCommitments,
        );
        expect(
            directBundle.privateOpeningMaterialBySourceTrustee.map(
                (sourceMaterial) =>
                    sourceMaterial.sourceTrusteeCoefficientCommitmentMaterialRecords,
            ),
        ).toEqual([[], []]);
        expect(
            directBundle.privateOpeningMaterialBySourceTrustee.map(
                ({
                    sourceTrusteeCoefficientCommitmentMaterialRecords:
                        _materialRecords,
                    ...sourceMaterialWithoutRecords
                }) => sourceMaterialWithoutRecords,
            ),
        ).toEqual(
            embeddedBundle.privateOpeningMaterialBySourceTrustee.map(
                ({
                    sourceTrusteeCoefficientCommitmentMaterialRecords:
                        _materialRecords,
                    ...sourceMaterialWithoutRecords
                }) => sourceMaterialWithoutRecords,
            ),
        );
    });

    it('streams direct binary-chunked commitment material without returning chunks', () => {
        const sourceTrusteeOpeningStates = [0, 1].map((rosterPosition) =>
            sourceTrusteeOpeningState(rosterPosition),
        );
        const bundleInput = {
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates,
        };
        const retainedBundle =
            createBinaryChunkedVssCoefficientCommitmentBundle(bundleInput);
        const capturedChunks: { chunkIndex: number; bytesHex: string }[] = [];
        const streamer = {
            beginThresholdShareCommitmentsFromTransportStream: (input: {
                readonly transportedVssCoefficientCommitmentMaterial: {
                    readonly chunkCount: number;
                    readonly totalByteLength: number;
                };
            }) => {
                expect(
                    input.transportedVssCoefficientCommitmentMaterial
                        .chunkCount,
                ).toBe(
                    retainedBundle.transportedVssCoefficientCommitmentMaterial
                        .chunkCount,
                );
                expect(
                    input.transportedVssCoefficientCommitmentMaterial
                        .totalByteLength,
                ).toBe(
                    retainedBundle.transportedVssCoefficientCommitmentMaterial
                        .totalByteLength,
                );

                return { ok: true };
            },
            absorbThresholdShareCommitmentsFromTransportStreamChunk: (input: {
                readonly chunkIndex: number;
                readonly bytesHex: string;
            }) => {
                capturedChunks.push({
                    chunkIndex: input.chunkIndex,
                    bytesHex: input.bytesHex,
                });

                return { ok: true };
            },
            finishThresholdShareCommitmentsFromTransportStream: () => {
                expect(capturedChunks).toEqual(
                    retainedBundle.transportedVssCoefficientCommitmentMaterial
                        .chunks,
                );
                const thresholdShareCommitments =
                    deriveThresholdShareCommitments({
                        setupContext,
                        vssCoefficientCommitments: retainedBundle.commitmentSet,
                        vssCoefficientCommitmentMaterial:
                            retainedBundle.materialSet,
                        transportedVssCoefficientCommitmentMaterial: {
                            ...retainedBundle.transportedVssCoefficientCommitmentMaterial,
                            chunks: capturedChunks,
                        },
                    });

                return {
                    thresholdShareCommitmentRoot:
                        thresholdShareCommitments.thresholdShareCommitmentRoot,
                    thresholdShareCommitments,
                    vssCoefficientCommitmentMaterial:
                        retainedBundle.materialSet,
                    verifiedVssCoefficientCommitmentMaterial: {
                        objectType: 'VerifiedVssCoefficientCommitmentMaterial',
                        objectVersion: 1,
                        setupProfileId: 'CollectiveBgvSetup-v1',
                        verificationId: 'vss-transport-1',
                        materialBinaryFormat:
                            'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
                        publicMatrixSeedHash:
                            retainedBundle.materialSet.publicMatrixSeedHash,
                        vssCoefficientCommitmentRoot:
                            retainedBundle.commitmentSet
                                .vssCoefficientCommitmentRoot,
                        vssCoefficientCommitmentMaterialRoot:
                            retainedBundle.materialSet
                                .vssCoefficientCommitmentMaterialRoot,
                        thresholdShareCommitmentRoot:
                            thresholdShareCommitments.thresholdShareCommitmentRoot,
                        transportProfileId:
                            'sealed-lattice-setup-binary-chunked-transport-v1',
                        transportChunkSizeBytes: 1_048_576,
                        transportChunkCount:
                            retainedBundle
                                .transportedVssCoefficientCommitmentMaterial
                                .chunkCount,
                        transportTotalByteLength:
                            retainedBundle
                                .transportedVssCoefficientCommitmentMaterial
                                .totalByteLength,
                        transportFullObjectHash:
                            retainedBundle
                                .transportedVssCoefficientCommitmentMaterial
                                .fullObjectHash,
                        transportChunkRoot:
                            retainedBundle
                                .transportedVssCoefficientCommitmentMaterial
                                .chunkRoot,
                    } as const,
                    transport: {
                        fullObjectHash:
                            retainedBundle
                                .transportedVssCoefficientCommitmentMaterial
                                .fullObjectHash,
                    },
                };
            },
        };

        const streamingBundle =
            createStreamingBinaryChunkedVssCoefficientCommitmentBundle({
                ...bundleInput,
                thresholdShareCommitmentTransportStreamer: streamer,
            });
        const { chunks: _chunks, ...retainedTransportReference } =
            retainedBundle.transportedVssCoefficientCommitmentMaterial;

        expect(streamingBundle.commitmentSet).toEqual(
            retainedBundle.commitmentSet,
        );
        expect(streamingBundle.materialSet).toEqual(retainedBundle.materialSet);
        expect(
            streamingBundle.transportedVssCoefficientCommitmentMaterial,
        ).toEqual(retainedTransportReference);
        expect(
            streamingBundle.transportedVssCoefficientCommitmentMaterial,
        ).not.toHaveProperty('chunks');
        expect(streamingBundle.thresholdShareCommitments).toEqual(
            deriveThresholdShareCommitments({
                setupContext,
                vssCoefficientCommitments: retainedBundle.commitmentSet,
                vssCoefficientCommitmentMaterial: retainedBundle.materialSet,
                transportedVssCoefficientCommitmentMaterial:
                    retainedBundle.transportedVssCoefficientCommitmentMaterial,
            }),
        );
        expect(
            streamingBundle.verifiedVssCoefficientCommitmentMaterial.objectType,
        ).toBe('VerifiedVssCoefficientCommitmentMaterial');
    });

    it('rejects tampered binary coefficient material before reconstruction', () => {
        const bundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates: [0, 1].map((rosterPosition) =>
                sourceTrusteeOpeningState(rosterPosition),
            ),
        });
        const transport =
            createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
                bundle.materialSet,
            );
        const firstChunk =
            transport.transportedVssCoefficientCommitmentMaterial.chunks[0];
        if (firstChunk === undefined) {
            throw new Error('transport fixture did not create a chunk');
        }
        const tamperedTransportedMaterial = {
            ...transport.transportedVssCoefficientCommitmentMaterial,
            chunks: [
                {
                    ...firstChunk,
                    bytesHex: `00${firstChunk.bytesHex.slice(2)}`,
                },
                ...transport.transportedVssCoefficientCommitmentMaterial.chunks.slice(
                    1,
                ),
            ],
        };

        expect(() =>
            materialRecordsFromTransportedVssCoefficientCommitmentMaterial({
                setupContext,
                vssCoefficientCommitments: bundle.commitmentSet,
                materialSet: transport.materialSet,
                transportedVssCoefficientCommitmentMaterial:
                    tamperedTransportedMaterial,
            }),
        ).toThrow(/fullObjectHash|chunkHashes|chunkRoot/u);
    });

    it('rejects malformed local opening state before root publication', () => {
        const firstSourceTrustee = sourceTrusteeOpeningState(0);
        const secondSourceTrustee = sourceTrusteeOpeningState(1);

        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningStates: [firstSourceTrustee],
            }),
        ).toThrow(/every accepted participant/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningStates: [
                    {
                        ...firstSourceTrustee,
                        coefficientOpenings: [
                            requiredOpening(firstSourceTrustee, 0),
                            requiredOpening(firstSourceTrustee, 0),
                            ...firstSourceTrustee.coefficientOpenings.slice(2),
                        ],
                    },
                    secondSourceTrustee,
                ],
            }),
        ).toThrow(/distinct limb\/coefficient coordinates/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningStates: [
                    {
                        ...firstSourceTrustee,
                        coefficientOpenings: [
                            {
                                ...requiredOpening(firstSourceTrustee, 0),
                                coefficientMessage: [
                                    qSharePrimes[0],
                                    ...requiredOpening(
                                        firstSourceTrustee,
                                        0,
                                    ).coefficientMessage.slice(1),
                                ],
                            },
                            ...firstSourceTrustee.coefficientOpenings.slice(1),
                        ],
                    },
                    secondSourceTrustee,
                ],
            }),
        ).toThrow(/residue below the declared modulus/u);
        expect(() =>
            createVssCoefficientCommitmentBundle({
                setupContext,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                qSharePrimes,
                ringDegree,
                participantCount,
                thresholdDegree,
                sourceTrusteeOpeningStates: [
                    {
                        ...firstSourceTrustee,
                        coefficientOpenings: [
                            {
                                ...requiredOpening(firstSourceTrustee, 0),
                                randomnessByColumn: [
                                    [
                                        2,
                                        ...requiredRandomnessColumn(
                                            requiredOpening(
                                                firstSourceTrustee,
                                                0,
                                            ),
                                            0,
                                        ).slice(1),
                                    ],
                                    ...requiredOpening(
                                        firstSourceTrustee,
                                        0,
                                    ).randomnessByColumn.slice(1),
                                ],
                            },
                            ...firstSourceTrustee.coefficientOpenings.slice(1),
                        ],
                    },
                    secondSourceTrustee,
                ],
            }),
        ).toThrow(/centered ternary/u);
        expect(() =>
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity: 'trustee-2',
                sourceTrusteeRosterPosition: 2,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytes: deterministicRandomBytes('trustee-2'),
            }),
        ).toThrow(/inside the accepted participant count/u);
        expect(() =>
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
                participantCount,
                qSharePrimes: [],
                ringDegree,
                thresholdDegree,
                randomBytes: deterministicRandomBytes('trustee-0'),
            }),
        ).toThrow(/at least one RNS prime/u);
        expect(() =>
            createVssSourceTrusteeCoefficientOpeningState({
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                randomBytes: (byteLength) =>
                    new Uint8Array(Math.max(0, byteLength - 1)),
            }),
        ).toThrow(/exactly the requested byte length/u);
    });
});
