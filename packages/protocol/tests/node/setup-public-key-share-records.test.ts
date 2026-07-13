import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createBinaryChunkedPublicKeyShareMaterialBundle,
    createPublicKeyShareSet,
    createPublicKeyShareSuccinctProofSet,
    publicKeyShareCoefficientVectorHashDomain,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareSet,
    type PublicKeyShareSuccinctProofSetInput,
} from '#packages/protocol/src/index';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const ringDegree = 8;
const participantCount = 2;

const fixtureHash = makeSetupFixtureHash('setup-public-key-share-records');

const setupContext = makeSetupContext(fixtureHash, participantCount);
const setupContextHash = deriveCanonicalObjectHash({
    objectType: 'CollectiveBgvSetupContext',
    ...setupContext,
});

const shareContribution = (
    trusteeRosterPosition: number,
): PublicKeyShareContributionInput => ({
    trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
    trusteeRosterPosition,
    shareCoefficientVectorHash512ByLimb: qSharePrimes.map(
        (_unusedRnsPrime, rnsLimbIndex) => ({
            coefficientVectorHash512: fixtureHash(
                `share-coefficient-${String(trusteeRosterPosition)}-${String(
                    rnsLimbIndex,
                )}`,
            ),
        }),
    ),
});

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    const view = new DataView(bytes.buffer);
    coefficients.forEach((coefficient, coefficientIndex) => {
        view.setBigUint64(coefficientIndex * 8, BigInt(coefficient), true);
    });

    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const coefficientVectorLeHex = (coefficients: readonly number[]): string =>
    bytesToHex(coefficientVectorBytes(coefficients));

const publicKeyShareCoefficientVectorHash = (
    coefficients: readonly number[],
): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

const shareMaterialCoefficients = (
    trusteeRosterPosition: number,
    rnsLimbIndex: number,
    rnsPrime: number,
): readonly number[] =>
    Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        const value =
            (trusteeRosterPosition + 1) * 83 +
            (rnsLimbIndex + 1) * 31 +
            coefficientIndex * 17;

        return value % rnsPrime;
    });

const shareMaterialContribution = (
    trusteeRosterPosition: number,
): PublicKeyShareMaterialContributionInput => ({
    trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
    trusteeRosterPosition,
    shareCoefficientVectorsByLimb: qSharePrimes.map(
        (rnsPrime, rnsLimbIndex) => {
            const coefficients = shareMaterialCoefficients(
                trusteeRosterPosition,
                rnsLimbIndex,
                rnsPrime,
            );

            return {
                coefficientsLeHex: coefficientVectorLeHex(coefficients),
            };
        },
    ),
});

const shareContributionFromMaterial = (
    contribution: PublicKeyShareMaterialContributionInput,
): PublicKeyShareContributionInput => ({
    trusteeIdentity: contribution.trusteeIdentity,
    trusteeRosterPosition: contribution.trusteeRosterPosition,
    shareCoefficientVectorHash512ByLimb:
        contribution.shareCoefficientVectorsByLimb.map(
            (_unusedCoefficientVector, rnsLimbIndex) => {
                const rnsPrime = qSharePrimes[rnsLimbIndex];
                if (rnsPrime === undefined) {
                    throw new Error('Expected the selected Q_share prime.');
                }

                return {
                    coefficientVectorHash512:
                        publicKeyShareCoefficientVectorHash(
                            shareMaterialCoefficients(
                                contribution.trusteeRosterPosition,
                                rnsLimbIndex,
                                rnsPrime,
                            ),
                        ),
                };
            },
        ),
});

const createShareSet = (): PublicKeyShareSet =>
    createPublicKeyShareSet({
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        shareContributions: [shareContribution(1), shareContribution(0)],
    });

const createSuccinctProofFixture = (): PublicKeyShareSuccinctProofSetInput => {
    const materialContributions = [
        shareMaterialContribution(0),
        shareMaterialContribution(1),
    ] as const;
    const commonInput = {
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
    } as const;
    const publicKeyShares = createPublicKeyShareSet({
        ...commonInput,
        shareContributions: materialContributions.map(
            shareContributionFromMaterial,
        ),
    });
    const publicKeyShareMaterialRootReferences =
        publicKeyShares.shareRecords.map((shareRecord) => ({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            publicKeyShareMaterialRoot: fixtureHash(
                `public-key-share-material-${String(
                    shareRecord.trusteeRosterPosition,
                )}`,
            ),
        }));
    const publicKeyShareMaterialRoots =
        publicKeyShareMaterialRootReferences.map(
            (reference) => reference.publicKeyShareMaterialRoot,
        );
    const publicKeyShareMaterial = {
        objectType: 'PublicKeyShareMaterialSet',
        publicKeyShareMaterialRoots,
        publicKeyShareMaterialSetRoot: deriveCanonicalObjectHash({
            objectType: 'PublicKeyShareMaterialSet',
            setupContextHash,
            ringDegree,
            publicMatrixSeedHash: commonInput.publicMatrixSeedHash,
            publicKeyShareSetRoot: publicKeyShares.publicKeyShareSetRoot,
            publicKeyShareMaterialRoots: publicKeyShareMaterialRootReferences,
        }),
    } as const;
    const statementRecords = publicKeyShares.shareRecords.map(
        (shareRecord) => ({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            sameSecretBridgeStatementRoot: fixtureHash(
                `bridge-statement-${String(shareRecord.trusteeRosterPosition)}`,
            ),
        }),
    );
    const sameSecretBridgeStatementSet = {
        objectType: 'VssSameSecretBridgeStatementSet',
        setupContextHash,
        participantCount,
        publicMatrixSeedHash: commonInput.publicMatrixSeedHash,
        statementRecords,
    } as unknown as PublicKeyShareSuccinctProofSetInput['sameSecretBridgeStatementSet'];
    const sameSecretBridgeProofMaterialSet = {
        objectType: 'VssSameSecretBridgeProofMaterialSet',
        proofRecords: statementRecords.map((statementRecord) => ({
            sameSecretBridgeStatementRoot:
                statementRecord.sameSecretBridgeStatementRoot,
            sameSecretBridgeProofRecordRoot: fixtureHash(
                `bridge-proof-${String(statementRecord.trusteeRosterPosition)}`,
            ),
        })),
    } as unknown as PublicKeyShareSuccinctProofSetInput['sameSecretBridgeProofMaterialSet'];

    return {
        ...commonInput,
        publicKeyShares,
        publicKeyShareMaterial,
        sameSecretBridgeStatementSet,
        sameSecretBridgeProofMaterialSet,
        proofMaterials: publicKeyShares.shareRecords.map((shareRecord) => ({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            statementHash: fixtureHash(
                `succinct-statement-${String(shareRecord.trusteeRosterPosition)}`,
            ),
            proofBytesHash: fixtureHash(
                `succinct-proof-bytes-${String(shareRecord.trusteeRosterPosition)}`,
            ),
            proofMaterialRoot: fixtureHash(
                `succinct-proof-material-${String(shareRecord.trusteeRosterPosition)}`,
            ),
        })),
    };
};

describe('public-key share builders', () => {
    it('creates a deterministic root-bound public-key share set', () => {
        const publicKeyShares = createShareSet();
        const { publicKeyShareSetRoot, ...shareSetWithoutRoot } =
            publicKeyShares;
        const firstShareRecord = publicKeyShares.shareRecords[0];
        if (firstShareRecord === undefined) {
            throw new Error('fixture public-key share record is missing');
        }
        const { publicKeyShareRoot, ...shareRecordWithoutRoot } =
            firstShareRecord;

        expect(
            publicKeyShares.shareRecords.map(
                (record) => record.trusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(publicKeyShareRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: 'PublicKeyShare',
                setupContextHash,
                trusteeIdentity: shareRecordWithoutRoot.trusteeIdentity,
                trusteeRosterPosition:
                    shareRecordWithoutRoot.trusteeRosterPosition,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                shareCoefficientVectorHash512ByLimb:
                    shareRecordWithoutRoot.shareCoefficientVectorHash512ByLimb,
            }),
        );
        expect(publicKeyShareSetRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: shareSetWithoutRoot.objectType,
                setupContextHash,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                shareRecords: shareSetWithoutRoot.shareRecords,
            }),
        );
    });

    it('rejects malformed public-key share statement inputs', () => {
        expect(() =>
            createPublicKeyShareSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                shareContributions: [
                    {
                        ...shareContribution(0),
                        shareCoefficientVectorHash512ByLimb:
                            shareContribution(
                                0,
                            ).shareCoefficientVectorHash512ByLimb.slice(1),
                    },
                    shareContribution(1),
                ],
            }),
        ).toThrow(/one entry for every Q_share limb/u);
        expect(() =>
            createPublicKeyShareSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                shareContributions: [
                    {
                        ...shareContribution(0),
                        trusteeIdentity: '',
                    },
                    shareContribution(1),
                ],
            }),
        ).toThrow(/trusteeIdentity/u);
        const succinctProofInput = createSuccinctProofFixture();
        expect(() =>
            createPublicKeyShareSuccinctProofSet({
                ...succinctProofInput,
                publicMatrixSeedHash: fixtureHash('wrong-public-matrix-seed'),
            }),
        ).toThrow(/must bind the authoritative setup context/u);
    });

    it('rejects a public-key share root that does not bind the parent context', async () => {
        const materialContributions = [
            shareMaterialContribution(0),
            shareMaterialContribution(1),
        ] as const;
        const publicKeyShares = createPublicKeyShareSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            shareContributions: materialContributions.map(
                shareContributionFromMaterial,
            ),
        });
        const [firstShareRecord, ...remainingShareRecords] =
            publicKeyShares.shareRecords;
        if (firstShareRecord === undefined) {
            throw new Error('Expected the first public-key share record.');
        }
        const tamperedShareRecords = [
            {
                ...firstShareRecord,
                publicKeyShareRoot: fixtureHash('wrong-public-key-share-root'),
            },
            ...remainingShareRecords,
        ];
        const tamperedPublicKeyShares = {
            ...publicKeyShares,
            shareRecords: tamperedShareRecords,
            publicKeyShareSetRoot: deriveCanonicalObjectHash({
                objectType: publicKeyShares.objectType,
                setupContextHash,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                shareRecords: tamperedShareRecords,
            }),
        };

        await expect(
            createBinaryChunkedPublicKeyShareMaterialBundle({
                setupContext,
                qSharePrimes,
                participantCount,
                ringDegree,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyShares: tamperedPublicKeyShares,
                materialContributions,
                writePublicKeyShareMaterial: () =>
                    Promise.resolve(new Uint8Array()),
            }),
        ).rejects.toThrow(/must bind the parent setup context/u);

        await expect(
            createBinaryChunkedPublicKeyShareMaterialBundle({
                setupContext,
                qSharePrimes,
                participantCount,
                ringDegree,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyShares: {
                    ...publicKeyShares,
                    publicKeyShareSetRoot: fixtureHash(
                        'wrong-public-key-share-set-root',
                    ),
                },
                materialContributions,
                writePublicKeyShareMaterial: () =>
                    Promise.resolve(new Uint8Array()),
            }),
        ).rejects.toThrow(/must bind the authoritative setup context/u);
    });

    it('builds repeatable canonical public-key share material sources', async () => {
        const materialContributions = [
            shareMaterialContribution(1),
            shareMaterialContribution(0),
        ] as const;
        const publicKeyShares = createPublicKeyShareSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            shareContributions: materialContributions.map(
                shareContributionFromMaterial,
            ),
        });
        const materialSetInput = {
            setupContext,
            qSharePrimes,
            participantCount,
            ringDegree,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            publicKeyShares,
            materialContributions,
        } as const;
        let totalByteLength = 0;
        const writePublicKeyShareMaterial = (input: {
            readonly totalByteLength: number;
        }): Promise<Uint8Array> => {
            totalByteLength = input.totalByteLength;
            return Promise.resolve(
                canonicalStreamDescriptorFixture(input.totalByteLength),
            );
        };
        const directMaterialBundle =
            await createBinaryChunkedPublicKeyShareMaterialBundle({
                ...materialSetInput,
                writePublicKeyShareMaterial,
            });
        const firstPull =
            await directMaterialBundle.publicKeyShareMaterialChunkSource.pullChunk(
                { chunkIndex: 0, expectedByteLength: totalByteLength },
            );
        const repeatedPull =
            await directMaterialBundle.publicKeyShareMaterialChunkSource.pullChunk(
                { chunkIndex: 0, expectedByteLength: totalByteLength },
            );

        const { publicKeyShareMaterialSetRoot, ...materialSetWithoutRoot } =
            directMaterialBundle.materialSet;
        const logicalMaterialRootReferences =
            materialSetWithoutRoot.publicKeyShareMaterialRoots.map(
                (publicKeyShareMaterialRoot, trusteeRosterPosition) => {
                    const shareRecord =
                        publicKeyShares.shareRecords[trusteeRosterPosition];
                    if (shareRecord === undefined) {
                        throw new Error(
                            'Expected the public-key share for the material root.',
                        );
                    }

                    return {
                        trusteeIdentity: shareRecord.trusteeIdentity,
                        trusteeRosterPosition,
                        publicKeyShareMaterialRoot,
                    };
                },
            );

        expect(publicKeyShareMaterialSetRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: materialSetWithoutRoot.objectType,
                setupContextHash,
                ringDegree,
                publicMatrixSeedHash: materialSetInput.publicMatrixSeedHash,
                publicKeyShareSetRoot: publicKeyShares.publicKeyShareSetRoot,
                publicKeyShareMaterialRoots: logicalMaterialRootReferences,
            }),
        );
        expect(firstPull).toBeInstanceOf(ArrayBuffer);
        expect(repeatedPull).toBeInstanceOf(ArrayBuffer);
        expect(new Uint8Array(firstPull ?? new ArrayBuffer(0))).toEqual(
            new Uint8Array(repeatedPull ?? new ArrayBuffer(0)),
        );
    });

    it('binds every succinct public-key proof to its bridge statement and proof record', () => {
        const input = createSuccinctProofFixture();
        const succinctProofs = createPublicKeyShareSuccinctProofSet(input);
        const {
            publicKeyShareSuccinctProofSetRoot,
            ...succinctProofSetWithoutRoot
        } = succinctProofs;
        const firstProofRecord = succinctProofs.proofRecords[0];
        const firstBridgeStatement =
            input.sameSecretBridgeStatementSet.statementRecords[0];
        const firstBridgeProof =
            input.sameSecretBridgeProofMaterialSet.proofRecords[0];
        if (
            firstProofRecord === undefined ||
            firstBridgeStatement === undefined ||
            firstBridgeProof === undefined
        ) {
            throw new Error('Expected the first succinct proof binding.');
        }
        expect(firstProofRecord).toMatchObject({
            trusteeRosterPosition: 0,
            statementHash: input.proofMaterials[0]?.statementHash,
            proofBytesHash: input.proofMaterials[0]?.proofBytesHash,
            proofMaterialRoot: input.proofMaterials[0]?.proofMaterialRoot,
        });
        const logicalProofRecords = succinctProofs.proofRecords.map(
            (proofRecord, trusteeRosterPosition) => {
                const shareRecord =
                    input.publicKeyShares.shareRecords[trusteeRosterPosition];
                const publicKeyShareMaterialRoot =
                    input.publicKeyShareMaterial.publicKeyShareMaterialRoots[
                        trusteeRosterPosition
                    ];
                const bridgeStatement =
                    input.sameSecretBridgeStatementSet.statementRecords[
                        trusteeRosterPosition
                    ];
                const bridgeProof =
                    input.sameSecretBridgeProofMaterialSet.proofRecords.find(
                        (candidate) =>
                            candidate.sameSecretBridgeStatementRoot ===
                            bridgeStatement?.sameSecretBridgeStatementRoot,
                    );
                if (
                    shareRecord === undefined ||
                    publicKeyShareMaterialRoot === undefined ||
                    bridgeStatement === undefined ||
                    bridgeProof === undefined
                ) {
                    throw new Error(
                        'Expected authoritative public-key proof siblings.',
                    );
                }

                return {
                    objectType: proofRecord.objectType,
                    setupContextHash,
                    trusteeIdentity: shareRecord.trusteeIdentity,
                    trusteeRosterPosition,
                    publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                    publicKeyShareMaterialRoot,
                    sameSecretBridgeStatementRoot:
                        bridgeStatement.sameSecretBridgeStatementRoot,
                    sameSecretBridgeProofRecordRoot:
                        bridgeProof.sameSecretBridgeProofRecordRoot,
                    statementHash: proofRecord.statementHash,
                    proofBytesHash: proofRecord.proofBytesHash,
                    proofMaterialRoot: proofRecord.proofMaterialRoot,
                };
            },
        );
        expect(publicKeyShareSuccinctProofSetRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: succinctProofSetWithoutRoot.objectType,
                proofRecords: logicalProofRecords,
            }),
        );
    });

    it('rejects malformed canonical proof-material references', () => {
        const input = createSuccinctProofFixture();
        const [firstProofMaterial, ...remainingProofMaterials] =
            input.proofMaterials;
        if (firstProofMaterial === undefined) {
            throw new Error('Expected the first succinct proof material.');
        }

        expect(() =>
            createPublicKeyShareSuccinctProofSet({
                ...input,
                proofMaterials: [
                    {
                        ...firstProofMaterial,
                        proofMaterialRoot: 'not-a-protocol-hash',
                    },
                    ...remainingProofMaterials,
                ],
            }),
        ).toThrow('proofMaterialRoot must be a protocol hash');
    });

    it('rejects bridge records that do not cover the accepted public-key trustees', () => {
        const input = createSuccinctProofFixture();
        const firstBridgeProof =
            input.sameSecretBridgeProofMaterialSet.proofRecords[0];
        const secondBridgeProof =
            input.sameSecretBridgeProofMaterialSet.proofRecords[1];
        if (firstBridgeProof === undefined || secondBridgeProof === undefined) {
            throw new Error('Expected two bridge proof records.');
        }
        const mismatchedBridgeProofMaterialSet = {
            ...input.sameSecretBridgeProofMaterialSet,
            proofRecords: [
                {
                    ...firstBridgeProof,
                    sameSecretBridgeStatementRoot: fixtureHash(
                        'unmatched-bridge-statement',
                    ),
                },
                secondBridgeProof,
            ],
        };

        expect(() =>
            createPublicKeyShareSuccinctProofSet({
                ...input,
                sameSecretBridgeProofMaterialSet:
                    mismatchedBridgeProofMaterialSet,
            }),
        ).toThrow(
            'sameSecretBridgeProofMaterialSet must contain one proof for every bridge statement',
        );
    });
});
