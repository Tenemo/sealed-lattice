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
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        shareContributions: [shareContribution(1), shareContribution(0)],
    });

const createSuccinctProofFixture = (): PublicKeyShareSuccinctProofSetInput => {
    return {
        setupContext,
        proofMaterials: Array.from(
            { length: participantCount },
            (_unused, trusteeRosterPosition) => ({
                proofBytesHash: fixtureHash(
                    `succinct-proof-bytes-${String(trusteeRosterPosition)}`,
                ),
            }),
        ),
    };
};

describe('public-key share builders', () => {
    it('creates public-key shares in canonical roster order', () => {
        const publicKeyShares = createShareSet();
        const firstShareRecord = publicKeyShares.shareRecords[0];
        if (firstShareRecord === undefined) {
            throw new Error('fixture public-key share record is missing');
        }

        expect(
            publicKeyShares.shareRecords.map(
                (record) => record.trusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(firstShareRecord).toEqual({
            objectType: 'PublicKeyShare',
            ...shareContribution(0),
        });
    });

    it('rejects malformed public-key share statement inputs', () => {
        expect(() =>
            createPublicKeyShareSet({
                setupContext,
                qSharePrimes,
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
    });

    it('rejects material that does not match the accepted public-key share hashes', async () => {
        const materialContributions = [
            shareMaterialContribution(0),
            shareMaterialContribution(1),
        ] as const;
        const publicKeyShares = createPublicKeyShareSet({
            setupContext,
            qSharePrimes,
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
        const mismatchingShareRecords = [
            {
                ...firstShareRecord,
                shareCoefficientVectorHash512ByLimb:
                    firstShareRecord.shareCoefficientVectorHash512ByLimb.map(
                        (coefficientHash, rnsLimbIndex) =>
                            rnsLimbIndex === 0
                                ? {
                                      coefficientVectorHash512: fixtureHash(
                                          'mismatching-coefficient-vector',
                                      ),
                                  }
                                : coefficientHash,
                    ),
            },
            ...remainingShareRecords,
        ];
        const mismatchingPublicKeyShares = {
            ...publicKeyShares,
            shareRecords: mismatchingShareRecords,
        };

        await expect(
            createBinaryChunkedPublicKeyShareMaterialBundle({
                setupContext,
                qSharePrimes,
                ringDegree,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyShares: mismatchingPublicKeyShares,
                materialContributions,
                writePublicKeyShareMaterial: () =>
                    Promise.resolve(new Uint8Array()),
            }),
        ).rejects.toThrow(/coefficient hash must match/u);
    });

    it('builds repeatable canonical public-key share material sources', async () => {
        const materialContributions = [
            shareMaterialContribution(1),
            shareMaterialContribution(0),
        ] as const;
        const publicKeyShares = createPublicKeyShareSet({
            setupContext,
            qSharePrimes,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            shareContributions: materialContributions.map(
                shareContributionFromMaterial,
            ),
        });
        const materialSetInput = {
            setupContext,
            qSharePrimes,
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
        const logicalMaterialRootReferences = publicKeyShares.shareRecords.map(
            (shareRecord, trusteeRosterPosition) => {
                const publicKeyShareRoot = deriveCanonicalObjectHash({
                    objectType: shareRecord.objectType,
                    setupContextHash,
                    trusteeIdentity: shareRecord.trusteeIdentity,
                    trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                    publicMatrixSeedHash: materialSetInput.publicMatrixSeedHash,
                    shareCoefficientVectorHash512ByLimb:
                        shareRecord.shareCoefficientVectorHash512ByLimb,
                });
                const publicKeyShareMaterialRoot = deriveCanonicalObjectHash({
                    objectType: 'PublicKeyShareMaterial',
                    setupContextHash,
                    trusteeIdentity: shareRecord.trusteeIdentity,
                    trusteeRosterPosition,
                    publicMatrixSeedHash: materialSetInput.publicMatrixSeedHash,
                    publicKeyShareRoot,
                    shareCoefficientVectorsByLimb: shareMaterialContribution(
                        trusteeRosterPosition,
                    ).shareCoefficientVectorsByLimb,
                });

                return {
                    trusteeIdentity: shareRecord.trusteeIdentity,
                    trusteeRosterPosition,
                    publicKeyShareMaterialRoot,
                };
            },
        );
        const publicKeyShareSetRoot = deriveCanonicalObjectHash({
            objectType: publicKeyShares.objectType,
            setupContextHash,
            publicMatrixSeedHash: materialSetInput.publicMatrixSeedHash,
            shareRecords: publicKeyShares.shareRecords,
        });

        expect(publicKeyShareMaterialSetRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: materialSetWithoutRoot.objectType,
                setupContextHash,
                ringDegree,
                publicMatrixSeedHash: materialSetInput.publicMatrixSeedHash,
                publicKeyShareSetRoot,
                publicKeyShareMaterialRoots: logicalMaterialRootReferences,
            }),
        );
        expect(firstPull).toBeInstanceOf(ArrayBuffer);
        expect(repeatedPull).toBeInstanceOf(ArrayBuffer);
        const directBytes = new Uint8Array(firstPull ?? new ArrayBuffer(0));
        expect(directBytes).toEqual(
            new Uint8Array(repeatedPull ?? new ArrayBuffer(0)),
        );
        const expectedBytes = new Uint8Array(
            8 +
                participantCount *
                    qSharePrimes.length *
                    ringDegree *
                    Uint32Array.BYTES_PER_ELEMENT *
                    2,
        );
        expectedBytes.set(new TextEncoder().encode('SLPKSMV2'));
        let expectedByteOffset = 8;
        for (
            let trusteeRosterPosition = 0;
            trusteeRosterPosition < participantCount;
            trusteeRosterPosition += 1
        ) {
            for (
                let rnsLimbIndex = 0;
                rnsLimbIndex < qSharePrimes.length;
                rnsLimbIndex += 1
            ) {
                const rnsPrime = qSharePrimes[rnsLimbIndex];
                if (rnsPrime === undefined) {
                    throw new Error('Expected the public-key RNS prime.');
                }
                const coefficientBytes = coefficientVectorBytes(
                    shareMaterialCoefficients(
                        trusteeRosterPosition,
                        rnsLimbIndex,
                        rnsPrime,
                    ),
                );
                expectedBytes.set(coefficientBytes, expectedByteOffset);
                expectedByteOffset += coefficientBytes.byteLength;
            }
        }
        expect(totalByteLength).toBe(expectedBytes.byteLength);
        expect(directBytes).toEqual(expectedBytes);
    });

    it('builds one succinct public-key proof record per accepted trustee', () => {
        const input = createSuccinctProofFixture();
        const succinctProofs = createPublicKeyShareSuccinctProofSet(input);
        const firstProofRecord = succinctProofs.proofRecords[0];
        if (firstProofRecord === undefined) {
            throw new Error('Expected the first succinct proof record.');
        }
        expect(succinctProofs.proofRecords).toHaveLength(participantCount);
        expect(firstProofRecord).toEqual({
            objectType: 'PublicKeyShareSuccinctProof',
            proofBytesHash: input.proofMaterials[0]?.proofBytesHash,
        });
    });

    it('rejects an incomplete proof set', () => {
        const input = createSuccinctProofFixture();
        expect(() =>
            createPublicKeyShareSuccinctProofSet({
                ...input,
                proofMaterials: input.proofMaterials.slice(1),
            }),
        ).toThrow('one proof per participant in roster order');
    });
});
