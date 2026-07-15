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
    140_700_980_543_489, 140_546_359_361_537, 140_507_704_066_049,
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
    trusteeRosterPosition,
    shareCoefficientVectorHashesByLimb: qSharePrimes.map(
        (_unusedRnsPrime, rnsLimbIndex) =>
            fixtureHash(
                `share-coefficient-${String(trusteeRosterPosition)}-${String(rnsLimbIndex)}`,
            ),
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
    trusteeRosterPosition,
    shareCoefficientVectorsLittleEndianHexByLimb: qSharePrimes.map(
        (rnsPrime, rnsLimbIndex) => {
            const coefficients = shareMaterialCoefficients(
                trusteeRosterPosition,
                rnsLimbIndex,
                rnsPrime,
            );

            return coefficientVectorLeHex(coefficients);
        },
    ),
});

const shareContributionFromMaterial = (
    contribution: PublicKeyShareMaterialContributionInput,
): PublicKeyShareContributionInput => ({
    trusteeRosterPosition: contribution.trusteeRosterPosition,
    shareCoefficientVectorHashesByLimb:
        contribution.shareCoefficientVectorsLittleEndianHexByLimb.map(
            (_unusedCoefficientVector, rnsLimbIndex) => {
                const rnsPrime = qSharePrimes[rnsLimbIndex];
                if (rnsPrime === undefined) {
                    throw new Error('Expected the selected Q_share prime.');
                }

                return publicKeyShareCoefficientVectorHash(
                    shareMaterialCoefficients(
                        contribution.trusteeRosterPosition,
                        rnsLimbIndex,
                        rnsPrime,
                    ),
                );
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

        expect(firstShareRecord).toEqual({
            objectType: 'PublicKeyShare',
            shareCoefficientVectorHashesByLimb:
                shareContribution(0).shareCoefficientVectorHashesByLimb,
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
                        shareCoefficientVectorHashesByLimb:
                            shareContribution(
                                0,
                            ).shareCoefficientVectorHashesByLimb.slice(1),
                    },
                    shareContribution(1),
                ],
            }),
        ).toThrow(/one entry for every Q_share limb/u);
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
                shareCoefficientVectorHashesByLimb:
                    firstShareRecord.shareCoefficientVectorHashesByLimb.map(
                        (coefficientHash, rnsLimbIndex) =>
                            rnsLimbIndex === 0
                                ? fixtureHash('mismatching-coefficient-vector')
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
            await directMaterialBundle.publicKeyShareMaterialStream.pullChunk({
                chunkIndex: 0,
                expectedByteLength: totalByteLength,
            });
        const repeatedPull =
            await directMaterialBundle.publicKeyShareMaterialStream.pullChunk({
                chunkIndex: 0,
                expectedByteLength: totalByteLength,
            });

        const { publicKeyShareMaterialSetRoot, ...materialSetWithoutRoot } =
            directMaterialBundle.materialSet;
        const logicalMaterialRootReferences = publicKeyShares.shareRecords.map(
            (shareRecord, trusteeRosterPosition) => {
                const publicKeyShareRoot = deriveCanonicalObjectHash({
                    objectType: shareRecord.objectType,
                    setupContextHash,
                    trusteeRosterPosition,
                    publicMatrixSeedHash: materialSetInput.publicMatrixSeedHash,
                    shareCoefficientVectorHashesByLimb:
                        shareRecord.shareCoefficientVectorHashesByLimb,
                });
                const publicKeyShareMaterialRoot = deriveCanonicalObjectHash({
                    objectType: 'PublicKeyShareMaterial',
                    setupContextHash,
                    trusteeRosterPosition,
                    publicMatrixSeedHash: materialSetInput.publicMatrixSeedHash,
                    publicKeyShareRoot,
                    shareCoefficientVectorsLittleEndianHexByLimb:
                        shareMaterialContribution(trusteeRosterPosition)
                            .shareCoefficientVectorsLittleEndianHexByLimb,
                });

                return {
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
        expect(
            directMaterialBundle.publicKeyShareMaterialStream.descriptorBytes,
        ).toEqual(canonicalStreamDescriptorFixture(totalByteLength));
        expect(directBytes).toEqual(expectedBytes);
    });

    it('builds one succinct public-key proof hash per accepted trustee', () => {
        const input = createSuccinctProofFixture();
        const succinctProofs = createPublicKeyShareSuccinctProofSet(input);
        const firstProofBytesHash = succinctProofs.proofBytesHashes[0];
        if (firstProofBytesHash === undefined) {
            throw new Error('Expected the first succinct proof hash.');
        }
        expect(succinctProofs.proofBytesHashes).toHaveLength(participantCount);
        expect(firstProofBytesHash).toBe(
            input.proofMaterials[0]?.proofBytesHash,
        );
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
