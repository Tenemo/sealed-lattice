import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createBinaryChunkedPublicKeyShareMaterialBundle,
    createBinaryChunkedPublicKeyShareMaterialTransport,
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createPublicKeyShareSuccinctProofSet,
    materialRecordsFromTransportedPublicKeyShareMaterial,
    publicKeyShareCoefficientVectorHashDomain,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareSet,
    type PublicKeyShareSuccinctProofSetInput,
} from '#packages/protocol/src/index';
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

const setupContext = makeSetupContext(fixtureHash);

const shareContribution = (
    trusteeRosterPosition: number,
): PublicKeyShareContributionInput => ({
    trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
    trusteeRosterPosition,
    shareCoefficientVectorHash512ByLimb: qSharePrimes.map(
        (rnsPrime, rnsLimbIndex) => ({
            rnsLimbIndex,
            rnsPrime,
            component: 'b_i',
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
                rnsLimbIndex,
                rnsPrime,
                component: 'b_i',
                coefficientByteLength: ringDegree * 8,
                coefficientVectorHash512:
                    publicKeyShareCoefficientVectorHash(coefficients),
                coefficientsLeHex: coefficientVectorLeHex(coefficients),
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
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
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
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
    } as const;
    const publicKeyShares = createPublicKeyShareSet({
        ...commonInput,
        shareContributions: materialContributions.map((contribution) => ({
            trusteeIdentity: contribution.trusteeIdentity,
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            shareCoefficientVectorHash512ByLimb:
                contribution.shareCoefficientVectorsByLimb.map(
                    (coefficientVector) => ({
                        rnsLimbIndex: coefficientVector.rnsLimbIndex,
                        rnsPrime: coefficientVector.rnsPrime,
                        component: coefficientVector.component,
                        coefficientVectorHash512:
                            coefficientVector.coefficientVectorHash512,
                    }),
                ),
        })),
    });
    const publicKeyShareProofs = createPublicKeyShareProofSet({
        ...commonInput,
        publicKeyShares,
    });
    const publicKeyShareMaterial = createPublicKeyShareMaterialSet({
        ...commonInput,
        ringDegree,
        publicKeyShares,
        materialContributions,
    });
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
        proofFamily: 'same-secret-bridge',
        ...setupContext,
        participantCount,
        publicMatrixSeedHash: commonInput.publicMatrixSeedHash,
        statementRecords,
        sameSecretBridgeStatementSetRoot: fixtureHash('bridge-statement-set'),
    } as unknown as PublicKeyShareSuccinctProofSetInput['sameSecretBridgeStatementSet'];
    const sameSecretBridgeProofMaterialSet = {
        objectType: 'VssSameSecretBridgeProofMaterialSet',
        proofFamily: 'same-secret-bridge',
        ...setupContext,
        participantCount,
        publicMatrixSeedHash: commonInput.publicMatrixSeedHash,
        sameSecretBridgeStatementSetRoot:
            sameSecretBridgeStatementSet.sameSecretBridgeStatementSetRoot,
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
        publicKeyShareProofs,
        publicKeyShareMaterial,
        sameSecretBridgeStatementSet,
        sameSecretBridgeProofMaterialSet,
        proofMaterials: publicKeyShareProofs.proofRecords.map(
            (proofRecord) => ({
                proofFamily: 'public-key-share',
                trusteeIdentity: proofRecord.trusteeIdentity,
                trusteeRosterPosition: proofRecord.trusteeRosterPosition,
                statementHash: fixtureHash(
                    `succinct-statement-${String(proofRecord.trusteeRosterPosition)}`,
                ),
                proofBytesHash: fixtureHash(
                    `succinct-proof-bytes-${String(proofRecord.trusteeRosterPosition)}`,
                ),
                proofBytesHex: proofRecord.trusteeRosterPosition
                    .toString(16)
                    .padStart(2, '0'),
            }),
        ),
    };
};

describe('public-key share statement builders', () => {
    it('creates deterministic root-bound public-key share and proof statement sets', () => {
        const publicKeyShares = createShareSet();
        const publicKeyShareProofs = createPublicKeyShareProofSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            publicKeyCrpRoot: fixtureHash('public-key-crp'),
            publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
            publicKeyShares,
        });
        const { publicKeyShareSetRoot, ...shareSetWithoutRoot } =
            publicKeyShares;
        const { publicKeyShareProofSetRoot, ...proofSetWithoutRoot } =
            publicKeyShareProofs;
        const firstShareRecord = publicKeyShares.shareRecords[0];
        const firstProofRecord = publicKeyShareProofs.proofRecords[0];
        if (firstShareRecord === undefined || firstProofRecord === undefined) {
            throw new Error('fixture public-key share record is missing');
        }
        const { publicKeyShareRoot, ...shareRecordWithoutRoot } =
            firstShareRecord;
        const { publicKeyShareProofRoot, ...proofRecordWithoutRoot } =
            firstProofRecord;

        expect(
            publicKeyShares.shareRecords.map(
                (record) => record.trusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(publicKeyShareRoot).toBe(
            deriveCanonicalObjectHash(shareRecordWithoutRoot),
        );
        expect(publicKeyShareSetRoot).toBe(
            deriveCanonicalObjectHash(shareSetWithoutRoot),
        );
        expect(firstProofRecord.publicKeyShareRoot).toBe(publicKeyShareRoot);
        expect(publicKeyShareProofRoot).toBe(
            deriveCanonicalObjectHash(proofRecordWithoutRoot),
        );
        expect(publicKeyShareProofSetRoot).toBe(
            deriveCanonicalObjectHash(proofSetWithoutRoot),
        );
    });

    it('rejects malformed public-key share statement inputs', () => {
        const publicKeyShares = createShareSet();

        expect(() =>
            createPublicKeyShareSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyCrpRoot: fixtureHash('public-key-crp'),
                publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
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
                publicKeyCrpRoot: fixtureHash('public-key-crp'),
                publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
                shareContributions: [
                    {
                        ...shareContribution(0),
                        trusteeIdentity: '',
                    },
                    shareContribution(1),
                ],
            }),
        ).toThrow(/trusteeIdentity/u);
        expect(() =>
            createPublicKeyShareProofSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyCrpRoot: fixtureHash('wrong-public-key-crp'),
                publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
                publicKeyShares,
            }),
        ).toThrow(/same common randomness/u);
    });

    it('builds direct binary-chunked public-key share material without an embedded material set', () => {
        const materialContributions = [
            shareMaterialContribution(1),
            shareMaterialContribution(0),
        ] as const;
        const publicKeyShares = createPublicKeyShareSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            publicKeyCrpRoot: fixtureHash('public-key-crp'),
            publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
            shareContributions: materialContributions.map((contribution) => ({
                trusteeIdentity: contribution.trusteeIdentity,
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                shareCoefficientVectorHash512ByLimb:
                    contribution.shareCoefficientVectorsByLimb.map(
                        (coefficientVector) => ({
                            rnsLimbIndex: coefficientVector.rnsLimbIndex,
                            rnsPrime: coefficientVector.rnsPrime,
                            component: coefficientVector.component,
                            coefficientVectorHash512:
                                coefficientVector.coefficientVectorHash512,
                        }),
                    ),
            })),
        });
        const materialSetInput = {
            setupContext,
            qSharePrimes,
            participantCount,
            ringDegree,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            publicKeyCrpRoot: fixtureHash('public-key-crp'),
            publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
            publicKeyShares,
            materialContributions,
        } as const;
        const embeddedMaterialSet =
            createPublicKeyShareMaterialSet(materialSetInput);
        const transportedEmbeddedMaterial =
            createBinaryChunkedPublicKeyShareMaterialTransport(
                embeddedMaterialSet,
            );
        const directMaterialBundle =
            createBinaryChunkedPublicKeyShareMaterialBundle(materialSetInput);
        const reconstructedMaterialRecords =
            materialRecordsFromTransportedPublicKeyShareMaterial({
                setupContext,
                publicKeyShares,
                materialSet: directMaterialBundle.materialSet,
                transportedPublicKeyShareMaterial:
                    directMaterialBundle.transportedPublicKeyShareMaterial,
            });

        expect(directMaterialBundle.materialSet).toEqual(
            transportedEmbeddedMaterial.materialSet,
        );
        expect(directMaterialBundle.transportedPublicKeyShareMaterial).toEqual(
            transportedEmbeddedMaterial.transportedPublicKeyShareMaterial,
        );
        expect(
            directMaterialBundle.transportedPublicKeyShareMaterial,
        ).toMatchObject({
            chunkCount: 1,
        });
        expect(reconstructedMaterialRecords).toEqual(
            embeddedMaterialSet.shareMaterialRecords,
        );
    });

    it('binds every succinct public-key proof to its bridge statement and proof record', () => {
        const input = createSuccinctProofFixture();
        const succinctProofs = createPublicKeyShareSuccinctProofSet(input);
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
        const { publicKeyShareSuccinctProofRoot, ...recordWithoutRoot } =
            firstProofRecord;

        expect(firstProofRecord.sameSecretBridgeStatementRoot).toBe(
            firstBridgeStatement.sameSecretBridgeStatementRoot,
        );
        expect(firstProofRecord.sameSecretBridgeProofRecordRoot).toBe(
            firstBridgeProof.sameSecretBridgeProofRecordRoot,
        );
        expect(publicKeyShareSuccinctProofRoot).toBe(
            deriveCanonicalObjectHash(recordWithoutRoot),
        );
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
