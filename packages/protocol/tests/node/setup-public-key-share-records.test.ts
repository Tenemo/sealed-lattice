import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createBinaryChunkedPublicKeyShareMaterialBundle,
    createBinaryChunkedPublicKeyShareMaterialTransport,
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientOpeningState,
    materialRecordsFromTransportedPublicKeyShareMaterial,
    publicKeyShareCoefficientVectorHashDomain,
    publicKeyShareMaterialBinaryFormat,
    setupTransportChunkSizeBytes,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareSet,
    type SameSecretConsistencyStatementSet,
} from '#packages/protocol/src/index';
import { setupCommitmentComputer } from '#tests/support/setup-commitment-computer';
import {
    makeSetupContext,
    makeSetupFixtureHash,
    makeVssOpeningRandomBytes,
} from '#tests/support/setup-fixtures';

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const fixtureHash = makeSetupFixtureHash('setup-public-key-share-records');

const deterministicRandomBytes = makeVssOpeningRandomBytes(
    'setup-public-key-share-records',
);

const setupContext = makeSetupContext(fixtureHash);

const sameSecretConsistency = (): SameSecretConsistencyStatementSet => {
    const vssCoefficientCommitments = createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        setupCommitmentComputer,
        qSharePrimes,
        ringDegree,
        participantCount,
        thresholdDegree,
        sourceTrusteeOpeningStates: Array.from(
            { length: participantCount },
            (_unused, sourceTrusteeRosterPosition) =>
                createVssSourceTrusteeCoefficientOpeningState({
                    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
                    sourceTrusteeRosterPosition,
                    participantCount,
                    qSharePrimes,
                    ringDegree,
                    thresholdDegree,
                    randomBytes: deterministicRandomBytes(
                        `trustee-${String(sourceTrusteeRosterPosition)}`,
                    ),
                }),
        ),
    }).commitmentSet;

    return createSameSecretConsistencyStatementSet({
        setupContext,
        qSharePrimes,
        participantCount,
        thresholdDegree,
        vssCoefficientCommitments,
    });
};

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

const createShareSet = (
    sameSecretStatements: SameSecretConsistencyStatementSet,
): PublicKeyShareSet =>
    createPublicKeyShareSet({
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        sameSecretConsistency: sameSecretStatements,
        shareContributions: [shareContribution(1), shareContribution(0)],
    });

describe('public-key share statement builders', () => {
    it('creates deterministic root-bound public-key share and proof statement sets', () => {
        const sameSecretStatements = sameSecretConsistency();
        const publicKeyShares = createShareSet(sameSecretStatements);
        const publicKeyShareProofs = createPublicKeyShareProofSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            publicKeyCrpRoot: fixtureHash('public-key-crp'),
            publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
            sameSecretConsistency: sameSecretStatements,
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
        expect(firstShareRecord.sameSecretStatementRoot).toBe(
            sameSecretStatements.statementRecords[0]?.sameSecretStatementRoot,
        );
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
        const sameSecretStatements = sameSecretConsistency();
        const publicKeyShares = createShareSet(sameSecretStatements);

        expect(() =>
            createPublicKeyShareSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
                publicKeyCrpRoot: fixtureHash('public-key-crp'),
                publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
                sameSecretConsistency: sameSecretStatements,
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
                sameSecretConsistency: sameSecretStatements,
                shareContributions: [
                    {
                        ...shareContribution(0),
                        trusteeIdentity: 'wrong-trustee',
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
                sameSecretConsistency: sameSecretStatements,
                publicKeyShares,
            }),
        ).toThrow(/same common randomness/u);
    });

    it('builds direct binary-chunked public-key share material without an embedded material set', () => {
        const sameSecretStatements = sameSecretConsistency();
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
            sameSecretConsistency: sameSecretStatements,
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
            binaryFormat: publicKeyShareMaterialBinaryFormat,
            chunkSizeBytes: setupTransportChunkSizeBytes,
        });
        expect(reconstructedMaterialRecords).toEqual(
            embeddedMaterialSet.shareMaterialRecords,
        );
    });
});
