import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createBinaryChunkedVssCoefficientCommitmentMaterialTransport,
    createVssCoefficientCommitmentBundle,
    deriveThresholdShareCommitments,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/index';
import { setupCommitmentComputer } from '#tests/support/setup-commitment-computer';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const fixtureHash = makeSetupFixtureHash('setup-threshold-share-commitments');

const setupContext = makeSetupContext(fixtureHash);

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        let value = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return bytes;
};

const thresholdRowHash = (row: readonly number[]): string =>
    hash512Hex(
        'sealed-lattice-threshold-share-commitment/row-coefficients-v1',
        [coefficientVectorBytes(row)],
    );

const coefficientMessage = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    rnsPrime: number,
): readonly number[] =>
    Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        const value =
            (sourceTrusteeRosterPosition + 1) * 29 +
            (rnsLimbIndex + 1) * 13 +
            (shamirCoefficientIndex + 1) * 5 +
            coefficientIndex;

        return value % rnsPrime;
    });

const randomnessByColumn = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): readonly (readonly number[])[] =>
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

const aggregateRowsForRecipient = (
    commitmentRecords: readonly Record<string, unknown>[],
    recipientTrusteePoint: number,
    rnsLimbIndex: number,
    commitmentModulusIndex: number,
): readonly (readonly number[])[] => {
    const matchingRecords = commitmentRecords.filter(
        (record) => record.rnsLimbIndex === rnsLimbIndex,
    );
    const firstCommitment = matchingRecords[0]?.commitment as
        | Record<string, unknown>
        | undefined;
    if (firstCommitment === undefined) {
        throw new Error('fixture commitment is missing');
    }
    const firstLimb = (
        firstCommitment.commitmentLimbs as readonly Record<string, unknown>[]
    ).find((limb) => limb.commitmentModulusIndex === commitmentModulusIndex);
    if (firstLimb === undefined) {
        throw new Error('fixture commitment limb is missing');
    }
    const modulus = Number(firstLimb.modulus);
    const rowCount = (firstLimb.rows as readonly unknown[]).length;
    const rows = Array.from({ length: rowCount }, () =>
        Array.from({ length: ringDegree }, () => 0n),
    );
    for (const record of matchingRecords) {
        const commitment = record.commitment as Record<string, unknown>;
        const commitmentLimb = (
            commitment.commitmentLimbs as readonly Record<string, unknown>[]
        ).find(
            (limb) => limb.commitmentModulusIndex === commitmentModulusIndex,
        );
        if (commitmentLimb === undefined) {
            throw new Error('fixture commitment limb is missing');
        }
        const scalar =
            Number(record.shamirCoefficientIndex) === 0
                ? 1n
                : BigInt(recipientTrusteePoint);
        const modulusWide = BigInt(modulus);
        (commitmentLimb.rows as readonly (readonly number[])[]).forEach(
            (sourceRow, rowIndex) => {
                sourceRow.forEach((coefficient, coefficientIndex) => {
                    rows[rowIndex][coefficientIndex] =
                        ((rows[rowIndex][coefficientIndex] ?? 0n) +
                            BigInt(coefficient) * scalar) %
                        modulusWide;
                });
            },
        );
    }

    return rows.map((row) => row.map((coefficient) => Number(coefficient)));
};

describe('threshold-share commitment derivation', () => {
    it('derives recipient commitments from public VSS coefficient material', () => {
        const commitmentBundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            setupCommitmentComputer,
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates: [0, 1].map((rosterPosition) =>
                sourceTrusteeOpeningState(rosterPosition),
            ),
        });
        const thresholdShareCommitments = deriveThresholdShareCommitments({
            setupContext,
            vssCoefficientCommitments: commitmentBundle.commitmentSet,
            vssCoefficientCommitmentMaterial: commitmentBundle.materialSet,
        });
        const firstRecipient = thresholdShareCommitments.recipientRecords[0];
        const firstRecipientFirstLimb = firstRecipient?.limbCommitments[0];
        const firstCommitmentLimb = firstRecipientFirstLimb?.commitmentLimbs[0];
        const expectedRows = aggregateRowsForRecipient(
            commitmentBundle.materialSet.coefficientCommitments,
            1,
            0,
            0,
        );

        expect(thresholdShareCommitments).toMatchObject({
            objectType: 'ThresholdShareCommitmentSet',
            participantCount,
            thresholdDegree,
            rnsLimbCount: qSharePrimes.length,
            derivationRule:
                'sum-source-trustee-polynomial-commitments-at-trustee-point',
        });
        expect(thresholdShareCommitments.recipientRecords).toHaveLength(
            participantCount,
        );
        expect(firstRecipient).toMatchObject({
            objectType: 'TrusteeThresholdShareCommitments',
            recipientIdentity: 'trustee-0',
            recipientRosterPosition: 0,
            trusteePoint: 1,
            ringDegree,
            ringDegreeStatus: 'development-reduced-ring',
        });
        expect(firstRecipientFirstLimb).toMatchObject({
            objectType: 'ThresholdShareCommitment',
            rnsLimbIndex: 0,
            rnsPrime: qSharePrimes[0],
            trusteePoint: 1,
            ringDegree,
            ringDegreeStatus: 'development-reduced-ring',
            shamirCoefficientScalarsDecimal: ['1', '1'],
        });
        expect(
            firstRecipientFirstLimb?.coefficientCommitmentRoots,
        ).toHaveLength(participantCount * thresholdDegree);
        expect(firstCommitmentLimb?.rowCoefficientHash512).toEqual(
            expectedRows.map((row) => thresholdRowHash(row)),
        );
        if (firstRecipient === undefined) {
            throw new Error('first recipient commitment is missing');
        }
        const { recipientCommitmentRoot, ...firstRecipientWithoutRoot } =
            firstRecipient;
        expect(recipientCommitmentRoot).toBe(
            deriveCanonicalObjectHash(firstRecipientWithoutRoot),
        );
    });

    it('rejects missing public commitment material before deriving roots', () => {
        const commitmentBundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            setupCommitmentComputer,
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates: [0, 1].map((rosterPosition) =>
                sourceTrusteeOpeningState(rosterPosition),
            ),
        });

        expect(() =>
            deriveThresholdShareCommitments({
                setupContext,
                vssCoefficientCommitments: commitmentBundle.commitmentSet,
                vssCoefficientCommitmentMaterial: {
                    ...commitmentBundle.materialSet,
                    coefficientCommitments:
                        commitmentBundle.materialSet.coefficientCommitments.slice(
                            1,
                        ),
                },
            }),
        ).toThrow(/materialRecordCount/u);
    });

    it('derives the same recipient commitments from binary-chunked VSS material', () => {
        const commitmentBundle = createVssCoefficientCommitmentBundle({
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            setupCommitmentComputer,
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates: [0, 1].map((rosterPosition) =>
                sourceTrusteeOpeningState(rosterPosition),
            ),
        });
        const embeddedThresholdShareCommitments =
            deriveThresholdShareCommitments({
                setupContext,
                vssCoefficientCommitments: commitmentBundle.commitmentSet,
                vssCoefficientCommitmentMaterial: commitmentBundle.materialSet,
            });
        const transport =
            createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
                commitmentBundle.materialSet,
            );
        const binaryThresholdShareCommitments = deriveThresholdShareCommitments(
            {
                setupContext,
                vssCoefficientCommitments: commitmentBundle.commitmentSet,
                vssCoefficientCommitmentMaterial: transport.materialSet,
                transportedVssCoefficientCommitmentMaterial:
                    transport.transportedVssCoefficientCommitmentMaterial,
            },
        );

        expect(binaryThresholdShareCommitments).toEqual(
            embeddedThresholdShareCommitments,
        );
        expect(() =>
            deriveThresholdShareCommitments({
                setupContext,
                vssCoefficientCommitments: commitmentBundle.commitmentSet,
                vssCoefficientCommitmentMaterial: transport.materialSet,
            }),
        ).toThrow(/transportedVssCoefficientCommitmentMaterial is required/u);
    });
});
