import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
    sameSecretBoundProofFamilies,
    sameSecretGenericKeySwitchBindingPolicy,
    sameSecretProofFamily,
    sameSecretRelation,
    sameSecretTargetDecryptionBindingPolicy,
    setupCommitmentProfileId,
    setupProofProfileId,
    type CollectiveBgvSetupContext,
    type SameSecretConsistencyStatementRecord,
    type VssCoefficientCommitmentSet,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientCommitmentRecord,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/index';

const qSharePrimes = [140_737_487_306_753, 140_737_486_716_929] as const;
const ringDegree = 8;
const participantCount = 3;
const thresholdDegree = 2;

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-same-secret-consistency-records',
        label,
    });

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
            (sourceTrusteeRosterPosition + 1) * 23 +
            (rnsLimbIndex + 1) * 11 +
            (shamirCoefficientIndex + 1) * 5 +
            coefficientIndex * 3;

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
                (sourceTrusteeRosterPosition * 2 +
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

const acceptedCommitmentSet = (): VssCoefficientCommitmentSet =>
    createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        qSharePrimes,
        ringDegree,
        participantCount,
        thresholdDegree,
        sourceTrusteeOpeningStates: [
            sourceTrusteeOpeningState(2),
            sourceTrusteeOpeningState(0),
            sourceTrusteeOpeningState(1),
        ],
    }).commitmentSet;

const requiredSourceTrusteeRecord = (
    commitmentSet: VssCoefficientCommitmentSet,
    sourceTrusteeRecordIndex: number,
): VssSourceTrusteeCoefficientCommitmentRecord => {
    const sourceTrusteeRecord =
        commitmentSet.sourceTrusteeRecords[sourceTrusteeRecordIndex];
    if (sourceTrusteeRecord === undefined) {
        throw new Error('fixture source trustee record is missing');
    }

    return sourceTrusteeRecord;
};

const requiredStatementRecord = (
    statementRecords: readonly SameSecretConsistencyStatementRecord[],
    statementRecordIndex: number,
): SameSecretConsistencyStatementRecord => {
    const statementRecord = statementRecords[statementRecordIndex];
    if (statementRecord === undefined) {
        throw new Error('fixture statement record is missing');
    }

    return statementRecord;
};

describe('same-secret consistency statement builders', () => {
    it('creates deterministic root-bound statement records from VSS constant commitments', () => {
        const vssCoefficientCommitments = acceptedCommitmentSet();
        const sameSecretConsistency = createSameSecretConsistencyStatementSet({
            setupContext,
            qSharePrimes,
            participantCount,
            thresholdDegree,
            vssCoefficientCommitments,
        });
        const { sameSecretConsistencyRoot, ...statementSetWithoutRoot } =
            sameSecretConsistency;
        const firstSourceTrusteeRecord = requiredSourceTrusteeRecord(
            vssCoefficientCommitments,
            0,
        );
        const firstStatementRecord = requiredStatementRecord(
            sameSecretConsistency.statementRecords,
            0,
        );
        const { sameSecretStatementRoot, ...statementWithoutRoot } =
            firstStatementRecord;
        const expectedSameSecretProofFamilyBindingRoot = deriveProtocolHash(
            'SameSecretProofFamilyBindingRoot',
            {
                objectType: 'SameSecretProofFamilyBinding',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: sameSecretProofFamily,
                sameSecretRelation,
                boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
                genericKeySwitchBindingPolicy:
                    sameSecretGenericKeySwitchBindingPolicy,
                targetDecryptionBindingPolicy:
                    sameSecretTargetDecryptionBindingPolicy,
            },
        );
        const expectedTrusteeSecretCommitmentRoot = deriveProtocolHash(
            'TrusteeSecretCommitmentRoot',
            {
                objectType: 'TrusteeSecretCommitment',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                commitmentProfileId: setupCommitmentProfileId,
                setupProofProfileId,
                ...setupContext,
                trusteeIdentity: firstSourceTrusteeRecord.sourceTrusteeIdentity,
                trusteeRosterPosition:
                    firstSourceTrusteeRecord.sourceTrusteeRosterPosition,
                vssSourceTrusteeCommitmentRoot:
                    firstSourceTrusteeRecord.sourceTrusteeCommitmentRoot,
                secretCommitmentSource: 'vss-constant-coefficient-commitments',
                sameSecretRelation,
                constantCoefficientCommitmentRoots:
                    firstStatementRecord.constantCoefficientCommitmentRoots,
            },
        );

        expect(
            sameSecretConsistency.statementRecords.map(
                (record) => record.trusteeRosterPosition,
            ),
        ).toEqual([0, 1, 2]);
        expect(sameSecretConsistency.vssCoefficientCommitmentRoot).toBe(
            vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        );
        expect(firstStatementRecord.constantCoefficientCommitmentRoots).toEqual(
            qSharePrimes.map((rnsPrime, rnsLimbIndex) => ({
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex: 0,
                commitmentRoot:
                    firstSourceTrusteeRecord.coefficientCommitments.find(
                        (record) =>
                            record.rnsLimbIndex === rnsLimbIndex &&
                            record.rnsPrime === rnsPrime &&
                            record.shamirCoefficientIndex === 0,
                    )?.commitmentRoot,
            })),
        );
        expect(firstStatementRecord.trusteeSecretCommitmentRoot).toBe(
            expectedTrusteeSecretCommitmentRoot,
        );
        expect(sameSecretConsistency.sameSecretProofFamilyBindingRoot).toBe(
            expectedSameSecretProofFamilyBindingRoot,
        );
        expect(firstStatementRecord.sameSecretProofFamilyBindingRoot).toBe(
            expectedSameSecretProofFamilyBindingRoot,
        );
        expect(statementWithoutRoot.trusteeSecretCommitmentRoot).toBe(
            sameSecretConsistency.trusteeSecretCommitmentRoots[0]
                ?.trusteeSecretCommitmentRoot,
        );
        expect(sameSecretStatementRoot).toBe(
            deriveProtocolHash(
                'SameSecretConsistencyRoot',
                statementWithoutRoot,
            ),
        );
        expect(sameSecretConsistencyRoot).toBe(
            deriveProtocolHash(
                'SameSecretConsistencyRoot',
                statementSetWithoutRoot,
            ),
        );
    });

    it('rejects malformed statement-set inputs before root publication', () => {
        const vssCoefficientCommitments = acceptedCommitmentSet();
        const firstSourceTrusteeRecord = requiredSourceTrusteeRecord(
            vssCoefficientCommitments,
            0,
        );
        const commitmentSetMissingSourceTrustee = {
            ...vssCoefficientCommitments,
            sourceTrusteeRecords:
                vssCoefficientCommitments.sourceTrusteeRecords.slice(1),
        } satisfies VssCoefficientCommitmentSet;
        const commitmentSetMissingConstant = {
            ...vssCoefficientCommitments,
            sourceTrusteeRecords: [
                {
                    ...firstSourceTrusteeRecord,
                    coefficientCommitments:
                        firstSourceTrusteeRecord.coefficientCommitments.filter(
                            (record) =>
                                !(
                                    record.rnsLimbIndex === 0 &&
                                    record.rnsPrime === qSharePrimes[0] &&
                                    record.shamirCoefficientIndex === 0
                                ),
                        ),
                },
                ...vssCoefficientCommitments.sourceTrusteeRecords.slice(1),
            ],
        } satisfies VssCoefficientCommitmentSet;

        expect(() =>
            createSameSecretConsistencyStatementSet({
                setupContext: {
                    ...setupContext,
                    setupEpoch: 'setup-epoch-2',
                },
                qSharePrimes,
                participantCount,
                thresholdDegree,
                vssCoefficientCommitments,
            }),
        ).toThrow(/must match setupContext/u);
        expect(() =>
            createSameSecretConsistencyStatementSet({
                setupContext,
                qSharePrimes,
                participantCount,
                thresholdDegree,
                vssCoefficientCommitments: commitmentSetMissingSourceTrustee,
            }),
        ).toThrow(/cover every participant/u);
        expect(() =>
            createSameSecretConsistencyStatementSet({
                setupContext,
                qSharePrimes,
                participantCount,
                thresholdDegree,
                vssCoefficientCommitments: commitmentSetMissingConstant,
            }),
        ).toThrow(/every constant coefficient commitment/u);
    });
});
