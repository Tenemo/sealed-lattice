import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createCompactVssCoefficientCommitmentSet,
    createCompactVssSameSecretBridgeStatementSet,
    createSameSecretConsistencyStatementSet,
    createSameSecretProofSet,
    createVssCoefficientCommitmentBundle,
    verifyCompactVssSameSecretBridgeStatementSet,
    compactVssCommitmentBinaryFormat,
    compactVssSameSecretBridgeIntegerSupport,
    sameSecretAnchorArgument,
    sameSecretBoundProofFamilies,
    sameSecretGenericKeySwitchBindingPolicy,
    compactVssSameSecretBridgeSignedRepresentativeConvention,
    compactVssSameSecretBridgeTargetBasisLimbOrder,
    sameSecretProofFamily,
    sameSecretRelation,
    sameSecretTargetDecryptionBindingPolicy,
    setupCommitmentProfileId,
    setupProofProfileId,
    type VssCoefficientCommitmentBundle,
    type VssCoefficientCommitmentSet,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientCommitmentRecord,
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
const participantCount = 3;
const thresholdDegree = 2;

const fixtureHash = makeSetupFixtureHash(
    'setup-same-secret-consistency-records',
);

const setupContext = makeSetupContext(fixtureHash);

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

const acceptedCommitmentBundle = (): VssCoefficientCommitmentBundle =>
    createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        setupCommitmentComputer,
        qSharePrimes,
        ringDegree,
        participantCount,
        thresholdDegree,
        sourceTrusteeOpeningStates: [
            sourceTrusteeOpeningState(2),
            sourceTrusteeOpeningState(0),
            sourceTrusteeOpeningState(1),
        ],
    });

const acceptedCommitmentSet = (): VssCoefficientCommitmentSet =>
    acceptedCommitmentBundle().commitmentSet;

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

const requiredStatementRecord = <StatementRecord>(
    statementRecords: readonly StatementRecord[],
    statementRecordIndex: number,
): StatementRecord => {
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
                anchorArgument: sameSecretAnchorArgument,
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

    it('binds compact target-basis constants to same-secret statement and proof roots', () => {
        const vssCoefficientBundle = acceptedCommitmentBundle();
        const sameSecretConsistency = createSameSecretConsistencyStatementSet({
            setupContext,
            qSharePrimes,
            participantCount,
            thresholdDegree,
            vssCoefficientCommitments: vssCoefficientBundle.commitmentSet,
        });
        const sameSecretProofs = createSameSecretProofSet({
            setupContext,
            qSharePrimes,
            participantCount,
            sameSecretConsistency,
            vssCoefficientCommitmentMaterial: vssCoefficientBundle.materialSet,
            proofAccountingHash: fixtureHash('same-secret-proof-accounting'),
            proofMaterials: sameSecretConsistency.statementRecords.map(
                (statementRecord) => ({
                    setupProofProfileId,
                    proofFamily: sameSecretProofFamily,
                    trusteeIdentity: statementRecord.trusteeIdentity,
                    trusteeRosterPosition:
                        statementRecord.trusteeRosterPosition,
                    statementHash: fixtureHash(
                        `same-secret-statement-${String(statementRecord.trusteeRosterPosition)}`,
                    ),
                    proofSizeBytes: 1,
                    proofBytesHash: fixtureHash(
                        `same-secret-proof-bytes-${String(statementRecord.trusteeRosterPosition)}`,
                    ),
                    proofBytesHex: '00',
                }),
            ),
        });
        const compactPublicMatrixSeedHash = fixtureHash(
            'compact-public-matrix-seed',
        );
        const compactCoefficientCommitmentSet =
            createCompactVssCoefficientCommitmentSet({
                setupContext,
                publicMatrixSeedHash: compactPublicMatrixSeedHash,
                participantCount,
                qSharePrimes,
                ringDegree,
                thresholdDegree,
                sourceTrusteeOpeningStates: [
                    sourceTrusteeOpeningState(2),
                    sourceTrusteeOpeningState(0),
                    sourceTrusteeOpeningState(1),
                ],
                coefficientOpeningRandomness: ({
                    trusteeRosterPosition,
                    rnsLimbIndex,
                    shamirCoefficientIndex,
                    ringDegree: compactRingDegree,
                }) => [
                    Array.from(
                        { length: compactRingDegree },
                        (_unused, coefficientIndex) =>
                            ((trusteeRosterPosition +
                                rnsLimbIndex +
                                shamirCoefficientIndex +
                                coefficientIndex) %
                                3) -
                            1,
                    ),
                    Array.from(
                        { length: compactRingDegree },
                        (_unused, coefficientIndex) =>
                            ((trusteeRosterPosition +
                                rnsLimbIndex +
                                shamirCoefficientIndex +
                                coefficientIndex +
                                1) %
                                3) -
                            1,
                    ),
                ],
            });
        const bridgeStatementSet = createCompactVssSameSecretBridgeStatementSet(
            {
                setupContext,
                targetBasisHash: fixtureHash('compact-target-basis'),
                publicMatrixSeedHash: compactPublicMatrixSeedHash,
                compactCoefficientCommitmentSet,
                sameSecretConsistency,
                sameSecretProofs,
            },
        );
        const firstBridgeStatement = requiredStatementRecord(
            bridgeStatementSet.statementRecords,
            0,
        );
        const {
            compactSameSecretBridgeStatementRoot,
            ...bridgeStatementWithoutRoot
        } = firstBridgeStatement;
        const {
            compactSameSecretBridgeStatementSetRoot,
            ...bridgeStatementSetWithoutRoot
        } = bridgeStatementSet;

        expect(bridgeStatementSet.compactCoefficientCommitmentRoot).toBe(
            compactCoefficientCommitmentSet.coefficientCommitmentRoot,
        );
        expect(bridgeStatementSet.sameSecretConsistencyRoot).toBe(
            sameSecretConsistency.sameSecretConsistencyRoot,
        );
        expect(bridgeStatementSet.sameSecretProofSetRoot).toBe(
            sameSecretProofs.sameSecretProofSetRoot,
        );
        expect(bridgeStatementSet).toMatchObject({
            integerSupport: compactVssSameSecretBridgeIntegerSupport,
            signedRepresentativeConvention:
                compactVssSameSecretBridgeSignedRepresentativeConvention,
            compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
            targetBasisLimbOrder:
                compactVssSameSecretBridgeTargetBasisLimbOrder,
        });
        expect(firstBridgeStatement).toMatchObject({
            integerSupport: bridgeStatementSet.integerSupport,
            signedRepresentativeConvention:
                bridgeStatementSet.signedRepresentativeConvention,
            compactCommitmentEncoding:
                bridgeStatementSet.compactCommitmentEncoding,
            targetBasisLimbOrder: bridgeStatementSet.targetBasisLimbOrder,
        });
        expect(
            firstBridgeStatement.targetConstantCoefficientCommitmentRoots,
        ).toHaveLength(qSharePrimes.length);
        expect(firstBridgeStatement.sameSecretStatementRoot).toBe(
            sameSecretConsistency.statementRecords[0]?.sameSecretStatementRoot,
        );
        expect(firstBridgeStatement.sameSecretProofRoot).toBe(
            sameSecretProofs.proofRecords[0]?.sameSecretProofRoot,
        );
        expect(compactSameSecretBridgeStatementRoot).toBe(
            deriveProtocolHash(
                'SetupProofRecordBindingHash',
                bridgeStatementWithoutRoot,
            ),
        );
        expect(compactSameSecretBridgeStatementSetRoot).toBe(
            deriveProtocolHash(
                'SetupProofRecordBindingHash',
                bridgeStatementSetWithoutRoot,
            ),
        );
        expect(
            verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: bridgeStatementSet,
                sameSecretConsistency,
                sameSecretProofs,
            }),
        ).toBe(bridgeStatementSet);

        const forgedProofRootStatement = {
            ...firstBridgeStatement,
            sameSecretProofRoot: '0'.repeat(128),
        } as typeof firstBridgeStatement;
        const {
            compactSameSecretBridgeStatementRoot: _oldForgedStatementRoot,
            ...forgedProofRootStatementWithoutRoot
        } = forgedProofRootStatement;
        const reboundForgedProofRootStatement = {
            ...forgedProofRootStatement,
            compactSameSecretBridgeStatementRoot: deriveProtocolHash(
                'SetupProofRecordBindingHash',
                forgedProofRootStatementWithoutRoot,
            ),
        };
        const forgedProofRootSet = {
            ...bridgeStatementSet,
            statementRecords: [
                reboundForgedProofRootStatement,
                ...bridgeStatementSet.statementRecords.slice(1),
            ],
        } as typeof bridgeStatementSet;
        const {
            compactSameSecretBridgeStatementSetRoot: _oldForgedSetRoot,
            ...forgedProofRootSetWithoutRoot
        } = forgedProofRootSet;
        const reboundForgedProofRootSet = {
            ...forgedProofRootSet,
            compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
                'SetupProofRecordBindingHash',
                forgedProofRootSetWithoutRoot,
            ),
        };
        expect(
            verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: reboundForgedProofRootSet,
            }),
        ).toBe(reboundForgedProofRootSet);
        expect(() =>
            verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: reboundForgedProofRootSet,
                sameSecretConsistency,
                sameSecretProofs,
            }),
        ).toThrow(/evidence roots/u);

        const unsupportedBoundaryStatement = {
            ...firstBridgeStatement,
            proofBoundary: 'unsupported compact same-secret bridge boundary',
        } as unknown as typeof firstBridgeStatement;
        const {
            compactSameSecretBridgeStatementRoot: _oldStatementRoot,
            ...unsupportedBoundaryStatementWithoutRoot
        } = unsupportedBoundaryStatement;
        const reboundUnsupportedBoundaryStatement = {
            ...unsupportedBoundaryStatement,
            compactSameSecretBridgeStatementRoot: deriveProtocolHash(
                'SetupProofRecordBindingHash',
                unsupportedBoundaryStatementWithoutRoot,
            ),
        };
        const unsupportedBoundarySet = {
            ...bridgeStatementSet,
            statementRecords: [
                reboundUnsupportedBoundaryStatement,
                ...bridgeStatementSet.statementRecords.slice(1),
            ],
        } as unknown as typeof bridgeStatementSet;
        const {
            compactSameSecretBridgeStatementSetRoot: _oldStatementSetRoot,
            ...unsupportedBoundarySetWithoutRoot
        } = unsupportedBoundarySet;

        expect(() =>
            verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: {
                    ...unsupportedBoundarySet,
                    compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
                        'SetupProofRecordBindingHash',
                        unsupportedBoundarySetWithoutRoot,
                    ),
                },
            }),
        ).toThrow(/proofBoundary/u);

        const unsupportedSignedConventionSet = {
            ...bridgeStatementSet,
            signedRepresentativeConvention:
                'unsupported compact bridge signed representative convention',
        } as unknown as typeof bridgeStatementSet;
        const {
            compactSameSecretBridgeStatementSetRoot:
                _oldConventionStatementSetRoot,
            ...unsupportedSignedConventionSetWithoutRoot
        } = unsupportedSignedConventionSet;

        expect(() =>
            verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: {
                    ...unsupportedSignedConventionSet,
                    compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
                        'SetupProofRecordBindingHash',
                        unsupportedSignedConventionSetWithoutRoot,
                    ),
                },
            }),
        ).toThrow(/signedRepresentativeConvention/u);
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
