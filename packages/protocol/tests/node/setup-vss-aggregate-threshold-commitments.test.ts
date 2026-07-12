import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    assembleVssPublicAggregateThresholdCommitmentSet,
    appendVssAggregateThresholdProofMaterials,
    createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    createVssPublicCoefficientCommitmentSet,
    createVssPublicRecipientShareCommitmentSet,
    type LocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    type VssAggregateThresholdProofComputer,
    type VssCommittedMaterialCommitmentComputer,
    type VssPublicSourceTrusteeOpeningState,
} from '#packages/protocol/src/setup/vss-commitments';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash(
    'setup-vss-aggregate-threshold-commitments',
);
const setupContext = makeSetupContext(fixtureHash);
const publicMatrixSeedHash = fixtureHash('public-matrix-seed');
const qSharePrimes = [17] as const;
const ringDegree = 2;
const sourceTrusteeOpeningStates: readonly VssPublicSourceTrusteeOpeningState[] =
    [
        {
            sourceTrusteeIdentity: 'North trustee',
            sourceTrusteeRosterPosition: 0,
            coefficientOpenings: [
                {
                    rnsLimbIndex: 0,
                    rnsPrime: 17,
                    shamirCoefficientIndex: 0,
                    coefficientMessage: [16, 1],
                },
            ],
        },
        {
            sourceTrusteeIdentity: 'South trustee',
            sourceTrusteeRosterPosition: 1,
            coefficientOpenings: [
                {
                    rnsLimbIndex: 0,
                    rnsPrime: 17,
                    shamirCoefficientIndex: 0,
                    coefficientMessage: [2, 3],
                },
            ],
        },
    ];

const aggregateCommitmentContexts: Record<string, unknown>[] = [];

const computeVssCommittedMaterialCommitment: VssCommittedMaterialCommitmentComputer =
    (input) => {
        if (input.commitmentRole === 'aggregate-threshold-share') {
            aggregateCommitmentContexts.push(input.commitmentContext);
        }
        const commitmentContextHash = deriveCanonicalObjectHash({
            objectType: 'VssCommittedMaterialCommitmentContext',
            commitmentRole: input.commitmentRole,
            commitmentContext: input.commitmentContext,
        });
        const commitment = {
            objectType: 'VssCommittedMaterialCommitment' as const,
            commitmentRole: input.commitmentRole,
            commitmentContextHash,
            rnsLimbIndex: input.rnsLimbIndex,
            rnsPrime: input.rnsPrime,
            ringDegree: input.ringDegree,
            materialColumnMaskDegree: 0,
            commitmentFields: [],
        };

        return {
            commitment,
            commitmentRoot: deriveCanonicalObjectHash(commitment),
            openingRoot: deriveCanonicalObjectHash({
                objectType: 'FixtureVssOpening',
                materialSeedHex: input.materialSeedHex,
                messageCoefficients: input.messageCoefficients,
            }),
            commitmentContextHash,
        };
    };

const materialSeed = (coordinate: Record<string, unknown>): string =>
    deriveCanonicalObjectHash({
        objectType: 'FixtureVssMaterialSeed',
        ...coordinate,
    });

const generateAggregateThresholdProof: VssAggregateThresholdProofComputer = (
    input,
) => {
    const proofBytesHash = fixtureHash(
        `aggregate-proof-${input.context.shareLinkageStatementRoot}`,
    );
    const proofMaterialRoot = deriveCanonicalObjectHash({
        objectType: 'SetupProofMaterialReference',
        proofFamily: 'vss-share-linkage',
        proofBytesHash,
    });

    return Promise.resolve({
        proofBytesEncoding: 'binary-chunked-proof-bytes',
        proofBytesHash,
        proofMaterialRoot,
        canonicalMaterial: {
            descriptorBytes: canonicalStreamDescriptorFixture(1),
        },
    });
};

const littleEndianCoefficients = (hex: string): number[] => {
    const bytes = Uint8Array.from(
        hex.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? [],
    );
    const view = new DataView(bytes.buffer);

    return Array.from(
        { length: bytes.length / 8 },
        (_unused, coefficientIndex) =>
            Number(view.getBigUint64(coefficientIndex * 8, true)),
    );
};

describe('VSS aggregate threshold commitment handoff', () => {
    it('refuses recipient-share carries outside the JavaScript safe integer range', () => {
        const participantCount = 33;
        const thresholdDegree = 22;
        const largeRosterOpeningStates: readonly VssPublicSourceTrusteeOpeningState[] =
            Array.from(
                { length: participantCount },
                (_unused, sourceTrusteeRosterPosition) => ({
                    sourceTrusteeIdentity: `Trustee ${sourceTrusteeRosterPosition}`,
                    sourceTrusteeRosterPosition,
                    coefficientOpenings: Array.from(
                        { length: thresholdDegree },
                        (_unusedOpening, shamirCoefficientIndex) => ({
                            rnsLimbIndex: 0,
                            rnsPrime: 17,
                            shamirCoefficientIndex,
                            coefficientMessage: [16],
                        }),
                    ),
                }),
            );

        expect(() =>
            createVssPublicRecipientShareCommitmentSet({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes,
                ringDegree: 1,
                thresholdDegree,
                sourceTrusteeOpeningStates: largeRosterOpeningStates,
                committedMaterialSeed: materialSeed,
                computeVssCommittedMaterialCommitment,
            }),
        ).toThrow(
            'VSS recipient-share carry exceeds the JavaScript safe integer range',
        );
    });

    it('keeps opening credentials private and uses the accepted roster identities', async () => {
        aggregateCommitmentContexts.length = 0;
        const coefficientBundle = createVssPublicCoefficientCommitmentSet({
            setupContext,
            publicMatrixSeedHash,
            participantCount: 2,
            qSharePrimes,
            ringDegree,
            thresholdDegree: 1,
            sourceTrusteeOpeningStates,
            committedMaterialSeed: materialSeed,
            computeVssCommittedMaterialCommitment,
        });
        const recipientBundle = createVssPublicRecipientShareCommitmentSet({
            setupContext,
            publicMatrixSeedHash,
            participantCount: 2,
            qSharePrimes,
            ringDegree,
            thresholdDegree: 1,
            sourceTrusteeOpeningStates,
            committedMaterialSeed: materialSeed,
            computeVssCommittedMaterialCommitment,
        });
        const createLocalAggregateBundle = (
            localTrusteeRosterPosition: number,
            localRecipientShareCredentials: typeof recipientBundle.recipientShareCredentials = recipientBundle.recipientShareCredentials.filter(
                (credential) =>
                    credential.recipientRosterPosition ===
                    localTrusteeRosterPosition,
            ),
        ): Promise<LocalTrusteeVssPublicAggregateThresholdCommitmentBundle> =>
            createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount: 2,
                qSharePrimes,
                ringDegree,
                coefficientCommitmentSet:
                    coefficientBundle.coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientBundle.recipientShareCommitmentSet,
                localTrusteeRosterPosition,
                localRecipientShareCredentials,
                committedMaterialSeed: materialSeed,
                computeVssCommittedMaterialCommitment,
                aggregateThresholdProofRandomness: ({
                    recipientRosterPosition,
                    rnsLimbIndex,
                }) => ({
                    seedHex: materialSeed({
                        recipientRosterPosition,
                        rnsLimbIndex,
                        purpose: 'proof-seed',
                    }),
                    nonceHex: materialSeed({
                        recipientRosterPosition,
                        rnsLimbIndex,
                        purpose: 'proof-nonce',
                    }),
                }),
                generateVssShareLinkageProof: generateAggregateThresholdProof,
            });
        const localAggregateBundles = [
            await createLocalAggregateBundle(0),
            await createLocalAggregateBundle(1),
        ];
        const aggregateThresholdCommitmentSet =
            assembleVssPublicAggregateThresholdCommitmentSet({
                publicMatrixSeedHash,
                participantCount: 2,
                qSharePrimes,
                ringDegree,
                recipientShareCommitmentSet:
                    recipientBundle.recipientShareCommitmentSet,
                publicAggregateThresholdCommitmentContributions:
                    localAggregateBundles.map(
                        (bundle) =>
                            bundle.publicAggregateThresholdCommitmentContribution,
                    ),
            });

        expect(
            aggregateThresholdCommitmentSet.recipientRecords.map(
                (record) => record.recipientIdentity,
            ),
        ).toEqual(['North trustee', 'South trustee']);
        expect(
            localAggregateBundles.map(
                (bundle) =>
                    bundle.localTrusteeAggregateOpeningCredentialHandoff
                        .trusteeIdentity,
            ),
        ).toEqual(['North trustee', 'South trustee']);
        expect(
            littleEndianCoefficients(
                localAggregateBundles[0]
                    ?.localTrusteeAggregateOpeningCredentialHandoff
                    ?.aggregateOpeningCredentials[0]
                    ?.aggregateCommitmentMessageValuesLeHex ?? '',
            ),
        ).toEqual([1, 4]);
        expect(
            localAggregateBundles.flatMap((bundle) =>
                bundle.localTrusteeAggregateOpeningCredentialHandoff.aggregateOpeningCredentials.map(
                    (credential) => ({
                        recipientRosterPosition:
                            credential.recipientRosterPosition,
                        aggregateCommitmentRoot:
                            credential.aggregateCommitmentRoot,
                        aggregateOpeningRoot: credential.aggregateOpeningRoot,
                    }),
                ),
            ),
        ).toEqual(
            aggregateThresholdCommitmentSet.recipientRecords.map((record) => ({
                recipientRosterPosition: record.recipientRosterPosition,
                aggregateCommitmentRoot: record.aggregateCommitmentRoot,
                aggregateOpeningRoot: record.aggregateOpeningRoot,
            })),
        );
        expect(
            aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
        ).toBe(
            deriveCanonicalObjectHash({
                objectType: 'VssPublicAggregateThresholdCommitmentSet',
                publicMatrixSeedHash,
                participantCount: 2,
                rnsLimbCount: 1,
                ringDegree,
                recipientRecords:
                    aggregateThresholdCommitmentSet.recipientRecords,
            }),
        );
        expect(
            aggregateThresholdCommitmentSet.aggregateThresholdProofs.every(
                (proof) =>
                    proof.proofBytesEncoding === 'binary-chunked-proof-bytes',
            ),
        ).toBe(true);
        expect(
            localAggregateBundles.flatMap(
                (bundle) => bundle.aggregateThresholdProofMaterials,
            ),
        ).toHaveLength(2);
        const aggregateProofMaterials = localAggregateBundles.flatMap(
            (bundle) => bundle.aggregateThresholdProofMaterials,
        );
        const transportedProofMaterialSet =
            appendVssAggregateThresholdProofMaterials(
                {
                    objectType:
                        'SetupTransportedVssShareLinkageProofMaterialSet',
                    proofFamily: 'vss-share-linkage',
                    proofMaterials: [],
                },
                aggregateProofMaterials,
            );
        expect(
            transportedProofMaterialSet.proofMaterials.map((material) => ({
                proofMaterialRoot: material.proofMaterialRoot,
                hasDescriptor: material.descriptorBytes instanceof Uint8Array,
            })),
        ).toEqual(
            aggregateProofMaterials.map((material) => ({
                proofMaterialRoot: material.proofMaterialRoot,
                hasDescriptor: true,
            })),
        );
        expect(() =>
            appendVssAggregateThresholdProofMaterials(
                transportedProofMaterialSet,
                aggregateProofMaterials,
            ),
        ).toThrow(
            'Aggregate threshold proof material must be a unique VSS share-linkage transport entry.',
        );
        await expect(
            createLocalAggregateBundle(
                0,
                recipientBundle.recipientShareCredentials,
            ),
        ).rejects.toThrow(
            'Local aggregate threshold commitment accepts credentials for exactly one recipient.',
        );
        expect(aggregateCommitmentContexts).toEqual([
            {
                objectType: 'VssPublicAggregateThresholdCommitmentContext',
                ceremonyId: setupContext.ceremonyId,
                manifestHash: setupContext.manifestHash,
                rosterHash: setupContext.rosterHash,
                setupParametersHash: setupContext.setupParametersHash,
                setupEpoch: setupContext.setupEpoch,
                recipientIdentity: 'North trustee',
                recipientRosterPosition: 0,
                recipientTrusteePoint: 1,
                rnsLimbIndex: 0,
                rnsPrime: 17,
            },
            {
                objectType: 'VssPublicAggregateThresholdCommitmentContext',
                ceremonyId: setupContext.ceremonyId,
                manifestHash: setupContext.manifestHash,
                rosterHash: setupContext.rosterHash,
                setupParametersHash: setupContext.setupParametersHash,
                setupEpoch: setupContext.setupEpoch,
                recipientIdentity: 'South trustee',
                recipientRosterPosition: 1,
                recipientTrusteePoint: 2,
                rnsLimbIndex: 0,
                rnsPrime: 17,
            },
        ]);
    });
});
