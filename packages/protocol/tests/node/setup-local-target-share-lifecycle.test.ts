import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares,
    restoreAndPrepareLocalTargetDecryptionShareWitness,
} from '#packages/protocol/src/index';
import {
    assembleVssPublicAggregateThresholdCommitmentSet,
    createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    createVssPublicCoefficientCommitmentSet,
    createVssPublicRecipientShareCommitmentSet,
    type LocalTrusteeVssPublicAggregateOpeningCredentialHandoff,
    type VssAggregateThresholdProofComputer,
    type VssCommittedMaterialCommitmentComputer,
} from '#packages/protocol/src/setup/vss-commitments';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash('setup-local-target-share-lifecycle');
const setupContext = makeSetupContext(fixtureHash);
const trusteeIdentity = 'North trustee';
const trusteeRosterPosition = 0;
const publicMatrixSeedHash = fixtureHash('public-matrix-seed');
const rnsPrime = 17;
const ringDegree = 2;
const aggregateMaterialSeedHex = fixtureHash('aggregate-material-seed');

const generateAggregateThresholdProof: VssAggregateThresholdProofComputer = (
    input,
) => {
    const proofBytesHash = fixtureHash(
        `aggregate-proof-${input.context.shareLinkageStatementRoot}`,
    );

    return Promise.resolve({
        proofBytesHash,
        proofMaterialRoot: deriveCanonicalObjectHash({
            objectType: 'SetupProofMaterialReference',
            proofFamily: 'vss-share-linkage',
            proofBytesHash,
        }),
        canonicalMaterial: {
            descriptorBytes: canonicalStreamDescriptorFixture(1),
        },
    });
};

type AggregateThresholdCommitmentSet = ReturnType<
    typeof assembleVssPublicAggregateThresholdCommitmentSet
>;
type LocalTrusteeSetupStateInput = Parameters<
    typeof createEncryptedLocalTrusteeSetupStateFromVerifiedShares
>[0];
type SetupArtifacts = Readonly<{
    aggregateOpeningCredentialHandoff: LocalTrusteeVssPublicAggregateOpeningCredentialHandoff;
    aggregateThresholdCommitmentSet: AggregateThresholdCommitmentSet;
    localStateInput: LocalTrusteeSetupStateInput;
}>;
type TargetContext = Readonly<{
    setupPackage: Readonly<{
        objectType: 'SetupPackage';
        setupContext: typeof setupContext;
        commonRandomness: Readonly<{ publicMatrixSeedHash: string }>;
        vssShareLinkageStatement: Readonly<{ statementRoot: string }>;
        vssPublicAggregateThresholdCommitmentSet: AggregateThresholdCommitmentSet;
    }>;
    targetAcceptedRecord: Readonly<{
        objectType: 'TargetAcceptedRecord';
        targetAcceptedRecordHash: string;
        targetContextHash: string;
        targetCiphertextHash: string;
        targetBasisHash: string;
    }>;
    targetDecryptionCiphertextHash: string;
    targetShareProfile: Readonly<{ targetShareProfileHash: string }>;
}>;

const computeVssCommittedMaterialCommitment: VssCommittedMaterialCommitmentComputer =
    (input) => {
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

const setupArtifacts = async (): Promise<SetupArtifacts> => {
    const sourceTrusteeOpeningStates = [
        {
            sourceTrusteeIdentity: trusteeIdentity,
            sourceTrusteeRosterPosition: trusteeRosterPosition,
            coefficientOpenings: [
                {
                    rnsLimbIndex: 0,
                    rnsPrime,
                    shamirCoefficientIndex: 0,
                    coefficientMessage: [7, 11],
                },
            ],
        },
    ] as const;
    const committedMaterialSeed = (
        coordinate: Record<string, unknown>,
    ): string =>
        coordinate.commitmentRole === 'aggregate-threshold-share'
            ? aggregateMaterialSeedHex
            : deriveCanonicalObjectHash({
                  objectType: 'FixtureVssMaterialSeed',
                  ...coordinate,
              });
    const coefficientBundle = createVssPublicCoefficientCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount: 1,
        qSharePrimes: [rnsPrime],
        ringDegree,
        thresholdDegree: 1,
        sourceTrusteeOpeningStates,
        committedMaterialSeed,
        computeVssCommittedMaterialCommitment,
    });
    const recipientBundle = createVssPublicRecipientShareCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount: 1,
        qSharePrimes: [rnsPrime],
        ringDegree,
        thresholdDegree: 1,
        sourceTrusteeOpeningStates,
        committedMaterialSeed,
        computeVssCommittedMaterialCommitment,
    });
    const aggregateBundle =
        await createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle({
            setupContext,
            publicMatrixSeedHash,
            participantCount: 1,
            qSharePrimes: [rnsPrime],
            ringDegree,
            coefficientCommitmentSet:
                coefficientBundle.coefficientCommitmentSet,
            recipientShareCommitmentSet:
                recipientBundle.recipientShareCommitmentSet,
            localTrusteeRosterPosition: trusteeRosterPosition,
            localRecipientShareCredentials:
                recipientBundle.recipientShareCredentials,
            committedMaterialSeed,
            computeVssCommittedMaterialCommitment,
            aggregateThresholdProofRandomness: () => ({
                seedHex: fixtureHash('aggregate-proof-seed'),
                nonceHex: fixtureHash('aggregate-proof-nonce'),
            }),
            generateVssShareLinkageProof: generateAggregateThresholdProof,
        });
    const aggregateThresholdCommitmentSet =
        assembleVssPublicAggregateThresholdCommitmentSet({
            publicMatrixSeedHash,
            participantCount: 1,
            qSharePrimes: [rnsPrime],
            ringDegree,
            recipientShareCommitmentSet:
                recipientBundle.recipientShareCommitmentSet,
            publicAggregateThresholdCommitmentContributions: [
                aggregateBundle.publicAggregateThresholdCommitmentContribution,
            ],
        });
    const sourceTrusteeCommitmentRoot = fixtureHash(
        'source-trustee-commitment',
    );
    const privateEnvelope = {
        objectType: 'PrivateVssShareEnvelope',
        ...setupContext,
        sourceTrusteeIdentity: trusteeIdentity,
        sourceTrusteeRosterPosition: trusteeRosterPosition,
        recipientIdentity: trusteeIdentity,
        recipientRosterPosition: trusteeRosterPosition,
        sourceTrusteeCommitmentRoot,
        rnsShareOpenings: [
            {
                objectType: 'PrivateVssShareOpening',
                rnsLimbIndex: 0,
                rnsPrime,
                shareValues: [7, 11],
            },
        ],
    };
    const privateEnvelopeHash = deriveCanonicalObjectHash(privateEnvelope);
    const privateVssEnvelopeCommitmentRoot = fixtureHash(
        'private-envelope-commitment-set',
    );
    const thresholdShareCommitmentRecipientRoot = fixtureHash(
        'threshold-share-recipient',
    );

    return {
        aggregateOpeningCredentialHandoff:
            aggregateBundle.localTrusteeAggregateOpeningCredentialHandoff,
        aggregateThresholdCommitmentSet,
        localStateInput: {
            setupContext,
            trusteeIdentity,
            trusteeRosterPosition,
            deviceEpoch: 2,
            thresholdShareCommitments: {
                objectType: 'ThresholdShareCommitmentSet',
                ...setupContext,
                recipientRecords: [
                    {
                        recipientIdentity: trusteeIdentity,
                        recipientRosterPosition: trusteeRosterPosition,
                        recipientCommitmentRoot:
                            thresholdShareCommitmentRecipientRoot,
                    },
                ],
            },
            privateVssEnvelopeCommitments: {
                objectType: 'PrivateVssEnvelopeCommitmentSet',
                ...setupContext,
                participantCount: 1,
                privateVssEnvelopeCommitmentRoot,
                envelopeReferences: [
                    {
                        ...setupContext,
                        sourceTrusteeIdentity: trusteeIdentity,
                        sourceTrusteeRosterPosition: trusteeRosterPosition,
                        recipientIdentity: trusteeIdentity,
                        recipientRosterPosition: trusteeRosterPosition,
                        sourceTrusteeCommitmentRoot,
                        privateEnvelopeHash,
                        localVerificationRoot:
                            fixtureHash('local-verification'),
                    },
                ],
            },
            verifiedPrivateVssShareEnvelopes: [privateEnvelope],
            localTrusteeAggregateOpeningCredentialHandoff:
                aggregateBundle.localTrusteeAggregateOpeningCredentialHandoff,
            vssShareAcceptances: {
                objectType: 'VssShareAcceptanceSet',
                ...setupContext,
                acceptanceRecords: [
                    {
                        ...setupContext,
                        sourceTrusteeIdentity: trusteeIdentity,
                        sourceTrusteeRosterPosition: trusteeRosterPosition,
                        recipientIdentity: trusteeIdentity,
                        recipientRosterPosition: trusteeRosterPosition,
                        privateVssEnvelopeCommitmentRoot,
                        acceptanceRoot: fixtureHash('acceptance-root'),
                    },
                ],
            },
            storageKeyBytesHex: '41'.repeat(32),
            localStateAeadNonceBytesHex: '51'.repeat(12),
            sealedAggregateThresholdShareAeadNonceBytesHex: '61'.repeat(12),
        },
    } as const;
};

const targetContext = (
    aggregateThresholdCommitmentSet: AggregateThresholdCommitmentSet,
): TargetContext => {
    const targetBasisHash = fixtureHash('target-basis');
    const targetAcceptedRecord = {
        objectType: 'TargetAcceptedRecord',
        targetAcceptedRecordHash: fixtureHash('target-accepted-record'),
        targetContextHash: fixtureHash('target-context'),
        targetCiphertextHash: fixtureHash('target-ciphertext'),
        targetBasisHash,
    } as const;
    const setupPackage = {
        objectType: 'SetupPackage',
        setupContext,
        commonRandomness: { publicMatrixSeedHash },
        vssShareLinkageStatement: {
            statementRoot: fixtureHash('share-linkage-statement'),
        },
        vssPublicAggregateThresholdCommitmentSet:
            aggregateThresholdCommitmentSet,
    } as const;

    return {
        setupPackage,
        targetAcceptedRecord,
        targetDecryptionCiphertextHash: fixtureHash(
            'target-decryption-ciphertext',
        ),
        targetShareProfile: {
            targetShareProfileHash: fixtureHash('target-share-profile'),
        },
    } as const;
};

describe('local setup-to-target-share witness lifecycle', () => {
    it('restores the setup-produced aggregate opening only from encrypted local state', async () => {
        const artifacts = await setupArtifacts();
        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                artifacts.localStateInput,
            );
        const target = targetContext(artifacts.aggregateThresholdCommitmentSet);
        const preparedWitness =
            await restoreAndPrepareLocalTargetDecryptionShareWitness({
                encryptedLocalState: encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex:
                    artifacts.localStateInput.storageKeyBytesHex,
                ...target,
            });

        expect(
            JSON.stringify(encryptedState.encryptedLocalState),
        ).not.toContain(aggregateMaterialSeedHex);
        expect(
            JSON.stringify(encryptedState.localStatePlaintext),
        ).not.toContain(aggregateMaterialSeedHex);
        const [originalCredential] =
            artifacts.aggregateOpeningCredentialHandoff
                .aggregateOpeningCredentials;
        if (originalCredential === undefined) {
            throw new Error('fixture must contain an aggregate credential.');
        }
        const {
            aggregateCommitmentMessageValuesLeHex: originalMessageHex,
            ...credentialSidecar
        } = originalCredential;
        expect(preparedWitness.localTargetShareWitness).toMatchObject({
            objectType: 'LocalTrusteeTargetDecryptionProofWitnessMaterial',
            trusteeIdentity,
            trusteeRosterPosition,
            aggregateOpening: {
                objectType: 'LocalTrusteeVssPublicAggregateOpeningWitness',
                aggregateOpeningCredentials: [credentialSidecar],
            },
            targetDecryptionSmudging: {
                trusteeIdentity,
                rosterPosition: trusteeRosterPosition,
                interpolationPoint: trusteeRosterPosition + 1,
                targetBasisHash: fixtureHash('target-basis'),
            },
        });
        expect(
            JSON.stringify(preparedWitness.localTargetShareWitness),
        ).not.toContain('aggregateCommitmentMessageValuesLeHex');
        const [materialSource] =
            preparedWitness.aggregateOpeningMaterialSources;
        expect(materialSource).toMatchObject({
            aggregateOpeningRoot: originalCredential.aggregateOpeningRoot,
            totalByteLength: ringDegree * 8,
        });
        if (materialSource === undefined) {
            throw new Error('prepared witness must expose a material source.');
        }
        const materialBytes = await materialSource.pullChunk({
            chunkIndex: 0,
            expectedByteLength: ringDegree * 8,
        });
        expect(materialBytes).toBeInstanceOf(ArrayBuffer);
        expect(
            Buffer.from(materialBytes ?? new ArrayBuffer(0)).toString('hex'),
        ).toBe(originalMessageHex);
        await expect(
            materialSource.pullChunk({
                chunkIndex: 1,
                expectedByteLength: 0,
            }),
        ).resolves.toBeUndefined();
        await expect(
            materialSource.pullChunk({
                chunkIndex: 0,
                expectedByteLength: ringDegree * 8 - 1,
            }),
        ).rejects.toThrow(/non-canonical chunk length/u);
    });

    it('rejects changed trustee, aggregate message, accepted root, and setup context', async () => {
        const artifacts = await setupArtifacts();
        const handoff = artifacts.aggregateOpeningCredentialHandoff;
        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...artifacts.localStateInput,
                localTrusteeAggregateOpeningCredentialHandoff: {
                    ...handoff,
                    trusteeIdentity: 'South trustee',
                },
            }),
        ).rejects.toThrow(/must belong to the local trustee/u);

        const credential = handoff.aggregateOpeningCredentials[0];
        if (credential === undefined) {
            throw new Error('fixture must contain an aggregate credential.');
        }
        const changedMessageHandoff = {
            ...handoff,
            aggregateOpeningCredentials: [
                {
                    ...credential,
                    aggregateCommitmentMessageValuesLeHex: `08${credential.aggregateCommitmentMessageValuesLeHex.slice(2)}`,
                },
            ],
        } satisfies LocalTrusteeVssPublicAggregateOpeningCredentialHandoff;
        await expect(
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...artifacts.localStateInput,
                localTrusteeAggregateOpeningCredentialHandoff:
                    changedMessageHandoff,
            }),
        ).rejects.toThrow(/must match the aggregate/u);

        const changedRootHandoff = {
            ...handoff,
            aggregateOpeningCredentials: [
                {
                    ...credential,
                    aggregateCommitmentRoot: fixtureHash(
                        'changed-aggregate-root',
                    ),
                },
            ],
        } satisfies LocalTrusteeVssPublicAggregateOpeningCredentialHandoff;
        const encryptedChangedRootState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                ...artifacts.localStateInput,
                localTrusteeAggregateOpeningCredentialHandoff:
                    changedRootHandoff,
            });
        const target = targetContext(artifacts.aggregateThresholdCommitmentSet);
        await expect(
            restoreAndPrepareLocalTargetDecryptionShareWitness({
                encryptedLocalState:
                    encryptedChangedRootState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedChangedRootState.localStateCommitment
                        .localStateRoot,
                setupContext,
                storageKeyBytesHex:
                    artifacts.localStateInput.storageKeyBytesHex,
                ...target,
            }),
        ).rejects.toThrow(/must match the accepted aggregate commitment/u);

        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                artifacts.localStateInput,
            );
        await expect(
            restoreAndPrepareLocalTargetDecryptionShareWitness({
                encryptedLocalState: encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex:
                    artifacts.localStateInput.storageKeyBytesHex,
                ...target,
                setupPackage: {
                    ...target.setupPackage,
                    setupContext: {
                        ...setupContext,
                        setupEpoch: 'changed-setup-epoch',
                    },
                },
            }),
        ).rejects.toThrow(/setupEpoch must match/u);
    });
});
