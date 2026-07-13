import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares,
    restoreAndPrepareLocalTargetDecryptionShareWitness,
} from '#packages/protocol/src/index';
import {
    type LocalTrusteeVssPublicAggregateOpeningCredentialHandoff,
    type VssPublicAggregateThresholdCommitmentSet,
} from '#packages/protocol/src/setup/vss-commitments';
import { withDeterministicWebCryptoRandomness } from '#tests/support/deterministic-web-crypto-randomness';
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
type AggregateThresholdCommitmentSet = VssPublicAggregateThresholdCommitmentSet;
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
}>;

const createEncryptedLocalTrusteeSetupStateFixture = (
    input: LocalTrusteeSetupStateInput,
): ReturnType<typeof createEncryptedLocalTrusteeSetupStateFromVerifiedShares> =>
    withDeterministicWebCryptoRandomness(
        ['61'.repeat(12), '51'.repeat(12)],
        () => createEncryptedLocalTrusteeSetupStateFromVerifiedShares(input),
    );

const setupArtifacts = (): SetupArtifacts => {
    const aggregateOpeningRoot = fixtureHash('aggregate-opening');
    const aggregateCommitment = {
        objectType: 'VssCommittedMaterialCommitment',
        commitmentRole: 'aggregate-threshold-share',
        commitmentContextHash: fixtureHash('aggregate-commitment-context'),
        rnsLimbIndex: 0,
        rnsPrime,
        ringDegree,
        commitmentFields: [],
    } as const;
    const aggregateCommitmentRoot =
        deriveCanonicalObjectHash(aggregateCommitment);
    const aggregateThresholdCommitmentSetWithoutRoot = {
        objectType: 'VssPublicAggregateThresholdCommitmentSet',
        publicMatrixSeedHash,
        participantCount: 1,
        rnsLimbCount: 1,
        ringDegree,
        recipientRecords: [
            {
                objectType: 'VssPublicAggregateThresholdCommitment',
                recipientIdentity: trusteeIdentity,
                recipientRosterPosition: trusteeRosterPosition,
                rnsLimbIndex: 0,
                rnsPrime,
                aggregateCommitmentRoot,
                aggregateOpeningRoot,
                commitment: aggregateCommitment,
            },
        ],
    } as const;
    const aggregateThresholdCommitmentSet = {
        ...aggregateThresholdCommitmentSetWithoutRoot,
        aggregateThresholdCommitmentRoot: deriveCanonicalObjectHash(
            aggregateThresholdCommitmentSetWithoutRoot,
        ),
        aggregateThresholdProofs: [],
    } satisfies AggregateThresholdCommitmentSet;
    const aggregateOpeningCredentialHandoff = {
        objectType: 'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff',
        trusteeIdentity,
        trusteeRosterPosition,
        aggregateOpeningCredentials: [
            {
                objectType: 'LocalTrusteeVssPublicAggregateOpeningCredential',
                recipientIdentity: trusteeIdentity,
                recipientRosterPosition: trusteeRosterPosition,
                rnsLimbIndex: 0,
                rnsPrime,
                aggregateCommitmentRoot,
                aggregateOpeningRoot,
                aggregateCommitmentMessageValuesLeHex:
                    '07000000000000000b00000000000000',
                aggregateMaterialSeedHex,
            },
        ],
    } as const satisfies LocalTrusteeVssPublicAggregateOpeningCredentialHandoff;
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
        aggregateOpeningCredentialHandoff,
        aggregateThresholdCommitmentSet,
        localStateInput: {
            setupContext,
            trusteeIdentity,
            trusteeRosterPosition,
            participantCount: 1,
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
                aggregateOpeningCredentialHandoff,
            storageKeyBytesHex: '41'.repeat(32),
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
    } as const;
};

describe('local setup-to-target-share witness lifecycle', () => {
    it('restores the setup-produced aggregate opening only from encrypted local state', async () => {
        const artifacts = setupArtifacts();
        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFixture(
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
        });
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
        const artifacts = setupArtifacts();
        const handoff = artifacts.aggregateOpeningCredentialHandoff;
        await expect(
            createEncryptedLocalTrusteeSetupStateFixture({
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
            createEncryptedLocalTrusteeSetupStateFixture({
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
            await createEncryptedLocalTrusteeSetupStateFixture({
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
            await createEncryptedLocalTrusteeSetupStateFixture(
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
