import { webcrypto } from 'node:crypto';

import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { afterEach, describe, expect, it } from 'vitest';

import {
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares,
    restoreAndPrepareLocalTargetDecryptionShareWitness,
} from '#packages/protocol/src/index';
import {
    type BrowserActionStorageCustody,
    type BrowserActionStorageRootBinding,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    type LocalTrusteeVssPublicAggregateOpeningCredentialHandoff,
    type VssPublicAggregateThresholdCommitmentSet,
} from '#packages/protocol/src/setup/vss-commitments';
import {
    createActiveTestActionStorageCustody,
    createTestBytes,
    testActionStorageRootByteLength,
} from '#packages/protocol/tests/support/action-storage-custody-test-support';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash('setup-local-target-share-lifecycle');
const setupContext = makeSetupContext(fixtureHash, 1);
const setupContextHash = deriveCanonicalObjectHash({
    objectType: 'CollectiveBgvSetupContext',
    ...setupContext,
});
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
type LocalTrusteeSetupStateInputWithoutCustody = Omit<
    LocalTrusteeSetupStateInput,
    'storageCustody'
>;
type SetupArtifacts = Readonly<{
    aggregateOpeningCredentialHandoff: LocalTrusteeVssPublicAggregateOpeningCredentialHandoff;
    aggregateThresholdCommitmentSet: AggregateThresholdCommitmentSet;
    localStateInput: LocalTrusteeSetupStateInputWithoutCustody;
}>;
type TargetSetupInput = Readonly<{
    setupPackage: Readonly<{
        objectType: 'SetupPackage';
        setupContext: typeof setupContext;
        commonRandomness: Readonly<{ publicMatrixSeedHash: string }>;
        vssShareLinkageStatement: Readonly<{
            statementRoot: string;
            qShareRnsLimbCount: number;
        }>;
        vssPublicAggregateThresholdCommitmentSet: AggregateThresholdCommitmentSet;
    }>;
}>;

const cryptoProvider = webcrypto as unknown as Crypto;
const storageBinding: BrowserActionStorageRootBinding = Object.freeze({
    actionContextHash: createTestBytes(64, 13),
    ceremonyContextHash: createTestBytes(64, 29),
    participantId: createTestBytes(64, 47),
    suiteId: createTestBytes(64, 71),
});
const openedCustodies = new Set<BrowserActionStorageCustody>();

afterEach(async () => {
    const custodies = [...openedCustodies];
    openedCustodies.clear();
    await Promise.all(custodies.map((custody) => custody.close()));
});

const createEncryptedLocalTrusteeSetupStateFixture = async (
    input: LocalTrusteeSetupStateInputWithoutCustody,
): Promise<
    Awaited<
        ReturnType<
            typeof createEncryptedLocalTrusteeSetupStateFromVerifiedShares
        >
    > &
        Readonly<{ storageCustody: BrowserActionStorageCustody }>
> => {
    const storageCustody = await createActiveTestActionStorageCustody({
        actionStorageRoot: createTestBytes(
            testActionStorageRootByteLength,
            openedCustodies.size + 101,
        ),
        binding: storageBinding,
        cryptoProvider,
    });
    openedCustodies.add(storageCustody);
    const encryptedState =
        await createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
            ...input,
            storageCustody,
        });

    return { ...encryptedState, storageCustody };
};

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
        recipientRecords: [
            {
                objectType: 'VssPublicAggregateThresholdCommitment',
                recipientIdentity: trusteeIdentity,
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
        setupContextHash,
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
                setupContextHash,
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
                privateVssEnvelopeCommitmentRoot,
                envelopeReferences: [
                    {
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
            actionRandomnessCommitment: createTestBytes(64, 211),
            creationRecoveryEpoch: 0n,
        },
    } as const;
};

const targetSetupInput = (
    aggregateThresholdCommitmentSet: AggregateThresholdCommitmentSet,
): TargetSetupInput => {
    const setupPackage = {
        objectType: 'SetupPackage',
        setupContext,
        commonRandomness: { publicMatrixSeedHash },
        vssShareLinkageStatement: {
            statementRoot: fixtureHash('share-linkage-statement'),
            qShareRnsLimbCount: 1,
        },
        vssPublicAggregateThresholdCommitmentSet:
            aggregateThresholdCommitmentSet,
    } as const;

    return {
        setupPackage,
    } as const;
};

describe('local setup-to-target-share witness lifecycle', () => {
    it('restores the setup-produced aggregate opening only from encrypted local state', async () => {
        const artifacts = setupArtifacts();
        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFixture(
                artifacts.localStateInput,
            );
        const targetSetup = targetSetupInput(
            artifacts.aggregateThresholdCommitmentSet,
        );
        const preparedWitness =
            await restoreAndPrepareLocalTargetDecryptionShareWitness({
                actionRandomnessCommitment:
                    artifacts.localStateInput.actionRandomnessCommitment,
                creationRecoveryEpoch:
                    artifacts.localStateInput.creationRecoveryEpoch,
                encryptedLocalState: encryptedState.encryptedLocalState,
                localStateCommitment: encryptedState.localStateCommitment,
                setupContext,
                storageCustody: encryptedState.storageCustody,
                ...targetSetup,
            });

        expect(
            Buffer.from(encryptedState.encryptedLocalState).toString('hex'),
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

        const tamperedEnvelope = encryptedState.encryptedLocalState.slice();
        tamperedEnvelope[tamperedEnvelope.byteLength - 1] ^= 1;
        await expect(
            restoreAndPrepareLocalTargetDecryptionShareWitness({
                actionRandomnessCommitment:
                    artifacts.localStateInput.actionRandomnessCommitment,
                creationRecoveryEpoch:
                    artifacts.localStateInput.creationRecoveryEpoch,
                encryptedLocalState: tamperedEnvelope,
                localStateCommitment: encryptedState.localStateCommitment,
                setupContext,
                storageCustody: encryptedState.storageCustody,
                ...targetSetup,
            }),
        ).rejects.toThrow();
        await expect(
            restoreAndPrepareLocalTargetDecryptionShareWitness({
                actionRandomnessCommitment: createTestBytes(64, 212),
                creationRecoveryEpoch:
                    artifacts.localStateInput.creationRecoveryEpoch,
                encryptedLocalState: encryptedState.encryptedLocalState,
                localStateCommitment: encryptedState.localStateCommitment,
                setupContext,
                storageCustody: encryptedState.storageCustody,
                ...targetSetup,
            }),
        ).rejects.toThrow();
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
        const targetSetup = targetSetupInput(
            artifacts.aggregateThresholdCommitmentSet,
        );
        await expect(
            restoreAndPrepareLocalTargetDecryptionShareWitness({
                actionRandomnessCommitment:
                    artifacts.localStateInput.actionRandomnessCommitment,
                creationRecoveryEpoch:
                    artifacts.localStateInput.creationRecoveryEpoch,
                encryptedLocalState:
                    encryptedChangedRootState.encryptedLocalState,
                localStateCommitment:
                    encryptedChangedRootState.localStateCommitment,
                setupContext,
                storageCustody: encryptedChangedRootState.storageCustody,
                ...targetSetup,
            }),
        ).rejects.toThrow(/must match the accepted aggregate commitment/u);

        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFixture(
                artifacts.localStateInput,
            );
        await expect(
            restoreAndPrepareLocalTargetDecryptionShareWitness({
                actionRandomnessCommitment:
                    artifacts.localStateInput.actionRandomnessCommitment,
                creationRecoveryEpoch:
                    artifacts.localStateInput.creationRecoveryEpoch,
                encryptedLocalState: encryptedState.encryptedLocalState,
                localStateCommitment: encryptedState.localStateCommitment,
                setupContext,
                storageCustody: encryptedState.storageCustody,
                ...targetSetup,
                setupPackage: {
                    ...targetSetup.setupPackage,
                    setupContext: {
                        ...setupContext,
                        setupEpoch: 'changed-setup-epoch',
                    },
                },
            }),
        ).rejects.toThrow(/setupEpoch must match/u);
    });
});
