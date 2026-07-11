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
} from '#packages/protocol/src/setup/vss-commitments';
import {
    loadTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { createVssCommitmentComputers } from '#tests/support/vss-commitment-computer';

type JsonRecord = Record<string, unknown>;

type SetupLifecycleArtifacts = Readonly<{
    aggregateMaterialSeedHex: string;
    canonicalTargetBasisHash: string;
    localStateInput: Parameters<
        typeof createEncryptedLocalTrusteeSetupStateFromVerifiedShares
    >[0];
    ringDegree: number;
    setupPackage: JsonRecord;
}>;

type TargetAcceptedRecord = Readonly<{
    objectType: 'TargetAcceptedRecord';
    boardPosition: number;
    boardSequence: number;
    ceremonyId: string;
    electionManifestHash: string;
    evaluatorReplayRecordHash: string;
    organizerIdentity: string;
    targetBasisHash: string;
    targetCiphertextHash: string;
    targetContextHash: string;
    targetDecryptionParametersHash: string;
    targetFinalityCheckpointHash: string;
    targetFinalityRecordHash: string;
    targetLayoutHash: string;
    targetPreimageHash: string;
    targetProposalHash: string;
    targetAcceptedRecordHash: string;
}>;

type TargetShareProfile = Readonly<{
    objectType: 'TargetDecryptionShareProfile';
    targetDecryptionProfileHash: string;
    targetDecryptionProfileBindingHash: string;
    decryptionThreshold: number;
    minimumSharesForInterpolation: number;
    decryptionShareQuorum: number;
    targetShareProfileHash: string;
}>;

type TargetArtifacts = Readonly<{
    targetAcceptedRecord: TargetAcceptedRecord;
    targetCiphertextBinding: Readonly<{
        aggregateCiphertextRoot: string;
        topCount: number;
        targetLayoutHash: string;
    }>;
    targetCiphertexts: Readonly<{
        targetIdCanonicalBytesHex: string;
        targetOrderCanonicalBytesHex: string;
    }>;
    targetDecryptionCiphertextHash: string;
    targetShareProfile: TargetShareProfile;
}>;

type LifecycleArtifacts = Readonly<{
    kernel: TranscriptCoreKernel;
    setup: SetupLifecycleArtifacts;
    target: TargetArtifacts;
}>;

type LifecycleArtifactsPromise = Promise<LifecycleArtifacts>;

const participantCount = 3;
const localTrusteeRosterPosition = 0;
const localTrusteeIdentity = 'trustee-0';
const setupEpoch = 'setup-epoch-1';

const hash = (kernel: TranscriptCoreKernel, label: string): string =>
    kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'LocalTargetShareLifecycleFixtureHash',
            label,
        },
    });

const sourceCoefficientMessage = (
    sourceTrusteeRosterPosition: number,
    shamirCoefficientIndex: number,
    ringDegree: number,
): number[] =>
    Array.from(
        { length: ringDegree },
        (_unusedCoefficient, coefficientPosition) =>
            (sourceTrusteeRosterPosition * 11 +
                shamirCoefficientIndex * 7 +
                (coefficientPosition % 13) +
                1) %
            97,
    );

const addResidueVectors = (
    left: readonly number[],
    right: readonly number[],
    modulus: number,
): number[] =>
    left.map((leftValue, coefficientPosition) => {
        const rightValue = right[coefficientPosition];
        if (rightValue === undefined) {
            throw new Error('Fixture residue vectors must have equal length.');
        }

        return (leftValue + rightValue) % modulus;
    });

const setupLifecycleArtifacts = (
    kernel: TranscriptCoreKernel,
): SetupLifecycleArtifacts => {
    const setupParameters = kernel.describeCollectiveBgvSetupParameters({
        participantCount,
    });
    const bgvParameters = kernel.describeBgvRnsParameters();
    const ringDegree = bgvParameters.parameters.polynomialDegree;
    const firstRnsPrime = setupParameters.qShare.primes[0];
    if (firstRnsPrime === undefined) {
        throw new Error('Setup parameters must contain a first Q_share prime.');
    }
    const setupContext = {
        ceremonyId: 'local-target-share-lifecycle-ceremony',
        manifestHash: hash(kernel, 'manifest'),
        rosterHash: hash(kernel, 'roster'),
        setupParametersHash: setupParameters.setupParametersHash,
        setupEpoch,
        participantCount,
        qSetupComplete: setupParameters.qSetupComplete,
        qBallotRelease: setupParameters.qBallotRelease,
        qFinal: setupParameters.qFinal,
        qDec: setupParameters.qDec,
    } as const;
    const publicMatrixSeedHash = hash(kernel, 'public-matrix-seed');
    const thresholdDegree = setupParameters.qDec;
    const sourceTrusteeOpeningStates = Array.from(
        { length: participantCount },
        (_unusedSource, sourceTrusteeRosterPosition) => ({
            sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
            sourceTrusteeRosterPosition,
            coefficientOpenings: Array.from(
                { length: thresholdDegree },
                (_unusedCoefficient, shamirCoefficientIndex) => ({
                    rnsLimbIndex: 0,
                    rnsPrime: firstRnsPrime,
                    shamirCoefficientIndex,
                    coefficientMessage: sourceCoefficientMessage(
                        sourceTrusteeRosterPosition,
                        shamirCoefficientIndex,
                        ringDegree,
                    ),
                }),
            ),
        }),
    );
    const committedMaterialSeed = (
        coordinate: Record<string, unknown>,
    ): string =>
        kernel.deriveCanonicalObjectHash({
            value: {
                objectType: 'LocalTargetShareLifecycleMaterialSeed',
                ...coordinate,
            },
        });
    const { vssCommittedMaterialCommitmentComputer } =
        createVssCommitmentComputers(kernel);
    const coefficientBundle = createVssPublicCoefficientCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount,
        qSharePrimes: [firstRnsPrime],
        ringDegree,
        thresholdDegree,
        sourceTrusteeOpeningStates,
        committedMaterialSeed,
        computeVssCommittedMaterialCommitment:
            vssCommittedMaterialCommitmentComputer,
    });
    const recipientBundle = createVssPublicRecipientShareCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount,
        qSharePrimes: [firstRnsPrime],
        ringDegree,
        thresholdDegree,
        sourceTrusteeOpeningStates,
        committedMaterialSeed,
        computeVssCommittedMaterialCommitment:
            vssCommittedMaterialCommitmentComputer,
    });
    const aggregateBundles = Array.from(
        { length: participantCount },
        (_unusedRecipient, recipientRosterPosition) =>
            createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount,
                qSharePrimes: [firstRnsPrime],
                ringDegree,
                coefficientCommitmentSet:
                    coefficientBundle.coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    recipientBundle.recipientShareCommitmentSet,
                localTrusteeRosterPosition: recipientRosterPosition,
                localRecipientShareCredentials:
                    recipientBundle.recipientShareCredentials.filter(
                        (credential) =>
                            credential.recipientRosterPosition ===
                            recipientRosterPosition,
                    ),
                committedMaterialSeed,
                computeVssCommittedMaterialCommitment:
                    vssCommittedMaterialCommitmentComputer,
                aggregateThresholdProofRandomness: ({ rnsLimbIndex }) => ({
                    seedHex: hash(
                        kernel,
                        `aggregate-proof-seed-${String(recipientRosterPosition)}-${String(rnsLimbIndex)}`,
                    ),
                    nonceHex: hash(
                        kernel,
                        `aggregate-proof-nonce-${String(recipientRosterPosition)}-${String(rnsLimbIndex)}`,
                    ),
                }),
                generateVssShareLinkageProof: () => ({
                    proofBytesHex: '00',
                }),
            }),
    );
    const aggregateThresholdCommitmentSet =
        assembleVssPublicAggregateThresholdCommitmentSet({
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes: [firstRnsPrime],
            ringDegree,
            recipientShareCommitmentSet:
                recipientBundle.recipientShareCommitmentSet,
            publicAggregateThresholdCommitmentContributions:
                aggregateBundles.map(
                    (bundle) =>
                        bundle.publicAggregateThresholdCommitmentContribution,
                ),
        });
    const localAggregateBundle = aggregateBundles[localTrusteeRosterPosition];
    if (localAggregateBundle === undefined) {
        throw new Error('Fixture must contain the local aggregate bundle.');
    }
    const privateVssEnvelopeCommitmentRoot = hash(
        kernel,
        'private-envelope-commitment-set',
    );
    const localShareValuesBySource = sourceTrusteeOpeningStates.map(
        (sourceOpeningState) => {
            const constantMessage =
                sourceOpeningState.coefficientOpenings[0]?.coefficientMessage;
            const linearMessage =
                sourceOpeningState.coefficientOpenings[1]?.coefficientMessage;
            if (constantMessage === undefined || linearMessage === undefined) {
                throw new Error(
                    'Fixture requires a degree-one Shamir polynomial.',
                );
            }

            return addResidueVectors(
                constantMessage,
                linearMessage,
                firstRnsPrime,
            );
        },
    );
    const privateEnvelopes = localShareValuesBySource.map(
        (shareValues, sourceTrusteeRosterPosition) => {
            const sourceTrusteeIdentity = `trustee-${String(sourceTrusteeRosterPosition)}`;

            return {
                objectType: 'PrivateVssShareEnvelope',
                ...setupContext,
                sourceTrusteeIdentity,
                sourceTrusteeRosterPosition,
                recipientIdentity: localTrusteeIdentity,
                recipientRosterPosition: localTrusteeRosterPosition,
                sourceTrusteeCommitmentRoot: hash(
                    kernel,
                    `source-commitment-${String(sourceTrusteeRosterPosition)}`,
                ),
                rnsShareOpenings: [
                    {
                        objectType: 'PrivateVssShareOpening',
                        rnsLimbIndex: 0,
                        rnsPrime: firstRnsPrime,
                        shareValues,
                    },
                ],
            };
        },
    );
    const envelopeReferences = privateEnvelopes.map(
        (privateEnvelope, sourceTrusteeRosterPosition) => ({
            ...setupContext,
            sourceTrusteeIdentity: privateEnvelope.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition,
            recipientIdentity: localTrusteeIdentity,
            recipientRosterPosition: localTrusteeRosterPosition,
            sourceTrusteeCommitmentRoot:
                privateEnvelope.sourceTrusteeCommitmentRoot,
            privateEnvelopeHash: kernel.deriveCanonicalObjectHash({
                value: privateEnvelope,
            }),
            localVerificationRoot: hash(
                kernel,
                `local-verification-${String(sourceTrusteeRosterPosition)}`,
            ),
        }),
    );
    const thresholdShareCommitmentRecipientRoot = hash(
        kernel,
        'threshold-share-recipient',
    );
    const setupPackage: JsonRecord = {
        objectType: 'SetupPackage',
        setupContext,
        phaseTranscript: [
            {
                phaseId: 'setupIntent',
                participantPhaseObjects: Array.from(
                    { length: participantCount },
                    (_unusedParticipant, rosterPosition) => ({
                        trusteeIdentity: `trustee-${String(rosterPosition)}`,
                        rosterPosition,
                        signingPublicKeyHash: hash(
                            kernel,
                            `signing-key-${String(rosterPosition)}`,
                        ),
                    }),
                ),
            },
        ],
        commonRandomness: { publicMatrixSeedHash },
        vssShareLinkageStatement: {
            statementRoot: hash(kernel, 'share-linkage-statement'),
        },
        vssPublicAggregateThresholdCommitmentSet:
            aggregateThresholdCommitmentSet,
    };
    const aggregateOpeningCredential =
        localAggregateBundle.localTrusteeAggregateOpeningCredentialHandoff
            .aggregateOpeningCredentials[0];
    if (aggregateOpeningCredential === undefined) {
        throw new Error(
            'Fixture must contain a local aggregate opening credential.',
        );
    }

    return {
        aggregateMaterialSeedHex:
            aggregateOpeningCredential.aggregateMaterialSeedHex,
        canonicalTargetBasisHash: setupParameters.canonicalTargetBasisHash,
        localStateInput: {
            setupContext,
            trusteeIdentity: localTrusteeIdentity,
            trusteeRosterPosition: localTrusteeRosterPosition,
            deviceEpoch: 0,
            thresholdShareCommitments: {
                objectType: 'ThresholdShareCommitmentSet',
                ...setupContext,
                recipientRecords: [
                    {
                        recipientIdentity: localTrusteeIdentity,
                        recipientRosterPosition: localTrusteeRosterPosition,
                        recipientCommitmentRoot:
                            thresholdShareCommitmentRecipientRoot,
                    },
                ],
            },
            privateVssEnvelopeCommitments: {
                objectType: 'PrivateVssEnvelopeCommitmentSet',
                ...setupContext,
                participantCount,
                privateVssEnvelopeCommitmentRoot,
                envelopeReferences,
            },
            verifiedPrivateVssShareEnvelopes: privateEnvelopes,
            localTrusteeAggregateOpeningCredentialHandoff:
                localAggregateBundle.localTrusteeAggregateOpeningCredentialHandoff,
            vssShareAcceptances: {
                objectType: 'VssShareAcceptanceSet',
                ...setupContext,
                acceptanceRecords: envelopeReferences.map(
                    (reference, sourceTrusteeRosterPosition) => ({
                        ...setupContext,
                        sourceTrusteeIdentity: reference.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition,
                        recipientIdentity: localTrusteeIdentity,
                        recipientRosterPosition: localTrusteeRosterPosition,
                        privateVssEnvelopeCommitmentRoot,
                        acceptanceRoot: hash(
                            kernel,
                            `acceptance-${String(sourceTrusteeRosterPosition)}`,
                        ),
                    }),
                ),
            },
            storageKeyBytesHex: '41'.repeat(32),
            localStateAeadNonceBytesHex: '51'.repeat(12),
            sealedAggregateThresholdShareAeadNonceBytesHex: '61'.repeat(12),
        },
        ringDegree,
        setupPackage,
    } as const;
};

const targetArtifacts = (
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
    ringDegree: number,
    targetBasisHash: string,
): TargetArtifacts => {
    const targetId = kernel.generateBgvCiphertextConventionFixture({
        leftSlots: [1, 0, 3],
        rightSlots: [0, 1, 0],
        includeCanonicalBytesHex: true,
    });
    const targetOrder = kernel.generateBgvCiphertextConventionFixture({
        leftSlots: [1, 0, 2],
        rightSlots: [0, 1, 0],
        includeCanonicalBytesHex: true,
    });
    if (
        !('canonicalBytesHex' in targetId) ||
        typeof targetId.canonicalBytesHex !== 'string' ||
        !('canonicalBytesHex' in targetOrder) ||
        typeof targetOrder.canonicalBytesHex !== 'string' ||
        !('ciphertextRoot' in targetId) ||
        !('ciphertextRoot' in targetOrder)
    ) {
        throw new Error(
            'Target ciphertext fixtures must include canonical bytes.',
        );
    }
    const targetLayoutHash = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'DirectEncryptedBallotTargetLayout',
            layoutId: 'direct-encrypted-target-projection',
            optionCount: 20,
            targetIdSlotRule: '(option + 1) * [rank < topCount]',
            targetOrderSlotRule: '(rank + 1) * [rank < topCount]',
            slotCount: ringDegree,
        },
    });
    const aggregateCiphertextRoot = hash(kernel, 'aggregate-ciphertext-root');
    const topCount = 2;
    const targetCiphertextHash = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'EncryptedSparseTargetCiphertext',
            aggregateCiphertextRoot,
            topCount,
            tiePolicy: 'higher-sum-first-then-lower-option-index',
            targetLayoutHash,
            targetIdRoot: targetId.ciphertextRoot,
            targetOrderRoot: targetOrder.ciphertextRoot,
            openedIntermediates: [],
        },
    });
    const releaseSetupContext =
        kernel.deriveBgvTargetDecryptionResultReleaseSetupContext({
            setupPackage,
        }) as JsonRecord;
    const targetDecryptionProfileHash = String(
        releaseSetupContext.targetDecryptionParametersHash,
    );
    const targetDecryptionProfileBindingHash = String(
        releaseSetupContext.targetDecryptionParametersBindingHash,
    );
    const targetShareProfileWithoutHash = {
        objectType: 'TargetDecryptionShareProfile',
        targetDecryptionProfileHash,
        targetDecryptionProfileBindingHash,
        decryptionThreshold: 2,
        minimumSharesForInterpolation: 2,
        decryptionShareQuorum: 2,
    } as const;
    const targetShareProfile = {
        ...targetShareProfileWithoutHash,
        targetShareProfileHash: kernel.deriveCanonicalObjectHash({
            value: targetShareProfileWithoutHash,
        }),
    };
    const targetAcceptedRecordWithoutHash = {
        objectType: 'TargetAcceptedRecord',
        boardPosition: 0,
        boardSequence: 0,
        ceremonyId: String(
            (setupPackage.setupContext as JsonRecord).ceremonyId,
        ),
        electionManifestHash: String(
            (setupPackage.setupContext as JsonRecord).manifestHash,
        ),
        evaluatorReplayRecordHash: hash(kernel, 'evaluator-replay'),
        organizerIdentity: 'organizer',
        targetBasisHash,
        targetCiphertextHash,
        targetContextHash: hash(kernel, 'target-context'),
        targetDecryptionParametersHash: targetDecryptionProfileHash,
        targetFinalityCheckpointHash: hash(
            kernel,
            'target-finality-checkpoint',
        ),
        targetFinalityRecordHash: hash(kernel, 'target-finality-record'),
        targetLayoutHash,
        targetPreimageHash: hash(kernel, 'target-preimage'),
        targetProposalHash: hash(kernel, 'target-proposal'),
    } as const;
    const targetAcceptedRecord = {
        ...targetAcceptedRecordWithoutHash,
        targetAcceptedRecordHash: kernel.deriveCanonicalObjectHash({
            value: targetAcceptedRecordWithoutHash,
        }),
    };

    return {
        targetAcceptedRecord,
        targetCiphertextBinding: {
            aggregateCiphertextRoot,
            topCount,
            targetLayoutHash,
        },
        targetCiphertexts: {
            targetIdCanonicalBytesHex: targetId.canonicalBytesHex,
            targetOrderCanonicalBytesHex: targetOrder.canonicalBytesHex,
        },
        targetDecryptionCiphertextHash: targetCiphertextHash,
        targetShareProfile,
    } as const;
};

const createLifecycleArtifacts = async (): LifecycleArtifactsPromise => {
    const kernel = await loadTranscriptCoreKernel();
    const setup = setupLifecycleArtifacts(kernel);
    const target = targetArtifacts(
        kernel,
        setup.setupPackage,
        setup.ringDegree,
        setup.canonicalTargetBasisHash,
    );

    return { kernel, setup, target } as const;
};

let lifecycleArtifactsPromise:
    | ReturnType<typeof createLifecycleArtifacts>
    | undefined;

const lifecycleArtifacts = (): LifecycleArtifactsPromise => {
    lifecycleArtifactsPromise ??= createLifecycleArtifacts();
    return lifecycleArtifactsPromise;
};

const firstAggregateOpeningCredential = (
    localTargetShareWitness: JsonRecord,
): JsonRecord => {
    const aggregateOpening =
        localTargetShareWitness.aggregateOpening as JsonRecord;
    const aggregateOpeningCredentials =
        aggregateOpening.aggregateOpeningCredentials as JsonRecord[];
    const credential = aggregateOpeningCredentials[0];
    if (credential === undefined) {
        throw new Error(
            'Fixture must contain an aggregate opening credential.',
        );
    }

    return credential;
};

describe('local setup-to-target-share WASM lifecycle', () => {
    it('restores encrypted setup material and generates a target-bound share in WASM', async () => {
        const { kernel, setup, target } = await lifecycleArtifacts();
        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                setup.localStateInput,
            );
        const localTargetShareWitness =
            await restoreAndPrepareLocalTargetDecryptionShareWitness({
                encryptedLocalState: encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext: setup.localStateInput.setupContext,
                storageKeyBytesHex: setup.localStateInput.storageKeyBytesHex,
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetDecryptionCiphertextHash:
                    target.targetDecryptionCiphertextHash,
                targetShareProfile: target.targetShareProfile,
            });
        const targetDecryptionShare =
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness,
            });

        expect(targetDecryptionShare).toMatchObject({
            objectType: 'BgvTargetDecryptionShare',
            trusteeIdentity: localTrusteeIdentity,
            rosterPosition: localTrusteeRosterPosition,
            targetAcceptedRecordHash:
                target.targetAcceptedRecord.targetAcceptedRecordHash,
            targetCiphertextHash:
                target.targetAcceptedRecord.targetCiphertextHash,
        });
        expect(targetDecryptionShare.targetDecryptionShareHash).toHaveLength(
            128,
        );
        expect(targetDecryptionShare.shareRoot).toHaveLength(128);
        expect(JSON.stringify(targetDecryptionShare)).not.toContain(
            setup.aggregateMaterialSeedHex,
        );
        expect(
            JSON.stringify(encryptedState.encryptedLocalState),
        ).not.toContain(setup.aggregateMaterialSeedHex);
    });

    it('rejects altered restored openings and a target ciphertext replay', async () => {
        const { kernel, setup, target } = await lifecycleArtifacts();
        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                setup.localStateInput,
            );
        const localTargetShareWitness =
            (await restoreAndPrepareLocalTargetDecryptionShareWitness({
                encryptedLocalState: encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext: setup.localStateInput.setupContext,
                storageKeyBytesHex: setup.localStateInput.storageKeyBytesHex,
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetDecryptionCiphertextHash:
                    target.targetDecryptionCiphertextHash,
                targetShareProfile: target.targetShareProfile,
            })) as JsonRecord;
        const alteredWitness = structuredClone(localTargetShareWitness);
        const credential = firstAggregateOpeningCredential(alteredWitness);
        credential.aggregateMaterialSeedHex = '00'.repeat(64);

        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: alteredWitness,
            }),
        ).toThrow(/credential commitment root/u);

        const messageAlteredWitness = structuredClone(localTargetShareWitness);
        const messageAlteredCredential = firstAggregateOpeningCredential(
            messageAlteredWitness,
        );
        const aggregateMessageHex = String(
            messageAlteredCredential.aggregateCommitmentMessageValuesLeHex,
        );
        messageAlteredCredential.aggregateCommitmentMessageValuesLeHex = `${
            aggregateMessageHex.startsWith('00') ? '01' : '00'
        }${aggregateMessageHex.slice(2)}`;

        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: messageAlteredWitness,
            }),
        ).toThrow(/credential commitment root/u);

        const contextAlteredWitness = structuredClone(localTargetShareWitness);
        contextAlteredWitness.setupEpoch = 'changed-setup-epoch';

        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: contextAlteredWitness,
            }),
        ).toThrow(/credential commitment root/u);

        const identityAlteredWitness = structuredClone(localTargetShareWitness);
        const identityAlteredCredential = firstAggregateOpeningCredential(
            identityAlteredWitness,
        );
        identityAlteredCredential.recipientIdentity =
            'changed-trustee-identity';

        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: identityAlteredWitness,
            }),
        ).toThrow(/aggregate opening credential recipient identity/u);

        const rootAlteredWitness = structuredClone(localTargetShareWitness);
        const rootAlteredCredential =
            firstAggregateOpeningCredential(rootAlteredWitness);
        rootAlteredCredential.aggregateCommitmentRoot = hash(
            kernel,
            'changed-aggregate-commitment-root',
        );

        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: rootAlteredWitness,
            }),
        ).toThrow(/aggregate opening credential commitment root/u);

        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: {
                    ...target.targetCiphertextBinding,
                    aggregateCiphertextRoot: hash(
                        kernel,
                        'replayed-aggregate-ciphertext',
                    ),
                },
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness,
            }),
        ).toThrow(/does not match the accepted target ciphertext hash/u);
    });
});
