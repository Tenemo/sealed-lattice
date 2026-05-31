import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import {
    checkpointContext,
    hashJson,
    loadOrComputeCheckpoint,
    readCheckpoint,
    readJsonFile,
    runtimeContext,
    writeJsonFileAtomic,
    type CheckpointContext,
    type RuntimeBinding,
} from './checkpoints.js';
import {
    parseRunnerConfig,
    usageText,
    type RunnerConfig,
    type WorkerConfig,
} from './config.js';
import type {
    AggregateComponentContext,
    AggregateFixture,
    AggregateStatementBuild,
    AggregateStatementInput,
    BallotPackageCheckpoint,
    BallotPackageContext,
    BridgeContributorCheckpoint,
    BridgeSupportHashes,
    ComponentCheckpoint,
    PendingBridgeProofRecordInput,
    PostCloseEvidence,
    RunnerSummary,
    TranscriptCoreKernel,
    WorkerResult,
    WorkerRunConfig,
} from './types.js';
import {
    runWorkerPool,
    workerOutputPrefix,
    writeWorkerRunConfig,
} from './worker-process.js';

import {
    canonicalJson,
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveProtocolHash,
} from '#packages/crypto/src/index';
import { createPendingBridgeProofRecordFromBridgeEvidence } from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    aggregateWitnessFromReceiverPlaintext,
    buildAggregateDerivationProofInput,
    buildAggregateDerivationStatement,
    createAggregateContributionFromBridgeProofRecord,
    createAggregateDerivationComponent,
    createAggregateReadyRecord,
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    selectFirstValidAggregateContributions,
    sumAggregateDerivationWitnesses,
    verifyAggregateReadyRecordStructure,
    verifyAggregateDerivationComponentStructure,
    type AggregateDerivationWitnessInput,
} from '#packages/protocol/src/ballot-privacy/index';
import { createMandatoryProfileBallotProofRecordBenchmarkFixture } from '#packages/protocol/tests/node/ballot-privacy-proof-record-generation-fixtures/fixture-assembly.js';
import type {
    ActionContext,
    AggregateContribution,
    ClaimBearingBallotPackage,
    ProtocolSignatureEnvelope,
    ShareCommitmentMessageBoundCert,
} from '#packages/types/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type { TopKEvaluatorEncryptedAggregateInput } from '#packages/wasm/src/transcript-core-bridge/kernel-types';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const hash = (label: string): string =>
    `${label.padEnd(64, '0').slice(0, 64)}${label.padEnd(64, '1').slice(0, 64)}`.replace(
        /[^a-f0-9]/gu,
        'a',
    );

const fixtureCertificate = (
    fixture: AggregateFixture,
): ShareCommitmentMessageBoundCert => {
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: fixture.relationInput.optionCount,
    });

    return createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
};

const createFixtureBallotPackage = (input: {
    readonly fixture: AggregateFixture;
    readonly generation: Record<string, unknown>;
}): ClaimBearingBallotPackage =>
    ({
        objectType: 'ClaimBearingBallotPackage',
        objectVersion: 1,
        ballotPackageHash: input.fixture.request.statement.ballotPackageHash,
        ballotProof: input.generation
            .ballotProof as ClaimBearingBallotPackage['ballotProof'],
        ballotProofStatement: input.fixture.request.statement,
        componentBundleStatement:
            input.fixture.request.componentBundleStatement,
        componentProofBundle: input.generation
            .componentProofBundle as ClaimBearingBallotPackage['componentProofBundle'],
        componentProofInputs: input.generation
            .componentProofInputs as ClaimBearingBallotPackage['componentProofInputs'],
        linearStatement: input.fixture.request.linearStatement,
        parameterSet: input.generation.parameterSet,
        proofBytesHex: input.generation.proofBytesHex as string,
        proofEncoding: input.generation.proofEncoding,
        publicRandomnessHex: input.fixture.request.publicRandomnessHex,
        receiverKeyProofRootEvidence:
            input.fixture.receiverKeyProofRootEvidence,
        receiverPayloads: input.fixture.claimBearingReceiverPayloads,
        shareCommitments: input.fixture.claimBearingShareCommitments,
    }) as unknown as ClaimBearingBallotPackage;

const createPostCloseEvidence = (input: {
    readonly ceremonyId: string;
    readonly contributorIdentity: string;
    readonly electionManifestHash: string;
    readonly rosterExternalAcceptanceHash: string;
    readonly votingClosedBoardHeadHash: string;
}): PostCloseEvidence => {
    const closeRecordPayload = {
        boardPosition: 0,
        boardSequence: 7,
        ceremonyId: input.ceremonyId,
        closeKind: 'VotingClosed',
        closedBoardHeadHash: input.votingClosedBoardHeadHash,
        electionManifestHash: input.electionManifestHash,
        objectType: 'CloseRecord',
        objectVersion: 1,
        organizerIdentity: 'organizer-1',
    };
    const closeRecordHash = deriveProtocolHash(
        'CloseRecordHash',
        closeRecordPayload,
    );
    const postVotingClosedContextHash = deriveProtocolHash(
        'PostVotingClosedContextHash',
        {
            ceremonyId: input.ceremonyId,
            closeRecordHash,
            electionManifestHash: input.electionManifestHash,
            votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
        },
    );
    const contributorActionContextPayload = {
        acceptedRecoveryEpochUpdateHash: null,
        actionSequence: 1,
        boardHeadHash: input.votingClosedBoardHeadHash,
        boardSequence: 7,
        ceremonyId: input.ceremonyId,
        contextHash: postVotingClosedContextHash,
        deviceEpoch: 0,
        electionManifestHash: input.electionManifestHash,
        recoveryEpoch: 0,
        recoveryPolicyHash: hash('recovery-policy'),
        rosterExternalAcceptanceHash: input.rosterExternalAcceptanceHash,
        signerIdentity: input.contributorIdentity,
    };
    const contributorActionContextHash = deriveProtocolHash(
        'ActionContextHash',
        contributorActionContextPayload,
    );

    return {
        closeRecord: {
            ...closeRecordPayload,
            closeRecordHash,
            postVotingClosedContextHash,
        },
        closeRecordHash,
        contributorActionContext: {
            ...contributorActionContextPayload,
            actionContextHash: contributorActionContextHash,
        },
        postVotingClosedContextHash,
    };
};

const receiverWitness = (
    fixture: AggregateFixture,
    receiverRosterPosition: number,
): AggregateDerivationWitnessInput => {
    const receiverPayloadPlaintext =
        fixture.projectionWitness.receiverPayloadPlaintexts?.find(
            (plaintext) =>
                plaintext.receiverRosterPosition === receiverRosterPosition,
        );
    const shareCommitmentOpening =
        fixture.projectionWitness.shareCommitmentOpenings.find(
            (opening) =>
                opening.receiverRosterPosition === receiverRosterPosition,
        );
    if (
        receiverPayloadPlaintext === undefined ||
        shareCommitmentOpening === undefined
    ) {
        throw new Error(
            `Fixture should include receiver-${receiverRosterPosition} witness material.`,
        );
    }

    return aggregateWitnessFromReceiverPlaintext({
        openingRandomness: shareCommitmentOpening.openingRandomness,
        receiverShareVector: receiverPayloadPlaintext.receiverShareVector,
    });
};

const createBallotContextFromCheckpoint = (input: {
    readonly checkpoint: BallotPackageCheckpoint;
    readonly fixture: AggregateFixture;
    readonly kernel: TranscriptCoreKernel;
}): BallotPackageContext => ({
    ...input.checkpoint,
    fixture: input.fixture,
    kernel: input.kernel,
});

const loadBallotPackageContext = async (input: {
    readonly config: RunnerConfig | WorkerRunConfig;
    readonly kernel: TranscriptCoreKernel;
    readonly runtime: RuntimeBinding;
}): Promise<{
    readonly fromCheckpoint: boolean;
    readonly value: BallotPackageContext;
}> => {
    const fixture = createMandatoryProfileBallotProofRecordBenchmarkFixture();
    const context = checkpointContext({
        ...input.runtime,
        checkpointName: 'aggregate-kernel-ballot-proof-package',
        input: {
            fixtureStatementHash:
                fixture.request.statement.ballotProofStatementHash,
            target: input.config.target,
        },
        stage: 'aggregate-kernel-ballot-proof-package',
    });
    const result = await loadOrComputeCheckpoint<BallotPackageCheckpoint>({
        checkpointDir: input.config.checkpointDir,
        compute: () => {
            const generation = input.kernel.generateBallotProofRecord(
                fixture.request,
            ) as Record<string, unknown>;
            if (generation.ok !== true) {
                throw new Error(
                    `Ballot proof generation failed: ${canonicalJson(generation)}`,
                );
            }
            const ballotPackage = createFixtureBallotPackage({
                fixture,
                generation,
            });
            const certificate = fixtureCertificate(fixture);
            const postCloseEvidence = createPostCloseEvidence({
                ceremonyId: fixture.statement.ceremonyId,
                contributorIdentity: 'receiver-1',
                electionManifestHash: fixture.statement.manifestHash,
                rosterExternalAcceptanceHash:
                    fixture.statement.rosterExternalAcceptanceHash,
                votingClosedBoardHeadHash: hash('closed-board-head'),
            });
            const {
                proofBytesHex: omittedProofBytesHex,
                ...ballotPackageWithoutProofBytes
            } = ballotPackage;
            void omittedProofBytesHex;
            const statementInput = {
                ballotPackages: [ballotPackage],
                casualMicroRosterAcknowledged: false,
                closeRecordHash: postCloseEvidence.closeRecordHash,
                contributorActionContextHash: postCloseEvidence
                    .contributorActionContext.actionContextHash as string,
                contributorIdentity: 'receiver-1',
                contributorRosterExternalAcceptanceHash:
                    fixture.statement.rosterExternalAcceptanceHash,
                contributorRosterPosition: 1,
                postVotingClosedContextHash:
                    postCloseEvidence.postVotingClosedContextHash,
                votingClosedBoardHeadHash: postCloseEvidence.closeRecord
                    .closedBoardHeadHash as string,
            } satisfies AggregateStatementInput;

            return {
                value: {
                    ballotPackage,
                    ballotPackageWithoutProofBytes:
                        ballotPackageWithoutProofBytes,
                    ballotProofGeneration: generation,
                    certificate,
                    fixtureStatementHash:
                        fixture.request.statement.ballotProofStatementHash,
                    postCloseEvidence,
                    statementInput,
                },
            };
        },
        context,
        forceRecompute:
            input.config.forceRecompute instanceof Set
                ? input.config.forceRecompute
                : new Set(input.config.forceRecompute),
        requireCheckpoints: input.config.requireCheckpoints,
        resumeCheckpoints: input.config.resumeCheckpoints,
    });

    return {
        fromCheckpoint: result.fromCheckpoint,
        value: createBallotContextFromCheckpoint({
            checkpoint: result.value,
            fixture,
            kernel: input.kernel,
        }),
    };
};

const createAggregateComponentForReceiver = (input: {
    readonly ballotPackageContext: BallotPackageContext;
    readonly contributorRosterPosition: number;
    readonly proverRandomnessHex: string;
}): ComponentCheckpoint => {
    const contributorIdentity = `receiver-${input.contributorRosterPosition}`;
    const fixture = input.ballotPackageContext.fixture;
    const postCloseEvidence = createPostCloseEvidence({
        ceremonyId: fixture.statement.ceremonyId,
        contributorIdentity,
        electionManifestHash: fixture.statement.manifestHash,
        rosterExternalAcceptanceHash:
            fixture.statement.rosterExternalAcceptanceHash,
        votingClosedBoardHeadHash: hash('closed-board-head'),
    });
    const statementInput = {
        ballotPackages: [input.ballotPackageContext.ballotPackage],
        casualMicroRosterAcknowledged: false,
        closeRecordHash: postCloseEvidence.closeRecordHash,
        contributorActionContextHash: postCloseEvidence.contributorActionContext
            .actionContextHash as string,
        contributorIdentity,
        contributorRosterExternalAcceptanceHash:
            fixture.statement.rosterExternalAcceptanceHash,
        contributorRosterPosition: input.contributorRosterPosition,
        postVotingClosedContextHash:
            postCloseEvidence.postVotingClosedContextHash,
        votingClosedBoardHeadHash: postCloseEvidence.closeRecord
            .closedBoardHeadHash as string,
    } satisfies AggregateStatementInput;
    const { aggregateCommitment, statement } =
        buildAggregateDerivationStatement(statementInput);
    const witness = sumAggregateDerivationWitnesses({
        witnesses: [receiverWitness(fixture, input.contributorRosterPosition)],
    });
    const proofBuild = buildAggregateDerivationProofInput({
        aggregateCommitment,
        statement,
        witness,
    });
    const generatedAggregateProof =
        input.ballotPackageContext.kernel.generateAggregateDerivationProof({
            proofInput: proofBuild.proofInput,
            proverRandomnessHex: input.proverRandomnessHex,
            secretState: proofBuild.secretState,
        });
    if (generatedAggregateProof.ok !== true) {
        throw new Error(
            `Aggregate derivation proof generation failed for ${contributorIdentity}: ${canonicalJson(generatedAggregateProof)}`,
        );
    }
    const component = createAggregateDerivationComponent({
        aggregateCommitment,
        proofBytesHex: String(generatedAggregateProof.proofBytesHex),
        proofInput: proofBuild.proofInput,
        shareCommitmentMessageBoundCert: input.ballotPackageContext.certificate,
        statement,
    });
    const componentVerification =
        verifyAggregateDerivationComponentStructure(component);
    if (!componentVerification.ok) {
        throw new Error(
            `Aggregate component structure rejected for ${contributorIdentity}: ${canonicalJson(componentVerification)}`,
        );
    }
    const {
        fixture: omittedFixture,
        kernel: omittedKernel,
        ...serializableBallotContext
    } = input.ballotPackageContext;
    void omittedFixture;
    void omittedKernel;

    return {
        ...serializableBallotContext,
        aggregateCommitment,
        component,
        generatedAggregateProof,
        postCloseEvidence,
        proofBuild,
        statement,
        statementInput,
        witness,
    };
};

const componentContextFromCheckpoint = (input: {
    readonly ballotPackageContext: BallotPackageContext;
    readonly checkpoint: ComponentCheckpoint;
}): AggregateComponentContext => ({
    ...input.checkpoint,
    fixture: input.ballotPackageContext.fixture,
    kernel: input.ballotPackageContext.kernel,
});

const loadComponentContext = async (input: {
    readonly ballotPackageContext: BallotPackageContext;
    readonly config: RunnerConfig | WorkerRunConfig;
    readonly receiver: number;
    readonly runtime: RuntimeBinding;
}): Promise<{
    readonly fromCheckpoint: boolean;
    readonly value: AggregateComponentContext;
}> => {
    const context = checkpointContext({
        ...input.runtime,
        checkpointName: `aggregate-kernel-component-receiver-${input.receiver}`,
        input: {
            ballotPackageHash:
                input.ballotPackageContext.ballotPackage.ballotPackageHash,
            receiver: input.receiver,
            target: input.config.target,
        },
        stage: 'aggregate-kernel-component-receiver',
    });
    const result = await loadOrComputeCheckpoint<ComponentCheckpoint>({
        checkpointDir: input.config.checkpointDir,
        compute: () => ({
            value: createAggregateComponentForReceiver({
                ballotPackageContext: input.ballotPackageContext,
                contributorRosterPosition: input.receiver,
                proverRandomnessHex:
                    input.receiver === 1 ? '66'.repeat(32) : '67'.repeat(32),
            }),
        }),
        context,
        forceRecompute:
            input.config.forceRecompute instanceof Set
                ? input.config.forceRecompute
                : new Set(input.config.forceRecompute),
        requireCheckpoints: input.config.requireCheckpoints,
        resumeCheckpoints: input.config.resumeCheckpoints,
    });

    return {
        fromCheckpoint: result.fromCheckpoint,
        value: componentContextFromCheckpoint({
            ballotPackageContext: input.ballotPackageContext,
            checkpoint: result.value,
        }),
    };
};

const setupParticipants = (
    statement: AggregateStatementBuild['statement'],
): readonly {
    readonly boardPosition: number;
    readonly rosterPosition: number;
    readonly trusteeIdentity: string;
}[] =>
    Array.from({ length: statement.participantCount }, (_unused, index) => ({
        boardPosition: index + 3,
        rosterPosition: index,
        trusteeIdentity: `receiver-${index}`,
    }));

const loadSetupPackage = async (input: {
    readonly ballotPackageContext: BallotPackageContext;
    readonly config: RunnerConfig;
    readonly runtime: RuntimeBinding;
}): Promise<{
    readonly fromCheckpoint: boolean;
    readonly value: Record<string, unknown>;
}> => {
    const statementBuild = buildAggregateDerivationStatement(
        input.ballotPackageContext.statementInput,
    );
    const context = checkpointContext({
        ...input.runtime,
        checkpointName: 'aggregate-kernel-bgv-passive-setup',
        input: {
            ceremonyId: statementBuild.statement.ceremonyId,
            manifestHash: statementBuild.statement.manifestHash,
            rosterHash: statementBuild.statement.rosterHash,
            target: input.config.target,
            thresholdProfileHash: statementBuild.statement.thresholdProfileHash,
        },
        stage: 'aggregate-kernel-bgv-passive-setup',
    });

    return loadOrComputeCheckpoint<Record<string, unknown>>({
        checkpointDir: input.config.checkpointDir,
        compute: () => {
            const setupPackage =
                input.ballotPackageContext.kernel.generateBgvPassiveSetup({
                    ceremonyId: statementBuild.statement.ceremonyId,
                    manifestHash: statementBuild.statement.manifestHash,
                    participants: setupParticipants(statementBuild.statement),
                    rosterHash: statementBuild.statement.rosterHash,
                    setupSeed:
                        'accepted-encrypted-aggregate-evaluator-test-seed',
                    thresholdProfileHash:
                        statementBuild.statement.thresholdProfileHash,
                }) as Record<string, unknown>;
            if (setupPackage.ok === false) {
                throw new Error(
                    `BGV setup generation failed: ${canonicalJson(setupPackage)}`,
                );
            }

            return { value: setupPackage };
        },
        context,
        forceRecompute: input.config.forceRecompute,
        requireCheckpoints: input.config.requireCheckpoints,
        resumeCheckpoints: input.config.resumeCheckpoints,
    });
};

const deriveSharedBridgeSupportHashes = (input: {
    readonly ballotSetHash: string;
    readonly ceremonyId: string;
    readonly setupPackageHash: string;
}): BridgeSupportHashes => ({
    aggregateSelectionPolicyHash: deriveProtocolHash('ChallengeDomainHash', {
        ballotSetHash: input.ballotSetHash,
        ceremonyId: input.ceremonyId,
        purpose: 'accepted-encrypted-aggregate-evaluator-selection-policy-v1',
        setupPackageHash: input.setupPackageHash,
    }),
    bridgeWitnessPrivacyProfileHash: deriveProtocolHash('ChallengeDomainHash', {
        ballotSetHash: input.ballotSetHash,
        ceremonyId: input.ceremonyId,
        purpose: 'accepted-encrypted-aggregate-evaluator-witness-privacy-v1',
        setupPackageHash: input.setupPackageHash,
    }),
    heParamHash: deriveProtocolHash('ChallengeDomainHash', {
        ballotSetHash: input.ballotSetHash,
        ceremonyId: input.ceremonyId,
        purpose: 'accepted-encrypted-aggregate-evaluator-he-param-v1',
        setupPackageHash: input.setupPackageHash,
    }),
});

const createAggregateContributionSignature = (input: {
    readonly actionContext: ActionContext;
    readonly aggregateContributionHash: string;
    readonly manifestHash: string;
}): ProtocolSignatureEnvelope => {
    const keyFixture = createMlDsaKeyPairFixture(
        `aggregate-ready-${input.actionContext.signerIdentity}`,
    );

    return createProtocolSignatureFixture({
        profile: createMlDsaSignatureProfileFixture(),
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        publicKeyHash: keyFixture.publicKeyHash,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            boardHeadHash: input.actionContext.boardHeadHash,
            byteLength: 64,
            ceremonyId: input.actionContext.ceremonyId,
            chunkMerkleRoot: null,
            contextHash: input.actionContext.contextHash,
            deviceEpoch: input.actionContext.deviceEpoch,
            manifestHash: input.manifestHash,
            objectRoot: input.aggregateContributionHash,
            objectType: 'AggregateContribution',
            objectVersion: 1,
            recoveryEpoch: input.actionContext.recoveryEpoch,
            signerIdentity: input.actionContext.signerIdentity,
            signerRole: 'Trustee',
        },
    });
};

const bridgeCheckpointContext = (input: {
    readonly config: RunnerConfig | WorkerRunConfig;
    readonly receiver: number;
    readonly runtime: RuntimeBinding;
    readonly setupPackage: Record<string, unknown>;
    readonly supportHashes: BridgeSupportHashes;
}): CheckpointContext =>
    checkpointContext({
        ...input.runtime,
        checkpointName: `aggregate-kernel-bridge-contributor-${input.receiver}`,
        input: {
            receiver: input.receiver,
            setupPackageHash: input.setupPackage.setupPackageHash,
            supportHashes: input.supportHashes,
            target: input.config.target,
        },
        stage: 'aggregate-kernel-bridge-contributor',
    });

const bridgeContributor = async (input: {
    readonly componentContext: AggregateComponentContext;
    readonly config: RunnerConfig | WorkerRunConfig;
    readonly runtime: RuntimeBinding;
    readonly setupPackage: Record<string, unknown>;
    readonly supportHashes: BridgeSupportHashes;
}): Promise<{
    readonly fromCheckpoint: boolean;
    readonly value: BridgeContributorCheckpoint;
}> => {
    const receiver = input.componentContext.statement.contributorRosterPosition;
    const context = bridgeCheckpointContext({
        config: input.config,
        receiver,
        runtime: input.runtime,
        setupPackage: input.setupPackage,
        supportHashes: input.supportHashes,
    });

    return loadOrComputeCheckpoint<BridgeContributorCheckpoint>({
        cachedFreshCsprngArtifact: true,
        checkpointDir: input.config.checkpointDir,
        compute: () => {
            const bridgeEncryption =
                input.componentContext.kernel.generateAggregateBridgeEncryption(
                    {
                        aggregateDerivationComponent:
                            input.componentContext.component,
                        aggregateSelectionPolicyHash:
                            input.supportHashes.aggregateSelectionPolicyHash,
                        aggregateWitness: input.componentContext.witness,
                        bridgeWitnessPrivacyProfileHash:
                            input.supportHashes.bridgeWitnessPrivacyProfileHash,
                        closeRecord:
                            input.componentContext.postCloseEvidence
                                .closeRecord,
                        contributorActionContext:
                            input.componentContext.postCloseEvidence
                                .contributorActionContext,
                        countedBallotPackages: [
                            input.componentContext.ballotPackage,
                        ],
                        heParamHash: input.supportHashes.heParamHash,
                        includeCanonicalBytesHex: true,
                        setupPackage: input.setupPackage,
                    },
                ) as Record<string, unknown>;
            if (bridgeEncryption.ok !== true) {
                throw new Error(
                    `Bridge encryption generation failed: ${canonicalJson(bridgeEncryption)}`,
                );
            }
            const bridgeVerification =
                input.componentContext.kernel.verifyAggregateBridgeEncryption({
                    aggregateDerivationComponent:
                        input.componentContext.component,
                    aggregateSelectionPolicyHash:
                        input.supportHashes.aggregateSelectionPolicyHash,
                    bridgeEncryption,
                    bridgeWitnessPrivacyProfileHash:
                        input.supportHashes.bridgeWitnessPrivacyProfileHash,
                    closeRecord:
                        input.componentContext.postCloseEvidence.closeRecord,
                    contributorActionContext:
                        input.componentContext.postCloseEvidence
                            .contributorActionContext,
                    countedBallotPackages: [
                        input.componentContext.ballotPackage,
                    ],
                    heParamHash: input.supportHashes.heParamHash,
                    setupPackage: input.setupPackage,
                }) as Record<string, unknown>;
            if (bridgeVerification.ok !== true) {
                throw new Error(
                    `Bridge verification failed: ${canonicalJson(bridgeVerification)}`,
                );
            }
            const bridgeProofRecord =
                createPendingBridgeProofRecordFromBridgeEvidence({
                    aggregateDerivationComponent:
                        input.componentContext.component,
                    aggregateSelectionPolicyHash:
                        input.supportHashes.aggregateSelectionPolicyHash,
                    bridgeEncryptionEvidence:
                        bridgeEncryption as PendingBridgeProofRecordInput['bridgeEncryptionEvidence'],
                    bridgeEvidenceVerification:
                        bridgeVerification as PendingBridgeProofRecordInput['bridgeEvidenceVerification'],
                    bridgeWitnessPrivacyProfileHash:
                        input.supportHashes.bridgeWitnessPrivacyProfileHash,
                    heParamHash: input.supportHashes.heParamHash,
                    setupPackage:
                        input.setupPackage as PendingBridgeProofRecordInput['setupPackage'],
                });
            const actionContext = input.componentContext.postCloseEvidence
                .contributorActionContext as ActionContext;
            const contribution =
                createAggregateContributionFromBridgeProofRecord({
                    actionContext,
                    boardPosition:
                        input.componentContext.statement
                            .contributorRosterPosition,
                    bridgeProofRecord,
                    closeRecordHash:
                        input.componentContext.postCloseEvidence
                            .closeRecordHash,
                    signature: ({ aggregateContributionHash }) =>
                        createAggregateContributionSignature({
                            actionContext,
                            aggregateContributionHash,
                            manifestHash:
                                input.componentContext.statement.manifestHash,
                        }),
                });
            const encryptedAggregateInput: TopKEvaluatorEncryptedAggregateInput =
                {
                    aggregateContribution: contribution,
                    aggregateDerivationComponentHash:
                        input.componentContext.component
                            .aggregateDerivationComponentHash,
                    aggregateDerivationStatementHash:
                        input.componentContext.statement
                            .aggregateDerivationStatementHash,
                    bridgeEncryption: {
                        ...bridgeEncryption,
                        bridgeProofBytesHex: undefined,
                        sampledPublicRelationChecks: undefined,
                        statusLabels: undefined,
                    },
                    bridgeEvidenceVerification: bridgeVerification,
                    postVotingClosedContextHash:
                        input.componentContext.statement
                            .postVotingClosedContextHash,
                };

            return {
                value: {
                    bridgeEncryption,
                    bridgeVerification,
                    contribution,
                    encryptedAggregateInput,
                    receiver:
                        input.componentContext.statement
                            .contributorRosterPosition,
                },
                verifierOutput: {
                    bridgeVerification,
                    ciphertextRoot:
                        bridgeEncryption.encryptedAggregateShareCiphertextRoot,
                    proofHash: hashJson({
                        bridgeProofBytesHex:
                            bridgeEncryption.bridgeProofBytesHex,
                    }),
                },
            };
        },
        context,
        forceRecompute:
            input.config.forceRecompute instanceof Set
                ? input.config.forceRecompute
                : new Set(input.config.forceRecompute),
        requireCheckpoints: input.config.requireCheckpoints,
        requireVerifierOutput: true,
        resumeCheckpoints: input.config.resumeCheckpoints,
    });
};

const createCurrentRecoveryEpochMap = (
    contributions: readonly AggregateContribution[],
): Record<
    string,
    {
        readonly currentDeviceEpoch: number;
        readonly currentRecoveryEpoch: number;
        readonly signerIdentity: string;
    }
> =>
    Object.fromEntries(
        contributions.map((contribution) => [
            contribution.contributorIdentity,
            {
                currentDeviceEpoch: contribution.deviceEpoch,
                currentRecoveryEpoch: contribution.recoveryEpoch,
                signerIdentity: contribution.contributorIdentity,
            },
        ]),
    );

const selectedContributorCount = (input: {
    readonly config: RunnerConfig;
}): number => {
    if (input.config.selectedContributorCount !== null) {
        return input.config.selectedContributorCount;
    }

    return 2;
};

const runMain = async (config: RunnerConfig): Promise<void> => {
    const startedAt = Date.now();
    await mkdir(config.checkpointDir, { recursive: true });
    const runtime = await runtimeContext();
    const kernel = await loadTranscriptCoreKernel();
    const localRuntime = await runtimeContext();
    if (localRuntime.kernelHash !== runtime.kernelHash) {
        throw new Error('Kernel hash changed during runner startup.');
    }
    console.log(
        [
            'aggregate derivation kernel runner:',
            `target=${config.target}`,
            `workers=${config.workers}`,
            `checkpointDir=${config.checkpointDir}`,
            `resume=${String(config.resumeCheckpoints)}`,
        ].join(' '),
    );

    const ballotPackageResult = await loadBallotPackageContext({
        config,
        kernel,
        runtime,
    });
    const ballotPackageContext = ballotPackageResult.value;
    const statementBuild = buildAggregateDerivationStatement(
        ballotPackageContext.statementInput,
    );
    const contributorCount = selectedContributorCount({
        config,
    });
    const receivers = Array.from(
        { length: contributorCount },
        (_unused, index) => index + 1,
    );
    const workerOutputDirectory = path.join(
        config.checkpointDir,
        'aggregate-derivation-kernel-workers',
    );
    const setupResult = await loadSetupPackage({
        ballotPackageContext,
        config,
        runtime,
    });
    const setupPackage = setupResult.value;
    const setupPackageHash = String(setupPackage.setupPackageHash);
    const supportHashes = deriveSharedBridgeSupportHashes({
        ballotSetHash: statementBuild.statement.ballotSetHash,
        ceremonyId: statementBuild.statement.ceremonyId,
        setupPackageHash,
    });
    const bridgeForceRecompute = config.resumeCheckpoints
        ? [...config.forceRecompute]
        : [...config.forceRecompute, 'aggregate-kernel-bridge-contributor'];
    const bridgeWorkerForceRecompute = bridgeForceRecompute.filter(
        (stage) => stage !== 'aggregate-kernel-component-receiver',
    );
    const bridgeRunConfigPath = await writeWorkerRunConfig({
        checkpointDir: config.checkpointDir,
        config,
        forceRecompute: bridgeWorkerForceRecompute,
        runtime,
        resumeCheckpoints: true,
        setupPackage,
        supportHashes,
    });
    const bridgeResults = (
        await runWorkerPool({
            receivers,
            runConfigPath: bridgeRunConfigPath,
            workerCount: config.workers,
            workerJob: 'bridge-contributor',
            workerOutputDirectory,
        })
    )
        .filter(
            (
                result,
            ): result is BridgeContributorCheckpoint & {
                readonly cachedFreshCsprngArtifact: boolean;
                readonly fromCheckpoint: boolean;
                readonly workerJob: 'bridge-contributor';
            } => result.workerJob === 'bridge-contributor',
        )
        .sort((left, right) => left.receiver - right.receiver);
    const contributions = bridgeResults.map((result) => result.contribution);
    const selection = selectFirstValidAggregateContributions({
        aggregateContributionQuorum: contributorCount,
        contributions,
        currentRecoveryEpochMap: createCurrentRecoveryEpochMap(contributions),
        expectedAggregateSelectionPolicyHash:
            supportHashes.aggregateSelectionPolicyHash,
        requiredPostVotingClosedContextHash:
            statementBuild.statement.postVotingClosedContextHash,
    });
    if (!selection.ok || selection.firstValidOrderHash === undefined) {
        throw new Error(
            `Contribution selection failed: ${canonicalJson(selection)}`,
        );
    }
    const aggregateReadyRecord = createAggregateReadyRecord({
        aggregateContributionQuorum: contributorCount,
        firstValidOrderHash: selection.firstValidOrderHash,
        rosterSize: statementBuild.statement.participantCount,
        selectedContributions: selection.selectedContributions,
    });
    const aggregateReadyVerification =
        verifyAggregateReadyRecordStructure(aggregateReadyRecord);
    if (!aggregateReadyVerification.ok) {
        throw new Error(
            `Aggregate-ready verification failed: ${canonicalJson(
                aggregateReadyVerification,
            )}`,
        );
    }

    const summary = {
        aggregateReadyRecordHash: String(
            aggregateReadyRecord.aggregateReadyRecordHash,
        ),
        aggregateReadyVerificationStatus:
            aggregateReadyVerification.statusLabels[0] ??
            'AggregateReadyRecordVerified',
        bridgeContributorCount: bridgeResults.length,
        checkpointDir: config.checkpointDir,
        durationMilliseconds: Date.now() - startedAt,
        objectType: 'AggregateDerivationKernelRunSummary',
        objectVersion: 1,
        reusedCachedFreshCsprngArtifacts: bridgeResults.some(
            (result) => result.cachedFreshCsprngArtifact,
        ),
        target: config.target,
        workerCount: config.workers,
    } satisfies RunnerSummary;
    const summaryPath = path.join(
        config.checkpointDir,
        'aggregate-derivation-kernel-last-summary.json',
    );
    await writeJsonFileAtomic(summaryPath, summary);
    console.log(
        `aggregate derivation kernel summary: ${canonicalJson(summary)}`,
    );
    console.log(`summary wrote: ${summaryPath}`);
};

const runWorkerMain = async (config: WorkerConfig): Promise<void> => {
    const runConfig = await readJsonFile<
        Omit<WorkerRunConfig, 'receiver'> & { readonly receiver?: number }
    >(config.runConfigPath);
    const workerConfig = {
        ...runConfig,
        receiver: config.receiver,
    } satisfies WorkerRunConfig;
    const runtime = await runtimeContext();
    if (
        runtime.kernelHash !== workerConfig.kernelHash ||
        runtime.sourceFingerprint !== workerConfig.sourceFingerprint ||
        runtime.dependencyArtifactHash !== workerConfig.dependencyArtifactHash
    ) {
        throw new Error(
            `Worker runtime binding mismatch for receiver ${config.receiver}.`,
        );
    }
    if (config.workerJob === 'bridge-contributor') {
        if (
            workerConfig.setupPackage === undefined ||
            workerConfig.supportHashes === undefined
        ) {
            throw new Error(
                'Bridge contributor worker requires setup and hashes.',
            );
        }
        const bridgeCheckpoint =
            await readCheckpoint<BridgeContributorCheckpoint>({
                checkpointDir: workerConfig.checkpointDir,
                context: bridgeCheckpointContext({
                    config: workerConfig,
                    receiver: config.receiver,
                    runtime,
                    setupPackage: workerConfig.setupPackage,
                    supportHashes: workerConfig.supportHashes,
                }),
                requireCheckpoints: workerConfig.requireCheckpoints,
                requireVerifierOutput: true,
                resumeCheckpoints: workerConfig.resumeCheckpoints,
            });
        if (bridgeCheckpoint !== undefined) {
            await writeJsonFileAtomic(config.workerOutputPath, {
                ...bridgeCheckpoint,
                cachedFreshCsprngArtifact: true,
                fromCheckpoint: true,
                workerJob: 'bridge-contributor',
            } satisfies WorkerResult);
            console.log(
                `${workerOutputPrefix}${canonicalJson({
                    checkpoint: true,
                    receiver: config.receiver,
                    workerJob: config.workerJob,
                })}`,
            );

            return;
        }
    }
    const kernel = await loadTranscriptCoreKernel();
    const ballotPackageResult = await loadBallotPackageContext({
        config: workerConfig,
        kernel,
        runtime,
    });
    const componentResult = await loadComponentContext({
        ballotPackageContext: ballotPackageResult.value,
        config: workerConfig,
        receiver: config.receiver,
        runtime,
    });
    if (config.workerJob === 'component-receiver') {
        const result = {
            componentHash:
                componentResult.value.component
                    .aggregateDerivationComponentHash,
            receiver: config.receiver,
            statementHash:
                componentResult.value.statement
                    .aggregateDerivationStatementHash,
            workerJob: 'component-receiver',
        } satisfies WorkerResult;
        await writeJsonFileAtomic(config.workerOutputPath, result);
        console.log(
            `${workerOutputPrefix}${canonicalJson({
                receiver: config.receiver,
                workerJob: config.workerJob,
            })}`,
        );

        return;
    }
    if (
        workerConfig.setupPackage === undefined ||
        workerConfig.supportHashes === undefined
    ) {
        throw new Error('Bridge contributor worker requires setup and hashes.');
    }
    const bridgeResult = await bridgeContributor({
        componentContext: componentResult.value,
        config: workerConfig,
        runtime,
        setupPackage: workerConfig.setupPackage,
        supportHashes: workerConfig.supportHashes,
    });
    await writeJsonFileAtomic(config.workerOutputPath, {
        ...bridgeResult.value,
        cachedFreshCsprngArtifact: bridgeResult.fromCheckpoint,
        fromCheckpoint: bridgeResult.fromCheckpoint,
        workerJob: 'bridge-contributor',
    } satisfies WorkerResult);
    console.log(
        `${workerOutputPrefix}${canonicalJson({
            checkpoint: bridgeResult.fromCheckpoint,
            receiver: config.receiver,
            workerJob: config.workerJob,
        })}`,
    );
};

export const main = async (): Promise<void> => {
    if (process.argv.includes('--help')) {
        console.log(usageText);

        return;
    }
    const parsedConfig = parseRunnerConfig(process.argv.slice(2));
    if ('workerJob' in parsedConfig) {
        await runWorkerMain(parsedConfig);

        return;
    }
    await runMain(parsedConfig);
};

if (isDirectlyInvokedModule(import.meta.url)) {
    main().catch((error: unknown) => {
        console.error(error);
        process.exitCode = 1;
    });
}
