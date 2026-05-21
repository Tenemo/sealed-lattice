import {
    checkpointPayload,
    checkpointRecord,
    mandatoryProofBenchmarkCheckpointNames,
    type ProofBenchmarkCheckpointStore,
} from './ballot-privacy-proof-benchmark-checkpoints';
import {
    captureRuntimeMemorySnapshot,
    type RuntimeMemorySnapshot,
} from './ballot-privacy-proof-benchmark-memory';
import { createMandatoryProfileBallotProofRecordBenchmarkFixture } from './ballot-privacy-proof-record-generation-fixtures';
import { runTimedTestStep, type TimedTestStepMetric } from './timed-test-steps';

import { deriveProtocolDigest } from '#packages/crypto/src/index';
import {
    aggregateWitnessFromReceiverPlaintext,
    buildAggregateDerivationProofInput,
    buildAggregateDerivationStatement,
    createAggregateDerivationComponent,
    createShareCommitmentMessageBoundCert,
    sumAggregateDerivationWitnesses,
    type AggregateDerivationWitnessInput,
} from '#packages/protocol/src/ballot-privacy/index';
import {
    createFixtureRandomnessSource,
    createReceiverKeyProof,
    generateReceiverState,
    type ReceiverEncryptionSecretState,
} from '#packages/protocol/src/ballot-privacy/lattice-primitives';
import { createBallotPrivacyProfileSet } from '#packages/protocol/src/ballot-privacy/profiles';
import { createReceiverKeyLinearProofStatement } from '#packages/protocol/src/ballot-privacy/receiver-key-linear-statement';
import {
    createReceiverKeyLinearProofEncoding,
    createReceiverKeyLinearProofParameterSet,
    createReceiverKeyProofMaterial,
} from '#packages/protocol/src/ballot-privacy/receiver-key-proof-parameters';
import type {
    ClaimBearingBallotPackage,
    ProtocolDigest,
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
    ShareCommitmentMessageBoundCert,
} from '#packages/types/src/index';
import type {
    BallotPrivacyKernelVerification,
    BallotPrivacyProofGeneration,
    BallotPrivacyReceiverKeyProofGeneration,
    TranscriptCoreKernel,
} from '#packages/wasm/src/transcript-core-bridge';

type ComponentProofRecord = {
    readonly componentId: string;
    readonly proofSizeBytes: number;
};

type ComponentProofInput = {
    readonly componentId: string;
    readonly proofBytesHex: string;
    readonly proofStatement?: Record<string, unknown>;
    readonly proofStatementFormat: string;
};

type ReceiverEncryptionPublicKeyMaterialForBenchmark = {
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly publicMatrixSeedDigest: ProtocolDigest;
};

export type RuntimeBenchmarkContext = {
    readonly browser?: string;
    readonly cpuThrottle?: {
        readonly baselineScore: number;
        readonly measuredScore: number;
        readonly source: string;
        readonly targetScore: number;
        readonly throttleRate: number;
    };
    readonly deviceClass: 'desktop' | 'mobile' | 'node';
    readonly provider?: string;
    readonly runtimeLabel: string;
    readonly userAgent?: string;
    readonly viewportHeight?: number;
    readonly viewportWidth?: number;
};

export type ComponentProofBenchmarkMetric = {
    readonly backendSourceColumnCount?: number;
    readonly ciphertextChunkCount?: number;
    readonly componentId: string;
    readonly plaintextBitLength?: number;
    readonly proofSizeBytes: number;
    readonly proofStatementFormat: string;
    readonly receiverCount?: number;
    readonly sourceColumnPackingCount?: number;
    readonly statementColumns?: number;
    readonly statementRows?: number;
};

export type MandatoryBallotProofRecordBenchmarkReport = {
    readonly componentProofs: readonly ComponentProofBenchmarkMetric[];
    readonly generationMs: number;
    readonly memoryAfterGeneration: RuntimeMemorySnapshot;
    readonly memoryAfterPackageVerification: RuntimeMemorySnapshot;
    readonly memoryAfterVerification: RuntimeMemorySnapshot;
    readonly memoryBeforeGeneration: RuntimeMemorySnapshot;
    readonly operation: 'mandatory-ballot-proof-record';
    readonly packageVerificationMs: number;
    readonly proofSizeBytes: number;
    readonly runtime: RuntimeBenchmarkContext;
    readonly steps: readonly TimedTestStepMetric[];
    readonly totalComponentProofSizeBytes: number;
    readonly verificationMs: number;
};

export type ReceiverKeyProofBenchmarkReport = {
    readonly generationMs: number;
    readonly memoryAfterGeneration: RuntimeMemorySnapshot;
    readonly memoryAfterVerification: RuntimeMemorySnapshot;
    readonly memoryBeforeGeneration: RuntimeMemorySnapshot;
    readonly operation: 'receiver-key-proof';
    readonly proofSizeBytes: number;
    readonly runtime: RuntimeBenchmarkContext;
    readonly steps: readonly TimedTestStepMetric[];
    readonly verificationMs: number;
};

export type AggregateDerivationProofBenchmarkReport = {
    readonly canonicalTurnout: number;
    readonly generationMs: number;
    readonly memoryAfterGeneration: RuntimeMemorySnapshot;
    readonly memoryAfterVerification: RuntimeMemorySnapshot;
    readonly memoryBeforeGeneration: RuntimeMemorySnapshot;
    readonly operation: 'aggregate-derivation-proof';
    readonly optionCount: number;
    readonly participantCount: number;
    readonly proofSizeBytes: number;
    readonly runtime: RuntimeBenchmarkContext;
    readonly shareVectorWidth: number;
    readonly statementColumns: number;
    readonly statementRows: number;
    readonly steps: readonly TimedTestStepMetric[];
    readonly verificationMs: number;
};

export type ReceiverKeyProofBenchmarkInput = {
    readonly linearStatement: unknown;
    readonly parameterSet: unknown;
    readonly proofEncoding: unknown;
    readonly proverRandomnessHex: string;
    readonly publicRandomnessHex: string;
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverKeyProofInput: {
        readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterialForBenchmark;
        readonly receiverPublicKey: ReceiverEncryptionPublicKey;
        readonly secretState: ReceiverEncryptionSecretState;
    };
    readonly secretState: ReceiverEncryptionSecretState;
};

const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'ballot-privacy-proof-benchmark',
    });

export const createReceiverKeyProofBenchmarkInput =
    (): ReceiverKeyProofBenchmarkInput => {
        const profileSet = createBallotPrivacyProfileSet();
        const receiverState = generateReceiverState({
            ceremonyId: 'ceremony-proof-benchmark',
            manifestDigest: digest('manifest'),
            randomnessSource: createFixtureRandomnessSource(
                'receiver-key-proof-benchmark',
            ),
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });

        return {
            linearStatement: createReceiverKeyLinearProofStatement({
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
            }),
            parameterSet: createReceiverKeyLinearProofParameterSet(),
            proofEncoding: createReceiverKeyLinearProofEncoding(),
            proverRandomnessHex: '09'.repeat(32),
            publicRandomnessHex: '00'.repeat(32),
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverKeyProofInput: {
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverPublicKey: receiverState.receiverPublicKey,
                secretState: receiverState.secretState,
            },
            secretState: receiverState.secretState,
        };
    };

const receiverKeyProofRecordForGeneration = (input: {
    readonly generation: BallotPrivacyReceiverKeyProofGeneration;
    readonly request: ReceiverKeyProofBenchmarkInput;
}): unknown => {
    const proofBytesHex = input.generation.proofBytesHex;
    if (proofBytesHex === undefined) {
        throw new Error('Receiver-key proof generation did not emit bytes.');
    }

    return createReceiverKeyProof({
        proofMaterial: createReceiverKeyProofMaterial({
            proofBytesHex,
            publicRandomnessHex: input.request.publicRandomnessHex,
        }),
        publicKeyMaterial:
            input.request.receiverKeyProofInput.publicKeyMaterial,
        receiverEncryptionProfile: input.request.receiverEncryptionProfile,
        receiverPublicKey:
            input.request.receiverKeyProofInput.receiverPublicKey,
        secretState: input.request.receiverKeyProofInput.secretState,
    });
};

const requireGenerationProofSize = (
    generation: Pick<BallotPrivacyProofGeneration, 'proofSizeBytes'>,
    label: string,
): number => {
    const proofSizeBytes = generation.proofSizeBytes;
    if (
        proofSizeBytes === undefined ||
        !Number.isSafeInteger(proofSizeBytes) ||
        proofSizeBytes < 0
    ) {
        throw new Error(`${label} did not report a canonical proof size.`);
    }

    return proofSizeBytes;
};

const proofByteLength = (proofBytesHex: string): number => {
    if (!/^(?:[0-9a-f]{2})*$/u.test(proofBytesHex)) {
        throw new Error('Proof bytes must be lowercase hexadecimal bytes.');
    }

    return proofBytesHex.length / 2;
};

const recordValue = (value: unknown): Record<string, unknown> | undefined =>
    typeof value === 'object' && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;

const numberValue = (value: unknown): number | undefined =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
        ? value
        : undefined;

const sourceBackendColumnCount = (
    proofStatement: Record<string, unknown>,
): number | undefined => {
    const sourceBackendColumnIndices =
        proofStatement.sourceBackendColumnIndices;
    if (Array.isArray(sourceBackendColumnIndices)) {
        return sourceBackendColumnIndices.length;
    }

    const sourceColumnPackings = proofStatement.sourceColumnPackings;
    if (!Array.isArray(sourceColumnPackings)) {
        return undefined;
    }

    const packings = sourceColumnPackings as readonly unknown[];

    return packings.reduce<number>((columnCount, packing) => {
        const packingRecord = recordValue(packing);
        const bindings = packingRecord?.bindings;

        return columnCount + (Array.isArray(bindings) ? bindings.length : 0);
    }, 0);
};

const receiverRows = (
    proofStatement: Record<string, unknown>,
): readonly Record<string, unknown>[] => {
    const rows = proofStatement.receiverRows;

    return Array.isArray(rows)
        ? rows.flatMap((row) => {
              const rowRecord = recordValue(row);

              return rowRecord === undefined ? [] : [rowRecord];
          })
        : [];
};

const receiverRowSum = (
    rows: readonly Record<string, unknown>[],
    fieldName: string,
): number | undefined => {
    if (rows.length === 0) {
        return undefined;
    }

    return rows.reduce(
        (sum, row) => sum + (numberValue(row[fieldName]) ?? 0),
        0,
    );
};

const firstReceiverRowNumber = (
    rows: readonly Record<string, unknown>[],
    fieldName: string,
): number | undefined =>
    rows.length === 0 ? undefined : numberValue(rows[0]?.[fieldName]);

const componentProofMetrics = (
    generation: BallotPrivacyProofGeneration,
): readonly ComponentProofBenchmarkMetric[] => {
    const componentProofBundle = recordValue(generation.componentProofBundle);
    const componentProofRecords = Array.isArray(
        componentProofBundle?.componentProofs,
    )
        ? (componentProofBundle.componentProofs.flatMap((componentProof) => {
              const componentProofRecord = recordValue(componentProof);
              const componentId = componentProofRecord?.componentId;
              const proofSizeBytes = componentProofRecord?.proofSizeBytes;

              return typeof componentId === 'string' &&
                  typeof proofSizeBytes === 'number'
                  ? [
                        {
                            componentId,
                            proofSizeBytes,
                        } satisfies ComponentProofRecord,
                    ]
                  : [];
          }) satisfies ComponentProofRecord[])
        : [];
    const proofSizesByComponentId = new Map(
        componentProofRecords.map((componentProof) => [
            componentProof.componentId,
            componentProof.proofSizeBytes,
        ]),
    );
    const componentProofInputs = Array.isArray(generation.componentProofInputs)
        ? (generation.componentProofInputs.flatMap((componentProofInput) => {
              const proofInput = recordValue(componentProofInput);
              const componentId = proofInput?.componentId;
              const proofBytesHex = proofInput?.proofBytesHex;
              const proofStatementFormat = proofInput?.proofStatementFormat;

              return typeof componentId === 'string' &&
                  typeof proofBytesHex === 'string' &&
                  typeof proofStatementFormat === 'string'
                  ? [
                        {
                            componentId,
                            proofBytesHex,
                            proofStatement:
                                proofInput === undefined
                                    ? undefined
                                    : recordValue(proofInput.proofStatement),
                            proofStatementFormat,
                        } satisfies ComponentProofInput,
                    ]
                  : [];
          }) satisfies ComponentProofInput[])
        : [];

    return componentProofInputs.map((proofInput) => {
        const proofStatement = proofInput.proofStatement ?? {};
        const rows = receiverRows(proofStatement);
        const proofSizeBytes =
            proofSizesByComponentId.get(proofInput.componentId) ??
            proofByteLength(proofInput.proofBytesHex);
        const sourceColumnPackings = proofStatement.sourceColumnPackings;

        return {
            backendSourceColumnCount: sourceBackendColumnCount(proofStatement),
            ciphertextChunkCount: receiverRowSum(rows, 'ciphertextChunkCount'),
            componentId: proofInput.componentId,
            plaintextBitLength: firstReceiverRowNumber(
                rows,
                'plaintextBitLength',
            ),
            proofSizeBytes,
            proofStatementFormat: proofInput.proofStatementFormat,
            receiverCount: rows.length === 0 ? undefined : rows.length,
            sourceColumnPackingCount: Array.isArray(sourceColumnPackings)
                ? sourceColumnPackings.length
                : undefined,
            statementColumns: numberValue(proofStatement.statementColumns),
            statementRows: numberValue(proofStatement.statementRows),
        };
    });
};

export const verifyMandatoryBallotProofBenchmarkShape = (
    report: MandatoryBallotProofRecordBenchmarkReport,
): void => {
    const componentById = new Map(
        report.componentProofs.map((componentProof) => [
            componentProof.componentId,
            componentProof,
        ]),
    );
    const scoreComponent = componentById.get(
        'score-and-shamir-field-component',
    );
    const payloadComponent = componentById.get(
        'payload-plaintext-field-component',
    );
    const shareCommitmentComponent = componentById.get(
        'share-commitment-component',
    );
    const receiverEncryptionComponent = componentById.get(
        'receiver-encryption-component',
    );
    const receiverKeyBindingComponent = componentById.get(
        'receiver-key-binding-component',
    );

    if (
        scoreComponent?.statementRows !== 82 ||
        scoreComponent.statementColumns !== 404 ||
        scoreComponent.backendSourceColumnCount !== 10_340
    ) {
        throw new Error('Mandatory score/Shamir benchmark shape drifted.');
    }
    if (
        payloadComponent?.statementRows !== 200 ||
        payloadComponent.statementColumns !== 1_800 ||
        payloadComponent.backendSourceColumnCount !== 101_520
    ) {
        throw new Error('Mandatory payload benchmark shape drifted.');
    }
    if (
        shareCommitmentComponent?.statementRows !== 320 ||
        shareCommitmentComponent.statementColumns !== 5_680 ||
        shareCommitmentComponent.receiverCount !== 20
    ) {
        throw new Error('Mandatory share-commitment benchmark shape drifted.');
    }
    if (
        receiverEncryptionComponent?.statementRows !== 1_800 ||
        receiverEncryptionComponent.statementColumns !== 3_600 ||
        receiverEncryptionComponent.receiverCount !== 20 ||
        receiverEncryptionComponent.ciphertextChunkCount !== 360 ||
        receiverEncryptionComponent.plaintextBitLength !== 4_508
    ) {
        throw new Error(
            'Mandatory receiver-encryption benchmark shape drifted.',
        );
    }
    if (receiverKeyBindingComponent?.proofSizeBytes !== 0) {
        throw new Error(
            'Mandatory receiver-key binding benchmark should remain public-zero.',
        );
    }
};

const buildBallotProofVerificationInput = (input: {
    readonly generation: BallotPrivacyProofGeneration;
    readonly request: ReturnType<
        typeof createMandatoryProfileBallotProofRecordBenchmarkFixture
    >['request'];
}): Parameters<TranscriptCoreKernel['verifyBallotProof']>[0] => ({
    ballotProof: input.generation.ballotProof,
    componentBundleStatement: input.request.componentBundleStatement,
    componentProofBundle: input.generation.componentProofBundle,
    componentProofInputs: input.generation.componentProofInputs,
    linearStatement: input.request.linearStatement,
    parameterSet: input.generation.parameterSet,
    proofBytesHex: input.generation.proofBytesHex,
    proofEncoding: input.generation.proofEncoding,
    publicRandomnessHex: input.request.publicRandomnessHex,
    statement: input.request.statement,
});

export const buildClaimBearingBallotPackageForBenchmark = (input: {
    readonly fixture: ReturnType<
        typeof createMandatoryProfileBallotProofRecordBenchmarkFixture
    >;
    readonly generation: BallotPrivacyProofGeneration;
}): ClaimBearingBallotPackage =>
    ({
        ballotPackageDigest:
            input.fixture.request.statement.ballotPackageDigest,
        ballotProof: input.generation.ballotProof,
        ballotProofStatement: input.fixture.request.statement,
        componentBundleStatement:
            input.fixture.request.componentBundleStatement,
        componentProofBundle: input.generation.componentProofBundle,
        componentProofInputs: input.generation.componentProofInputs,
        linearStatement: input.fixture.request.linearStatement,
        objectType: 'ClaimBearingBallotPackage',
        objectVersion: 1,
        parameterSet: input.generation.parameterSet,
        proofBytesHex: input.generation.proofBytesHex,
        proofEncoding: input.generation.proofEncoding,
        publicRandomnessHex: input.fixture.request.publicRandomnessHex,
        receiverKeyProofRootEvidence:
            input.fixture.receiverKeyProofRootEvidence,
        receiverPayloads: input.fixture.claimBearingReceiverPayloads,
        shareCommitments: input.fixture.claimBearingShareCommitments,
    }) as ClaimBearingBallotPackage;

const aggregateReceiverWitnessForBenchmark = (
    fixture: ReturnType<
        typeof createMandatoryProfileBallotProofRecordBenchmarkFixture
    >,
): AggregateDerivationWitnessInput => {
    const receiverPayloadPlaintext =
        fixture.projectionWitness.receiverPayloadPlaintexts?.find(
            (plaintext) => plaintext.receiverRosterPosition === 1,
        );
    const shareCommitmentOpening =
        fixture.projectionWitness.shareCommitmentOpenings.find(
            (opening) => opening.receiverRosterPosition === 1,
        );
    if (
        receiverPayloadPlaintext === undefined ||
        shareCommitmentOpening === undefined
    ) {
        throw new Error(
            'Benchmark fixture should include receiver-1 witness material.',
        );
    }

    return aggregateWitnessFromReceiverPlaintext({
        openingRandomness: shareCommitmentOpening.openingRandomness,
        receiverShareVector: receiverPayloadPlaintext.receiverShareVector,
    });
};

const aggregateShareCommitmentMessageBoundCertForBenchmark = (
    fixture: ReturnType<
        typeof createMandatoryProfileBallotProofRecordBenchmarkFixture
    >,
): ShareCommitmentMessageBoundCert => {
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: fixture.relationInput.optionCount,
    });

    return createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
};

const createAggregatePostCloseEvidenceForBenchmark = (input: {
    readonly ceremonyId: string;
    readonly contributorIdentity: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly rosterExternalAcceptanceDigest: ProtocolDigest;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
}): {
    readonly closeRecord: Record<string, unknown>;
    readonly contributorActionContext: Record<string, unknown>;
    readonly closeRecordDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
} => {
    const closeRecordPayload = {
        boardPosition: 0,
        boardSequence: 7,
        ceremonyId: input.ceremonyId,
        closeKind: 'VotingClosed',
        closedBoardHeadDigest: input.votingClosedBoardHeadDigest,
        electionManifestDigest: input.electionManifestDigest,
        objectType: 'CloseRecord',
        objectVersion: 1,
        organizerIdentity: 'organizer-1',
    };
    const closeRecordDigest = deriveProtocolDigest(
        'CloseRecordDigest',
        closeRecordPayload,
    );
    const postVotingClosedContextDigest = deriveProtocolDigest(
        'PostVotingClosedContextDigest',
        {
            ceremonyId: input.ceremonyId,
            closeRecordDigest,
            electionManifestDigest: input.electionManifestDigest,
            votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
        },
    );
    const contributorActionContextPayload = {
        acceptedRecoveryEpochUpdateDigest: null,
        actionSequence: 1,
        boardHeadDigest: input.votingClosedBoardHeadDigest,
        boardSequence: 7,
        ceremonyId: input.ceremonyId,
        contextDigest: postVotingClosedContextDigest,
        deviceEpoch: 0,
        electionManifestDigest: input.electionManifestDigest,
        recoveryEpoch: 0,
        recoveryPolicyDigest: digest('aggregate-recovery-policy'),
        rosterExternalAcceptanceDigest: input.rosterExternalAcceptanceDigest,
        signerIdentity: input.contributorIdentity,
    };
    const contributorActionContextDigest = deriveProtocolDigest(
        'ActionContextDigest',
        contributorActionContextPayload,
    );

    return {
        closeRecord: {
            ...closeRecordPayload,
            closeRecordDigest,
            postVotingClosedContextDigest,
        },
        closeRecordDigest,
        contributorActionContext: {
            ...contributorActionContextPayload,
            actionContextDigest: contributorActionContextDigest,
        },
        postVotingClosedContextDigest,
    };
};

export const runMandatoryBallotProofRecordBenchmark = (input: {
    readonly checkpoints?: ProofBenchmarkCheckpointStore;
    readonly kernel: TranscriptCoreKernel;
    readonly resumeFromCheckpoints?: boolean;
    readonly runtime: RuntimeBenchmarkContext;
}): {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly claimVerification: BallotPrivacyKernelVerification;
    readonly fixture: ReturnType<
        typeof createMandatoryProfileBallotProofRecordBenchmarkFixture
    >;
    readonly generation: BallotPrivacyProofGeneration;
    readonly report: MandatoryBallotProofRecordBenchmarkReport;
    readonly verification: BallotPrivacyKernelVerification;
} => {
    const steps: TimedTestStepMetric[] = [];
    const fixture = runTimedTestStep(
        steps,
        'build mandatory proof relation request',
        () => createMandatoryProfileBallotProofRecordBenchmarkFixture(),
    );
    const { request } = fixture;
    input.checkpoints?.write?.(
        mandatoryProofBenchmarkCheckpointNames.relationRequest,
        checkpointRecord(
            mandatoryProofBenchmarkCheckpointNames.relationRequest,
            {
                publicContext: fixture.publicContext,
                request,
            },
        ),
    );
    input.checkpoints?.write?.(
        mandatoryProofBenchmarkCheckpointNames.loweredStatements,
        checkpointRecord(
            mandatoryProofBenchmarkCheckpointNames.loweredStatements,
            {
                componentBundleStatement: request.componentBundleStatement,
                componentProofInputs: request.componentProofInputs,
                linearStatement: request.linearStatement,
                statement: request.statement,
            },
        ),
    );
    const memoryBeforeGeneration = captureRuntimeMemorySnapshot();
    const generationCheckpoint = checkpointPayload(
        input.checkpoints?.read?.(
            mandatoryProofBenchmarkCheckpointNames.generatedProofRecord,
        ),
        mandatoryProofBenchmarkCheckpointNames.generatedProofRecord,
    );
    const checkpointGeneration = recordValue(generationCheckpoint)?.generation;
    const shouldUseGenerationCheckpoint =
        input.resumeFromCheckpoints === true &&
        recordValue(checkpointGeneration) !== undefined;
    const generation = runTimedTestStep(
        steps,
        shouldUseGenerationCheckpoint
            ? 'load mandatory proof record checkpoint'
            : 'generate mandatory proof record',
        () =>
            shouldUseGenerationCheckpoint
                ? (checkpointGeneration as BallotPrivacyProofGeneration)
                : input.kernel.generateBallotProofRecord(request),
        { reusedCheckpoint: shouldUseGenerationCheckpoint },
    );
    const generationMs =
        steps.find(
            (step) =>
                step.name === 'generate mandatory proof record' ||
                step.name === 'load mandatory proof record checkpoint',
        )?.durationMs ?? 0;
    input.checkpoints?.write?.(
        mandatoryProofBenchmarkCheckpointNames.generatedProofRecord,
        checkpointRecord(
            mandatoryProofBenchmarkCheckpointNames.generatedProofRecord,
            {
                generation,
            },
        ),
    );
    const memoryAfterGeneration = captureRuntimeMemorySnapshot();
    const proofSizeBytes = requireGenerationProofSize(
        generation,
        'Mandatory ballot proof record generation',
    );
    const proofVerificationInput = runTimedTestStep(
        steps,
        'build mandatory proof verification input',
        () => buildBallotProofVerificationInput({ generation, request }),
    );
    const verification = runTimedTestStep(
        steps,
        'verify mandatory ballot proof record',
        () => input.kernel.verifyBallotProof(proofVerificationInput),
    );
    const verificationMs =
        steps.find(
            (step) => step.name === 'verify mandatory ballot proof record',
        )?.durationMs ?? 0;
    const memoryAfterVerification = captureRuntimeMemorySnapshot();
    const ballotPackage = runTimedTestStep(
        steps,
        'build claim-bearing ballot package',
        () =>
            buildClaimBearingBallotPackageForBenchmark({
                fixture,
                generation,
            }),
    );
    input.checkpoints?.write?.(
        mandatoryProofBenchmarkCheckpointNames.claimBearingPackage,
        checkpointRecord(
            mandatoryProofBenchmarkCheckpointNames.claimBearingPackage,
            ballotPackage,
        ),
    );
    const claimVerification = runTimedTestStep(
        steps,
        'verify claim-bearing ballot package',
        () =>
            input.kernel.verifyClaimBearingBallotPackage({
                ballotPackage,
            }),
    );
    const packageVerificationMs =
        steps.find(
            (step) => step.name === 'verify claim-bearing ballot package',
        )?.durationMs ?? 0;
    const memoryAfterPackageVerification = captureRuntimeMemorySnapshot();
    const componentProofs = runTimedTestStep(
        steps,
        'summarize mandatory component proof metrics',
        () => componentProofMetrics(generation),
    );
    const totalComponentProofSizeBytes = componentProofs.reduce(
        (sum, componentProof) => sum + componentProof.proofSizeBytes,
        0,
    );
    const report: MandatoryBallotProofRecordBenchmarkReport = {
        componentProofs,
        generationMs,
        memoryAfterGeneration,
        memoryAfterPackageVerification,
        memoryAfterVerification,
        memoryBeforeGeneration,
        operation: 'mandatory-ballot-proof-record',
        packageVerificationMs,
        proofSizeBytes,
        runtime: input.runtime,
        steps,
        totalComponentProofSizeBytes,
        verificationMs,
    };

    verifyMandatoryBallotProofBenchmarkShape(report);
    input.checkpoints?.write?.(
        mandatoryProofBenchmarkCheckpointNames.verificationReport,
        checkpointRecord(
            mandatoryProofBenchmarkCheckpointNames.verificationReport,
            {
                claimVerification,
                report,
                verification,
            },
        ),
    );

    return {
        ballotPackage,
        claimVerification,
        fixture,
        generation,
        report,
        verification,
    };
};

export const runAggregateDerivationProofBenchmark = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly checkpoints?: ProofBenchmarkCheckpointStore;
    readonly fixture: ReturnType<
        typeof createMandatoryProfileBallotProofRecordBenchmarkFixture
    >;
    readonly kernel: TranscriptCoreKernel;
    readonly resumeFromCheckpoints?: boolean;
    readonly runtime: RuntimeBenchmarkContext;
}): {
    readonly generation: BallotPrivacyProofGeneration;
    readonly report: AggregateDerivationProofBenchmarkReport;
    readonly verification: BallotPrivacyKernelVerification;
} => {
    const steps: TimedTestStepMetric[] = [];
    const postCloseEvidence = runTimedTestStep(
        steps,
        'build aggregate derivation post-close evidence',
        () =>
            createAggregatePostCloseEvidenceForBenchmark({
                ceremonyId: input.fixture.request.statement.ceremonyId,
                contributorIdentity: 'receiver-1',
                electionManifestDigest:
                    input.fixture.request.statement.manifestDigest,
                rosterExternalAcceptanceDigest:
                    input.fixture.request.statement
                        .rosterExternalAcceptanceDigest,
                votingClosedBoardHeadDigest: digest(
                    'aggregate-voting-closed-board-head',
                ),
            }),
    );
    const { aggregateCommitment, statement } = runTimedTestStep(
        steps,
        'build aggregate derivation statement',
        () =>
            buildAggregateDerivationStatement({
                ballotPackages: [input.ballotPackage],
                closeRecordDigest: postCloseEvidence.closeRecordDigest,
                contributorActionContextDigest: postCloseEvidence
                    .contributorActionContext
                    .actionContextDigest as ProtocolDigest,
                contributorIdentity: 'receiver-1',
                contributorRosterExternalAcceptanceDigest:
                    input.fixture.request.statement
                        .rosterExternalAcceptanceDigest,
                contributorRosterPosition: 1,
                postVotingClosedContextDigest:
                    postCloseEvidence.postVotingClosedContextDigest,
                unsafeSmallRosterAcknowledged: false,
                votingClosedBoardHeadDigest: digest(
                    'aggregate-voting-closed-board-head',
                ),
            }),
    );
    const witness = runTimedTestStep(
        steps,
        'build aggregate derivation witness',
        () =>
            sumAggregateDerivationWitnesses({
                witnesses: [
                    aggregateReceiverWitnessForBenchmark(input.fixture),
                ],
            }),
    );
    const proofBuild = runTimedTestStep(
        steps,
        'build aggregate derivation proof input',
        () =>
            buildAggregateDerivationProofInput({
                aggregateCommitment,
                statement,
                witness,
            }),
    );
    const memoryBeforeGeneration = captureRuntimeMemorySnapshot();
    const generationCheckpoint = checkpointPayload(
        input.checkpoints?.read?.(
            mandatoryProofBenchmarkCheckpointNames.aggregateDerivationGeneratedProofRecord,
        ),
        mandatoryProofBenchmarkCheckpointNames.aggregateDerivationGeneratedProofRecord,
    );
    const checkpointGeneration = recordValue(generationCheckpoint)?.generation;
    const shouldUseGenerationCheckpoint =
        input.resumeFromCheckpoints === true &&
        recordValue(checkpointGeneration) !== undefined;
    const generation = runTimedTestStep(
        steps,
        shouldUseGenerationCheckpoint
            ? 'load aggregate derivation proof checkpoint'
            : 'generate aggregate derivation proof',
        () =>
            shouldUseGenerationCheckpoint
                ? (checkpointGeneration as BallotPrivacyProofGeneration)
                : input.kernel.generateAggregateDerivationProof({
                      proofInput: proofBuild.proofInput,
                      proverRandomnessHex: '66'.repeat(32),
                      secretState: proofBuild.secretState,
                  }),
        { reusedCheckpoint: shouldUseGenerationCheckpoint },
    );
    const generationMs =
        steps.find(
            (step) =>
                step.name === 'generate aggregate derivation proof' ||
                step.name === 'load aggregate derivation proof checkpoint',
        )?.durationMs ?? 0;
    input.checkpoints?.write?.(
        mandatoryProofBenchmarkCheckpointNames.aggregateDerivationGeneratedProofRecord,
        checkpointRecord(
            mandatoryProofBenchmarkCheckpointNames.aggregateDerivationGeneratedProofRecord,
            {
                generation,
            },
        ),
    );
    const memoryAfterGeneration = captureRuntimeMemorySnapshot();
    const proofSizeBytes = requireGenerationProofSize(
        generation,
        'Aggregate derivation proof generation',
    );
    const proofBytesHex = generation.proofBytesHex;
    if (proofBytesHex === undefined) {
        throw new Error(
            'Aggregate derivation proof generation did not emit bytes.',
        );
    }
    const component = runTimedTestStep(
        steps,
        'build aggregate derivation component',
        () =>
            createAggregateDerivationComponent({
                aggregateCommitment,
                proofBytesHex,
                proofInput: proofBuild.proofInput,
                shareCommitmentMessageBoundCert:
                    aggregateShareCommitmentMessageBoundCertForBenchmark(
                        input.fixture,
                    ),
                statement,
            }),
    );
    const verification = runTimedTestStep(
        steps,
        'verify aggregate derivation component',
        () =>
            input.kernel.verifyAggregateDerivationProof({
                closeRecord: postCloseEvidence.closeRecord,
                component,
                contributorActionContext:
                    postCloseEvidence.contributorActionContext,
                countedBallotPackages: [input.ballotPackage],
            }),
    );
    const verificationMs =
        steps.find(
            (step) => step.name === 'verify aggregate derivation component',
        )?.durationMs ?? 0;
    const memoryAfterVerification = captureRuntimeMemorySnapshot();
    const proofStatement = recordValue(proofBuild.proofInput.proofStatement);
    const statementRows = numberValue(proofStatement?.statementRows);
    const statementColumns = numberValue(proofStatement?.statementColumns);
    if (statementRows === undefined || statementColumns === undefined) {
        throw new Error(
            'Aggregate derivation proof statement did not report its shape.',
        );
    }

    const report: AggregateDerivationProofBenchmarkReport = {
        canonicalTurnout: statement.canonicalTurnout,
        generationMs,
        memoryAfterGeneration,
        memoryAfterVerification,
        memoryBeforeGeneration,
        operation: 'aggregate-derivation-proof',
        optionCount: statement.optionCount,
        participantCount: statement.participantCount,
        proofSizeBytes,
        runtime: input.runtime,
        shareVectorWidth: statement.shareVectorWidth,
        statementColumns,
        statementRows,
        steps,
        verificationMs,
    };
    input.checkpoints?.write?.(
        mandatoryProofBenchmarkCheckpointNames.aggregateDerivationVerificationReport,
        checkpointRecord(
            mandatoryProofBenchmarkCheckpointNames.aggregateDerivationVerificationReport,
            {
                report,
                verification,
            },
        ),
    );

    return {
        generation,
        report,
        verification,
    };
};

export const runReceiverKeyProofBenchmark = (input: {
    readonly kernel: TranscriptCoreKernel;
    readonly runtime: RuntimeBenchmarkContext;
}): {
    readonly generation: BallotPrivacyReceiverKeyProofGeneration;
    readonly report: ReceiverKeyProofBenchmarkReport;
    readonly verification: BallotPrivacyKernelVerification;
} => {
    const steps: TimedTestStepMetric[] = [];
    const request = createReceiverKeyProofBenchmarkInput();
    const memoryBeforeGeneration = captureRuntimeMemorySnapshot();
    const generation = runTimedTestStep(
        steps,
        'generate receiver-key proof',
        () =>
            input.kernel.generateReceiverKeyProof({
                linearStatement: request.linearStatement,
                parameterSet: request.parameterSet,
                proofEncoding: request.proofEncoding,
                proverRandomnessHex: request.proverRandomnessHex,
                publicRandomnessHex: request.publicRandomnessHex,
                secretState: request.secretState,
            }),
    );
    const generationMs =
        steps.find((step) => step.name === 'generate receiver-key proof')
            ?.durationMs ?? 0;
    const memoryAfterGeneration = captureRuntimeMemorySnapshot();
    const proofSizeBytes = requireGenerationProofSize(
        generation,
        'Receiver-key proof generation',
    );
    const receiverKeyProof = receiverKeyProofRecordForGeneration({
        generation,
        request,
    });
    const proofBytesHex = generation.proofBytesHex;
    if (proofBytesHex === undefined) {
        throw new Error('Receiver-key proof generation did not emit bytes.');
    }
    const parameterSet = createReceiverKeyLinearProofParameterSet({
        expectedProofSizeBytes: proofSizeBytes,
    });
    const proofEncoding = createReceiverKeyLinearProofEncoding({
        expectedProofSizeBytes: proofSizeBytes,
    });
    const verification = runTimedTestStep(
        steps,
        'verify receiver-key proof',
        () =>
            input.kernel.verifyReceiverKeyProof({
                linearStatement: request.linearStatement,
                parameterSet,
                proofBytesHex,
                proofEncoding,
                publicRandomnessHex: request.publicRandomnessHex,
                receiverKeyProof,
            }),
    );
    const verificationMs =
        steps.find((step) => step.name === 'verify receiver-key proof')
            ?.durationMs ?? 0;
    const memoryAfterVerification = captureRuntimeMemorySnapshot();

    return {
        generation,
        report: {
            generationMs,
            memoryAfterGeneration,
            memoryAfterVerification,
            memoryBeforeGeneration,
            operation: 'receiver-key-proof',
            proofSizeBytes,
            runtime: input.runtime,
            steps,
            verificationMs,
        },
        verification,
    };
};

export const formatProofBenchmarkReport = (
    report:
        | MandatoryBallotProofRecordBenchmarkReport
        | AggregateDerivationProofBenchmarkReport
        | ReceiverKeyProofBenchmarkReport,
): string => JSON.stringify(report, null, 2);
