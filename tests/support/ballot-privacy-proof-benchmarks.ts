import { deriveProtocolDigest } from '../../packages/crypto/src/index';
import {
    createFixtureRandomnessSource,
    createReceiverKeyProof,
    generateReceiverState,
    type ReceiverEncryptionSecretState,
} from '../../packages/protocol/src/ballot-privacy/lattice-primitives';
import { createBallotPrivacyProfileSet } from '../../packages/protocol/src/ballot-privacy/profiles';
import { createReceiverKeyLinearProofStatement } from '../../packages/protocol/src/ballot-privacy/receiver-key-linear-statement';
import {
    createReceiverKeyLinearProofEncoding,
    createReceiverKeyLinearProofParameterSet,
    createReceiverKeyProofMaterial,
} from '../../packages/protocol/src/ballot-privacy/receiver-key-proof-parameters';
import type {
    ProtocolDigest,
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
} from '../../packages/types/src/index';
import type {
    BallotPrivacyKernelVerification,
    BallotPrivacyProofGeneration,
    BallotPrivacyReceiverKeyProofGeneration,
    TranscriptCoreKernel,
} from '../../packages/wasm/src/transcript-core-bridge';

import { createMandatoryProfileBallotProofRecordBenchmarkFixture } from './ballot-privacy-proof-record-generation-fixtures';

type ProcessMemoryUsage = {
    readonly arrayBuffers?: number;
    readonly external?: number;
    readonly heapTotal?: number;
    readonly heapUsed?: number;
    readonly rss?: number;
};

type ProcessLike = {
    readonly memoryUsage?: () => ProcessMemoryUsage;
};

type PerformanceMemory = {
    readonly jsHeapSizeLimit?: number;
    readonly totalJSHeapSize?: number;
    readonly usedJSHeapSize?: number;
};

type PerformanceWithMemory = Performance & {
    readonly memory?: PerformanceMemory;
};

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
    readonly deviceClass: 'desktop' | 'mobile' | 'node';
    readonly provider?: string;
    readonly runtimeLabel: string;
    readonly userAgent?: string;
    readonly viewportHeight?: number;
    readonly viewportWidth?: number;
};

export type RuntimeMemorySnapshot = {
    readonly arrayBufferBytes?: number;
    readonly externalBytes?: number;
    readonly heapLimitBytes?: number;
    readonly residentSetBytes?: number;
    readonly totalHeapBytes?: number;
    readonly usedHeapBytes?: number;
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
    readonly memoryAfterVerification: RuntimeMemorySnapshot;
    readonly memoryBeforeGeneration: RuntimeMemorySnapshot;
    readonly operation: 'mandatory-ballot-proof-record';
    readonly proofSizeBytes: number;
    readonly runtime: RuntimeBenchmarkContext;
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

const runtimeNowMs = (): number => globalThis.performance?.now() ?? Date.now();

const safeMemoryInteger = (value: number | undefined): number | undefined =>
    value === undefined || !Number.isSafeInteger(value) || value < 0
        ? undefined
        : value;

export const captureRuntimeMemorySnapshot = (): RuntimeMemorySnapshot => {
    const performanceMemory = (
        globalThis.performance as PerformanceWithMemory | undefined
    )?.memory;
    if (performanceMemory !== undefined) {
        return {
            heapLimitBytes: safeMemoryInteger(
                performanceMemory.jsHeapSizeLimit,
            ),
            totalHeapBytes: safeMemoryInteger(
                performanceMemory.totalJSHeapSize,
            ),
            usedHeapBytes: safeMemoryInteger(performanceMemory.usedJSHeapSize),
        };
    }

    const processLike = (globalThis as { readonly process?: ProcessLike })
        .process;
    const memoryUsage = processLike?.memoryUsage?.();

    return memoryUsage === undefined
        ? {}
        : {
              arrayBufferBytes: safeMemoryInteger(memoryUsage.arrayBuffers),
              externalBytes: safeMemoryInteger(memoryUsage.external),
              residentSetBytes: safeMemoryInteger(memoryUsage.rss),
              totalHeapBytes: safeMemoryInteger(memoryUsage.heapTotal),
              usedHeapBytes: safeMemoryInteger(memoryUsage.heapUsed),
          };
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

export const runMandatoryBallotProofRecordBenchmark = (input: {
    readonly kernel: TranscriptCoreKernel;
    readonly runtime: RuntimeBenchmarkContext;
}): {
    readonly generation: BallotPrivacyProofGeneration;
    readonly report: MandatoryBallotProofRecordBenchmarkReport;
    readonly verification: BallotPrivacyKernelVerification;
} => {
    const { request } =
        createMandatoryProfileBallotProofRecordBenchmarkFixture();
    const memoryBeforeGeneration = captureRuntimeMemorySnapshot();
    const generationStartMs = runtimeNowMs();
    const generation = input.kernel.generateBallotProofRecord(request);
    const generationMs = runtimeNowMs() - generationStartMs;
    const memoryAfterGeneration = captureRuntimeMemorySnapshot();
    const proofSizeBytes = requireGenerationProofSize(
        generation,
        'Mandatory ballot proof record generation',
    );
    const verificationStartMs = runtimeNowMs();
    const verification = input.kernel.verifyBallotProof(
        buildBallotProofVerificationInput({ generation, request }),
    );
    const verificationMs = runtimeNowMs() - verificationStartMs;
    const memoryAfterVerification = captureRuntimeMemorySnapshot();
    const componentProofs = componentProofMetrics(generation);
    const totalComponentProofSizeBytes = componentProofs.reduce(
        (sum, componentProof) => sum + componentProof.proofSizeBytes,
        0,
    );
    const report: MandatoryBallotProofRecordBenchmarkReport = {
        componentProofs,
        generationMs,
        memoryAfterGeneration,
        memoryAfterVerification,
        memoryBeforeGeneration,
        operation: 'mandatory-ballot-proof-record',
        proofSizeBytes,
        runtime: input.runtime,
        totalComponentProofSizeBytes,
        verificationMs,
    };

    verifyMandatoryBallotProofBenchmarkShape(report);

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
    const request = createReceiverKeyProofBenchmarkInput();
    const memoryBeforeGeneration = captureRuntimeMemorySnapshot();
    const generationStartMs = runtimeNowMs();
    const generation = input.kernel.generateReceiverKeyProof({
        linearStatement: request.linearStatement,
        parameterSet: request.parameterSet,
        proofEncoding: request.proofEncoding,
        proverRandomnessHex: request.proverRandomnessHex,
        publicRandomnessHex: request.publicRandomnessHex,
        secretState: request.secretState,
    });
    const generationMs = runtimeNowMs() - generationStartMs;
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
    const verificationStartMs = runtimeNowMs();
    const verification = input.kernel.verifyReceiverKeyProof({
        linearStatement: request.linearStatement,
        parameterSet,
        proofBytesHex,
        proofEncoding,
        publicRandomnessHex: request.publicRandomnessHex,
        receiverKeyProof,
    });
    const verificationMs = runtimeNowMs() - verificationStartMs;
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
            verificationMs,
        },
        verification,
    };
};

export const formatProofBenchmarkReport = (
    report:
        | MandatoryBallotProofRecordBenchmarkReport
        | ReceiverKeyProofBenchmarkReport,
): string => JSON.stringify(report, null, 2);
