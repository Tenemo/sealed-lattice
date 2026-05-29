import type { BallotPrivacyProofGeneration } from '#packages/wasm/src/transcript-core-bridge';
import type {
    ComponentProofBenchmarkMetric,
    MandatoryBallotProofRecordBenchmarkReport,
} from '#tests/support/ballot-privacy-proof-benchmarks';

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

export const requireGenerationProofSize = (
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

export const recordValue = (
    value: unknown,
): Record<string, unknown> | undefined =>
    typeof value === 'object' && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;

export const numberValue = (value: unknown): number | undefined =>
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

export const componentProofMetrics = (
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
            'Mandatory receiver-key binding benchmark should remain a public binding check.',
        );
    }
};
