export const mandatoryProofBenchmarkCheckpointNames = {
    claimBearingPackage: 'ballot-privacy-proof-benchmark-claim-bearing-package',
    generatedProofRecord:
        'ballot-privacy-proof-benchmark-generated-proof-record',
    loweredStatements: 'ballot-privacy-proof-benchmark-lowered-statements',
    relationRequest: 'ballot-privacy-proof-benchmark-relation-request',
    verificationReport: 'ballot-privacy-proof-benchmark-verification-report',
} as const;

export type ProofBenchmarkCheckpointName =
    (typeof mandatoryProofBenchmarkCheckpointNames)[keyof typeof mandatoryProofBenchmarkCheckpointNames];

export type ProofBenchmarkCheckpointStore = {
    readonly read?: (checkpointName: ProofBenchmarkCheckpointName) => unknown;
    readonly write?: (
        checkpointName: ProofBenchmarkCheckpointName,
        value: unknown,
    ) => void;
};

const recordValue = (value: unknown): Record<string, unknown> | undefined =>
    typeof value === 'object' && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;

export const checkpointRecord = (
    checkpointName: ProofBenchmarkCheckpointName,
    payload: unknown,
): Record<string, unknown> => ({
    checkpointName,
    payload,
    schemaVersion: 1,
});

export const checkpointPayload = (
    value: unknown,
    checkpointName: ProofBenchmarkCheckpointName,
): unknown => {
    const record = recordValue(value);
    if (
        record?.schemaVersion !== 1 ||
        record.checkpointName !== checkpointName
    ) {
        return undefined;
    }

    return record.payload;
};
