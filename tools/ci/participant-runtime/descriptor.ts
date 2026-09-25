// The participant runtime descriptor holds every record, object and state
// bound the worker enforces. The assembly derives it from the profile's owning
// models; the worker checks its shape and binds its exact JSON encoding into
// the runtime identity, so no other bound can open a retained root.
export type ParticipantDescriptor = Readonly<{
    participantCount: number;
    optionCount: number;
    registration: Readonly<{
        publicKeyBytes: number;
        maximumProofBytes: number;
        maximumHeaderBytes: number;
        maximumPollDefinitionBytes: number;
        maximumUsernameIngressBytes: number;
        signatureBytes: number;
        recipientCapsuleBytes: number;
        signingCapsuleBytes: number;
        maximumProposalBytes: number;
    }>;
    root: Readonly<{
        maximumRecords: number;
        maximumRootBytes: number;
        setupReferenceBytes: number;
    }>;
    contribution: Readonly<{
        // Setup polynomial i is statement object i + 1; object zero is the
        // statement header.
        expandedPolynomials: number;
        // The prover commits these witness columns, the base mask and the
        // degree mask in the first oracle.
        firstOracleColumns: number;
        statementBytes: number;
        saltBytes: number;
        bodyHeaderBytes: number;
        proofHeaderBytes: number;
        minimumProofBytes: number;
        maximumProofBytes: number;
        maximumStateBytes: number;
        maximumCheckpointHeaderBytes: number;
        confirmationBodyBytes: number;
        openingBodyBytes: number;
        confirmationPacketBytes: number;
        requiredStorageBytes: number;
        // The polynomials a contribution body carries, in body order, each
        // of coefficients of one width.
        polynomials: readonly Readonly<{
            expandedIndex: number;
            bytes: number;
            coefficients: number;
        }>[];
        // Their retained records of at most one mebibyte.
        publicRecords: readonly Readonly<{
            object: number;
            offset: number;
            length: number;
        }>[];
        checkpointLengths: readonly number[];
    }>;
    ballot: Readonly<{
        minimumScore: number;
        maximumScore: number;
        recordBytes: number;
        // The encryption and proof randomness banks, in journal order.
        randomBudgets: readonly number[];
        journalRecords: number;
        maximumStateBytes: number;
        minimumBodyBytes: number;
        maximumBodyBytes: number;
        envelopeBytes: number;
        requiredStorageBytes: number;
    }>;
}>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const positive = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

const natural = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

const positiveFields = (value: unknown, names: readonly string[]): boolean =>
    isRecord(value) &&
    Object.keys(value).length === names.length &&
    names.every((name) => positive(value[name]));

const contributionScalars = [
    'expandedPolynomials',
    'firstOracleColumns',
    'statementBytes',
    'saltBytes',
    'bodyHeaderBytes',
    'proofHeaderBytes',
    'minimumProofBytes',
    'maximumProofBytes',
    'maximumStateBytes',
    'maximumCheckpointHeaderBytes',
    'confirmationBodyBytes',
    'openingBodyBytes',
    'confirmationPacketBytes',
    'requiredStorageBytes',
] as const;

const validContribution = (value: unknown): boolean => {
    if (
        !isRecord(value) ||
        Object.keys(value).length !== contributionScalars.length + 3 ||
        !contributionScalars.every((name) => positive(value[name])) ||
        !Array.isArray(value.polynomials) ||
        !Array.isArray(value.publicRecords) ||
        !Array.isArray(value.checkpointLengths)
    )
        return false;
    const polynomials: unknown[] = value.polynomials;
    const records: unknown[] = value.publicRecords;
    const lengths: unknown[] = value.checkpointLengths;
    return (
        polynomials.length > 0 &&
        polynomials.every(
            (polynomial) =>
                isRecord(polynomial) &&
                Object.keys(polynomial).length === 3 &&
                natural(polynomial.expandedIndex) &&
                positive(polynomial.bytes) &&
                positive(polynomial.coefficients) &&
                polynomial.bytes % polynomial.coefficients === 0,
        ) &&
        records.length >= polynomials.length &&
        records.every(
            (record) =>
                isRecord(record) &&
                Object.keys(record).length === 3 &&
                positive(record.object) &&
                natural(record.offset) &&
                positive(record.length),
        ) &&
        lengths.length > 0 &&
        lengths.every(positive)
    );
};

const ballotScalars = [
    'minimumScore',
    'maximumScore',
    'recordBytes',
    'journalRecords',
    'maximumStateBytes',
    'minimumBodyBytes',
    'maximumBodyBytes',
    'envelopeBytes',
    'requiredStorageBytes',
] as const;

const validBallot = (value: unknown): boolean => {
    if (
        !isRecord(value) ||
        Object.keys(value).length !== ballotScalars.length + 1 ||
        !ballotScalars.every((name) => positive(value[name])) ||
        !Array.isArray(value.randomBudgets)
    )
        return false;
    const budgets: unknown[] = value.randomBudgets;
    return budgets.length === 2 && budgets.every(positive);
};

export const parseParticipantDescriptor = (
    value: unknown,
): ParticipantDescriptor => {
    if (
        !isRecord(value) ||
        Object.keys(value).length !== 6 ||
        !positive(value.participantCount) ||
        !positive(value.optionCount) ||
        !positiveFields(value.registration, [
            'publicKeyBytes',
            'maximumProofBytes',
            'maximumHeaderBytes',
            'maximumPollDefinitionBytes',
            'maximumUsernameIngressBytes',
            'signatureBytes',
            'recipientCapsuleBytes',
            'signingCapsuleBytes',
            'maximumProposalBytes',
        ]) ||
        !positiveFields(value.root, [
            'maximumRecords',
            'maximumRootBytes',
            'setupReferenceBytes',
        ]) ||
        !validContribution(value.contribution) ||
        !validBallot(value.ballot)
    )
        throw new Error('Malformed participant runtime descriptor.');
    return value as ParticipantDescriptor;
};
