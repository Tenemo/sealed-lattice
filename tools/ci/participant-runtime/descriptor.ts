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
}>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const positive = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

const positiveFields = (value: unknown, names: readonly string[]): boolean =>
    isRecord(value) &&
    Object.keys(value).length === names.length &&
    names.every((name) => positive(value[name]));

export const parseParticipantDescriptor = (
    value: unknown,
): ParticipantDescriptor => {
    if (
        !isRecord(value) ||
        Object.keys(value).length !== 4 ||
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
        ])
    )
        throw new Error('Malformed participant runtime descriptor.');
    return value as ParticipantDescriptor;
};
