const publicArchiveResourceInputs = {
    maximumPayloadBytes: 1_048_576n,
    maximumRecordBytes: 1_572_864n,
    maximumPurposeBytes: 128n,
    maximumDependencies: 4_096n,
    maximumReplicas: 32n,
    maximumRecords: 65_536n,
    verificationKeyBytes: 1_952n,
    signatureBytes: 3_309n,
} as const;

export const archiveRecordByteLength = (
    purposeBytes: bigint,
    dependencies: bigint,
    payloadBytes: bigint,
): bigint => {
    const input = publicArchiveResourceInputs;
    if (
        purposeBytes < 1n ||
        purposeBytes > input.maximumPurposeBytes ||
        dependencies < 0n ||
        dependencies > input.maximumDependencies ||
        payloadBytes < 0n ||
        payloadBytes > input.maximumPayloadBytes
    )
        throw new RangeError('Archive inputs exceed their bounds.');
    const tupleHeader = 8n,
        itemHeader = 6n,
        variableHeader = 4n;
    const domainBytes = BigInt(
        Buffer.byteLength('sealed-lattice/archive-record/v1'),
    );
    return (
        tupleHeader +
        5n * itemHeader +
        4n * variableHeader +
        domainBytes +
        64n +
        purposeBytes +
        dependencies * (64n + 8n) +
        payloadBytes
    );
};

export const compilePublicArchiveResourceCensus = () => {
    const input = publicArchiveResourceInputs;
    const maximumEncodedRecordBytes = archiveRecordByteLength(
        input.maximumPurposeBytes,
        input.maximumDependencies,
        input.maximumPayloadBytes,
    );
    const maximumEncodeRequestBytes =
        1n +
        64n +
        4n +
        input.maximumPurposeBytes +
        2n +
        72n * input.maximumDependencies +
        4n +
        input.maximumPayloadBytes;
    const maximumReadRequestBytes =
        1n + 64n + 72n + 4n + maximumEncodedRecordBytes;
    const maximumReadResponseBytes =
        1n +
        4n +
        input.maximumPurposeBytes +
        2n +
        72n * input.maximumDependencies +
        4n +
        input.maximumPayloadBytes;
    const maximumAcknowledgementRequestBytes =
        1n +
        2n +
        2n +
        input.maximumReplicas * input.verificationKeyBytes +
        64n +
        72n +
        2n +
        input.maximumReplicas * (2n + 4n + input.signatureBytes);
    const maximumDiscoveryReferenceBytes = BigInt(
        Buffer.byteLength(
            JSON.stringify({
                identity: 'f'.repeat(128),
                byteLength: Number(input.maximumRecordBytes),
            }),
        ),
    );
    const minimumFullDiscoveryPageRecords =
        (input.maximumRecordBytes - 1n) / (maximumDiscoveryReferenceBytes + 1n);
    const maximumStaticDiscoveryRequestsPerReplica =
        (input.maximumRecords + minimumFullDiscoveryPageRecords - 1n) /
            minimumFullDiscoveryPageRecords +
        1n;
    return {
        ...input,
        maximumEncodedRecordBytes,
        maximumEncodeRequestBytes,
        maximumReadRequestBytes,
        maximumReadResponseBytes,
        maximumAcknowledgementRequestBytes,
        maximumDiscoveryReferenceBytes,
        minimumFullDiscoveryPageRecords,
        maximumStaticDiscoveryRequestsPerReplica,
        maximumConcurrentDiscoveryRequestsPerReplica: input.maximumRecords + 1n,
        maximumDiscoverySuffixBytes: BigInt(
            Buffer.byteLength(
                'discovery/' + 'f'.repeat(128) + '?after=' + 'f'.repeat(128),
            ),
        ),
        maximumSimultaneousResponseBufferBytes:
            input.maximumReplicas * input.maximumRecordBytes,
    };
};
