const maximumUnsigned64 = (1n << 64n) - 1n;
const hash512HexPattern = /^[0-9a-f]{128}$/u;

export const proofStorageWidthSchedule = [
    8, 32, 128, 512, 1_024, 2_048, 3_451,
] as const;

export type ProofStorageWidth = (typeof proofStorageWidthSchedule)[number];

export const proofStorageWidthProfile = {
    activeColumnLdeScratchByteLength: 1_048_576n,
    algebraicBaseColumnCount: 8,
    absoluteCapTableIdentifier: 'sealed-lattice/absolute-resource-caps/v1',
    backendProfileIdentifier:
        'packed-deep-fri-goldilocks5-rate-1-8-six-fold-rs256-183-query-v1',
    batchingFunctionCount: 18,
    custodySchemaIdentifier: 'bounded-external-storage-replay-v1',
    custodySchemaVersion: 1,
    evaluationDomainSize: 131_072,
    extensionDomainWorkingByteLength: 10_485_760n,
    externalMemoryAppendRequestByteLengthCeiling: 49_340n,
    externalMemoryBoundaryTransferLiveByteLengthCeiling: 49_508n,
    externalMemoryChunkByteLength: 49_152n,
    externalMemoryCopiedBufferByteLengthCeiling: 49_340n,
    externalMemoryEmptyResponseByteLength: 80n,
    externalMemoryOperationHeaderByteLength: 32n,
    externalMemoryReadRequestByteLength: 188n,
    externalMemoryReadResponseByteLengthCeiling: 49_320n,
    externalMemoryReadResultHeaderByteLength: 88n,
    externalMemoryRequestHeaderByteLength: 156n,
    externalMemoryResponseHeaderByteLength: 80n,
    externalMemoryTransactionOperationByteLengthNative64: 48n,
    externalMemoryTransactionRequestByteLengthNative64: 112n,
    firstDataModulus: 1_953_759_233,
    frozenInputIdentityHashDomain:
        'proof-backend-bakeoff/frozen-fragment-input/v1',
    frozenInputIdentityShake256Hex:
        '930c501295b47a502f01dd8475291d43c2a93fe8198cbe91904218eeefc68a44dd517d167b35e154853241e215255b35646a52d732edddce650777d9a0a52dec',
    frozenInputRecipeIdentifier:
        'sealed-lattice/proof-backend-bakeoff/frozen-fragment-input/v1',
    intendedReleaseRuntime: 'desktop-browser-wasm',
    legacyBaseLeafCount: 65_536n,
    maximumCommonProofByteLength: 268_435_456n,
    maximumCopiedBufferByteLength: 8_388_608n,
    maximumLocalRecordSealInvocationCount: 1_073_741_824n,
    maximumLocalRecordSealedPlaintextByteLength: 1_099_511_627_776n,
    maximumNativeCustodyPathByteLength: 1_024,
    maximumPhysicalObjectCount: 4_096n,
    maximumStoredScratchByteLength: 1_073_741_824n,
    maximumTransportByteLength: 4_294_967_291n,
    maximumWasmMemoryByteLength: 671_088_640n,
    materialRadix: 129_140_163,
    measurementRuntime: 'native-rust',
    plaintextModulus: 257,
    publicColumnDerivationAlgorithm:
        'splitmix64-column-row-goldilocks-canonical-v1',
    publicColumnInputDomain:
        'sealed-lattice/proof-storage/public-column-replay/v1',
    publicColumnSeedHex: '6a09e667f3bcc909',
    queryRepresentativeCount: 183n,
    authenticatedMapEntryByteLengthNative64: 56n,
    authenticatedTreeOpeningHeaderByteLengthNative64: 32n,
    btreeMapHeaderByteLengthNative64: 24n,
    conservativeBtreeEntryStorageMultiplier: 16n,
    conservativeHeapAllocationOverheadByteLength: 64n,
    conservativeSingleAppendRecyclerCapacity: 4n,
    conservativeSingleOperationVectorCapacity: 4n,
    conservativeSingleReadResultVectorCapacity: 1n,
    proofChallengeExtensionElementByteLength: 40n,
    proofTreeCount: 7n,
    proofTreeValueByteLengthNative64: 48n,
    retainedAlgebraicCoefficientByteLength: 1_048_576n,
    releaseProfileIdentifier: 'release-desktop-browser-wasm-v1',
    representativeBrowserWidth: 512,
    ringDimension: 32_768,
    rosterSize: 10,
    sourceOpeningClaimCount: 9,
    traceRowCount: 16_384,
    widthInputIdentityHashDomain: 'proof-storage/public-source-input/v1',
    vectorHeaderByteLengthNative64: 24n,
} as const;

export const deriveProofStorageWidthExternalMemoryFramingGeometry =
    (): Readonly<{
        appendResponseDecodeWorkspaceByteLengthCeiling: bigint;
        appendRequestByteLengthCeiling: bigint;
        boundaryTransferLiveByteLengthCeiling: bigint;
        copiedBufferByteLengthCeiling: bigint;
        emptyResponseByteLength: bigint;
        rawAbiRequestCopyWorkspaceByteLengthCeiling: bigint;
        rawAbiResponseDecodeWorkspaceByteLengthCeiling: bigint;
        rawAbiTransferWorkspaceByteLengthCeiling: bigint;
        readRequestByteLength: bigint;
        readResponseDecodeWorkspaceByteLengthCeiling: bigint;
        readResponseByteLengthCeiling: bigint;
    }> => {
        const appendRequestByteLengthCeiling =
            proofStorageWidthProfile.externalMemoryRequestHeaderByteLength +
            proofStorageWidthProfile.externalMemoryOperationHeaderByteLength +
            proofStorageWidthProfile.externalMemoryChunkByteLength;
        const emptyResponseByteLength =
            proofStorageWidthProfile.externalMemoryResponseHeaderByteLength;
        const readRequestByteLength =
            proofStorageWidthProfile.externalMemoryRequestHeaderByteLength +
            proofStorageWidthProfile.externalMemoryOperationHeaderByteLength;
        const readResponseByteLengthCeiling =
            proofStorageWidthProfile.externalMemoryResponseHeaderByteLength +
            proofStorageWidthProfile.externalMemoryReadResultHeaderByteLength +
            proofStorageWidthProfile.externalMemoryChunkByteLength;
        const copiedBufferByteLengthCeiling =
            appendRequestByteLengthCeiling > readResponseByteLengthCeiling
                ? appendRequestByteLengthCeiling
                : readResponseByteLengthCeiling;
        const appendTransferLiveByteLength =
            appendRequestByteLengthCeiling + emptyResponseByteLength;
        const readTransferLiveByteLength =
            readRequestByteLength + readResponseByteLengthCeiling;
        const boundaryTransferLiveByteLengthCeiling =
            appendTransferLiveByteLength > readTransferLiveByteLength
                ? appendTransferLiveByteLength
                : readTransferLiveByteLength;
        const requestContainerByteLength =
            proofStorageWidthProfile.externalMemoryTransactionRequestByteLengthNative64;
        const operationVectorStorageByteLength =
            proofStorageWidthProfile.conservativeSingleOperationVectorCapacity *
            proofStorageWidthProfile.externalMemoryTransactionOperationByteLengthNative64;
        const vectorHeaderByteLength =
            proofStorageWidthProfile.vectorHeaderByteLengthNative64;
        const maximumEncodedAppendRequestByteLength =
            appendRequestByteLengthCeiling;
        const readResultVectorStorageByteLength =
            proofStorageWidthProfile.conservativeSingleReadResultVectorCapacity *
            vectorHeaderByteLength;
        const appendRecyclerVectorStorageByteLength =
            proofStorageWidthProfile.conservativeSingleAppendRecyclerCapacity *
            vectorHeaderByteLength;
        const requestCopyContainerByteLength =
            4n * vectorHeaderByteLength +
            vectorHeaderByteLength +
            readResultVectorStorageByteLength +
            vectorHeaderByteLength +
            appendRecyclerVectorStorageByteLength +
            requestContainerByteLength +
            operationVectorStorageByteLength;
        // At request copy after an earlier read, the append and read scratch,
        // request append, recycled read result, operation encoding, cached
        // request, and raw boundary allocations all coexist.
        const rawAbiRequestCopyPayloadByteLength =
            4n * proofStorageWidthProfile.externalMemoryChunkByteLength +
            proofStorageWidthProfile.externalMemoryChunkByteLength +
            proofStorageWidthProfile.externalMemoryOperationHeaderByteLength +
            2n * maximumEncodedAppendRequestByteLength;
        const rawAbiRequestCopyWorkspaceByteLengthCeiling =
            rawAbiRequestCopyPayloadByteLength +
            requestCopyContainerByteLength +
            10n *
                proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength;
        // Supplying the empty append response clears, but retains, the cached
        // request and fixed raw-ABI boundary capacities. The local empty
        // read-results Vec and the runtime's empty recycler both remain live.
        const appendResponseDecodeWorkspaceByteLengthCeiling =
            4n * proofStorageWidthProfile.externalMemoryChunkByteLength +
            proofStorageWidthProfile.externalMemoryChunkByteLength +
            proofStorageWidthProfile.externalMemoryOperationHeaderByteLength +
            2n * maximumEncodedAppendRequestByteLength +
            requestCopyContainerByteLength +
            vectorHeaderByteLength +
            10n *
                proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength;
        // A full read response after an append retains the append recycler
        // outer backing and payload while the decoded read result is filled.
        const readResponseDecodeWorkspaceByteLengthCeiling =
            4n * proofStorageWidthProfile.externalMemoryChunkByteLength +
            proofStorageWidthProfile.externalMemoryChunkByteLength +
            proofStorageWidthProfile.externalMemoryOperationHeaderByteLength +
            2n * maximumEncodedAppendRequestByteLength +
            4n * vectorHeaderByteLength +
            vectorHeaderByteLength +
            appendRecyclerVectorStorageByteLength +
            vectorHeaderByteLength +
            vectorHeaderByteLength +
            readResultVectorStorageByteLength +
            requestContainerByteLength +
            operationVectorStorageByteLength +
            10n *
                proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength;
        const rawAbiResponseDecodeWorkspaceByteLengthCeiling =
            appendResponseDecodeWorkspaceByteLengthCeiling >
            readResponseDecodeWorkspaceByteLengthCeiling
                ? appendResponseDecodeWorkspaceByteLengthCeiling
                : readResponseDecodeWorkspaceByteLengthCeiling;
        const rawAbiTransferWorkspaceByteLengthCeiling =
            rawAbiRequestCopyWorkspaceByteLengthCeiling >
            rawAbiResponseDecodeWorkspaceByteLengthCeiling
                ? rawAbiRequestCopyWorkspaceByteLengthCeiling
                : rawAbiResponseDecodeWorkspaceByteLengthCeiling;
        return {
            appendResponseDecodeWorkspaceByteLengthCeiling,
            appendRequestByteLengthCeiling,
            boundaryTransferLiveByteLengthCeiling,
            copiedBufferByteLengthCeiling,
            emptyResponseByteLength,
            rawAbiRequestCopyWorkspaceByteLengthCeiling,
            rawAbiResponseDecodeWorkspaceByteLengthCeiling,
            rawAbiTransferWorkspaceByteLengthCeiling,
            readRequestByteLength,
            readResponseDecodeWorkspaceByteLengthCeiling,
            readResponseByteLengthCeiling,
        };
    };

export const deriveProofStorageWidthOpeningWorkspaceGeometry = (
    width: ProofStorageWidth,
): Readonly<{
    freshVerifierOuterVectorContainerByteLengthCeiling: bigint;
    freshVerifierPublicOpeningWorkspaceByteLengthCeiling: bigint;
    proverPublicOpeningWorkspaceByteLengthCeiling: bigint;
}> => {
    const widthValue = BigInt(width);
    const queryCount = proofStorageWidthProfile.queryRepresentativeCount;
    const proverAllocationCount = 2n * (queryCount + 1n);
    const proverPublicOpeningWorkspaceByteLengthCeiling =
        2n *
            queryCount *
            widthValue *
            proofStorageWidthProfile.proofTreeValueByteLengthNative64 +
        proverAllocationCount *
            proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
        proverAllocationCount *
            proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength;
    const authenticatedMapCount = proofStorageWidthProfile.proofTreeCount + 1n;
    const authenticatedMapEntryCount = queryCount * authenticatedMapCount;
    const freshVerifierExtensionElementCount =
        queryCount *
        (4n * widthValue + 2n * (proofStorageWidthProfile.proofTreeCount - 1n));
    const freshVerifierPublicOpeningWorkspaceByteLengthCeiling =
        freshVerifierExtensionElementCount *
            proofStorageWidthProfile.proofChallengeExtensionElementByteLength +
        authenticatedMapEntryCount *
            proofStorageWidthProfile.conservativeBtreeEntryStorageMultiplier *
            proofStorageWidthProfile.authenticatedMapEntryByteLengthNative64 +
        authenticatedMapCount *
            proofStorageWidthProfile.btreeMapHeaderByteLengthNative64 +
        proofStorageWidthProfile.proofTreeCount *
            proofStorageWidthProfile.authenticatedTreeOpeningHeaderByteLengthNative64 +
        (3n * authenticatedMapEntryCount + 1n) *
            proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength;
    const freshVerifierOuterVectorContainerByteLengthCeiling =
        2n * proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
        2n *
            queryCount *
            proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
        2n *
            proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength;
    return {
        freshVerifierOuterVectorContainerByteLengthCeiling,
        freshVerifierPublicOpeningWorkspaceByteLengthCeiling,
        proverPublicOpeningWorkspaceByteLengthCeiling,
    };
};

export const deriveProofStorageWidthNativeCustodyMetadataByteLengthCeiling = (
    width: ProofStorageWidth,
): bigint => {
    const pathCount = BigInt(width) + 2n;
    return (
        pathCount *
            (proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
                BigInt(
                    proofStorageWidthProfile.maximumNativeCustodyPathByteLength,
                ) +
                proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength) +
        proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
        proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength
    );
};

export const deriveProofStorageWidthGeometry = (
    width: ProofStorageWidth,
): Readonly<{
    absorbedLeafValueCount: bigint;
    activeColumnLdeScratchByteLength: bigint;
    ldeTransformCount: bigint;
    legacyBaseLeafObjectByteLength: bigint;
    localRecordSealInvocationCount: 0n;
    openedLeafElementByteLength: bigint;
    openedLeafRangeChunkCount: bigint;
    openedValueCount: bigint;
    physicalObjectPeak: bigint;
    proofObjectSealTransactionCount: 1n;
    publicBaseLeafByteLength: bigint;
    queriedLeafPayloadByteLength: bigint;
    sealedSecretPlaintextByteLength: 0n;
    sourceReplayByteLength: bigint;
    sourceObjectSealTransactionCount: bigint;
    widthDependentQueriedBaseOpeningByteLength: bigint;
}> => {
    const widthValue = BigInt(width);
    const publicBaseLeafByteLength = 124n + 16n * widthValue;
    const queriedLeafPayloadByteLength =
        proofStorageWidthProfile.queryRepresentativeCount *
        publicBaseLeafByteLength;
    const chunksPerOpenedLeaf =
        (publicBaseLeafByteLength +
            4n +
            proofStorageWidthProfile.externalMemoryChunkByteLength -
            1n) /
        proofStorageWidthProfile.externalMemoryChunkByteLength;
    const sourceReplayByteLength = 131_072n * widthValue;

    return {
        absorbedLeafValueCount: 393_216n * widthValue,
        activeColumnLdeScratchByteLength:
            proofStorageWidthProfile.activeColumnLdeScratchByteLength,
        ldeTransformCount: 6n * widthValue,
        legacyBaseLeafObjectByteLength:
            proofStorageWidthProfile.legacyBaseLeafCount *
            publicBaseLeafByteLength,
        localRecordSealInvocationCount: 0n,
        openedLeafElementByteLength: publicBaseLeafByteLength + 4n,
        sealedSecretPlaintextByteLength: 0n,
        openedLeafRangeChunkCount:
            proofStorageWidthProfile.queryRepresentativeCount *
            chunksPerOpenedLeaf,
        openedValueCount:
            2n * proofStorageWidthProfile.queryRepresentativeCount * widthValue,
        physicalObjectPeak: widthValue + 1n,
        proofObjectSealTransactionCount: 1n,
        publicBaseLeafByteLength,
        queriedLeafPayloadByteLength,
        sourceReplayByteLength,
        sourceObjectSealTransactionCount: widthValue,
        widthDependentQueriedBaseOpeningByteLength:
            proofStorageWidthProfile.queryRepresentativeCount *
            16n *
            widthValue,
    };
};

type JsonObject = Readonly<Record<string, unknown>>;

const requireJsonObject = (value: unknown, fieldName: string): JsonObject => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} must be a JSON object.`);
    }
    return value as JsonObject;
};

const parseCanonicalUnsigned64Decimal = (
    value: unknown,
    fieldName: string,
): bigint => {
    if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
        throw new Error(`${fieldName} must be a canonical decimal u64 string.`);
    }
    const parsed = BigInt(value);
    if (parsed > maximumUnsigned64) {
        throw new Error(`${fieldName} exceeds u64.`);
    }
    return parsed;
};

const parseGuardUnsigned64 = (value: unknown, fieldName: string): bigint => {
    if (typeof value === 'string') {
        return parseCanonicalUnsigned64Decimal(value, fieldName);
    }
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new Error(
            `${fieldName} must be a safe unsigned JSON integer or canonical decimal u64 string.`,
        );
    }
    return BigInt(value);
};

const requireExactNumber = (
    value: unknown,
    expected: number,
    fieldName: string,
): number => {
    if (value !== expected) {
        throw new Error(`${fieldName} must be ${expected}.`);
    }
    return expected;
};

const requireExactString = (
    value: unknown,
    expected: string,
    fieldName: string,
): string => {
    if (value !== expected) {
        throw new Error(`${fieldName} must be ${expected}.`);
    }
    return expected;
};

const requireHash512Hex = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !hash512HexPattern.test(value)) {
        throw new Error(
            `${fieldName} must be a lowercase 64-byte hexadecimal digest.`,
        );
    }
    return value;
};

const requireExpectedUnsigned64 = (
    actual: bigint,
    expected: bigint,
    fieldName: string,
): void => {
    if (actual !== expected) {
        throw new Error(
            `${fieldName} must be ${expected.toString()}, but received ${actual.toString()}.`,
        );
    }
};

const checkedAddUnsigned64 = (
    left: bigint,
    right: bigint,
    fieldName: string,
): bigint => {
    const sum = left + right;
    if (sum > maximumUnsigned64) {
        throw new Error(`${fieldName} exceeds u64.`);
    }
    return sum;
};

const requirePositiveUnsigned64 = (value: bigint, fieldName: string): void => {
    if (value === 0n) {
        throw new Error(`${fieldName} must be positive.`);
    }
};

export type ProofStorageWidthProfileBinding = Readonly<{
    absoluteCapTableIdentifier: string;
    backendProfileIdentifier: string;
    custodyModel: 'bounded-external-storage-replay';
    custodySchemaIdentifier: string;
    custodySchemaVersion: 1;
    evaluationDomainSize: 131_072;
    frozenInputIdentityHashDomain: string;
    frozenInputIdentityShake256Hex: string;
    frozenInputRecipeIdentifier: string;
    intendedReleaseRuntime: 'desktop-browser-wasm';
    measurementRuntime: 'native-rust';
    maximumNativeCustodyPathByteLength: 1_024;
    publicColumnDerivationAlgorithm: string;
    publicColumnInputDomain: string;
    publicColumnSeedHex: string;
    releaseProfileIdentifier: string;
    representativeBrowserWidth: 512;
    traceRowCount: 16_384;
    widthInputIdentityHashDomain: string;
}>;

const validateProofStorageWidthProfileBinding = (
    record: JsonObject,
): ProofStorageWidthProfileBinding => {
    if (record.custodyModel !== 'bounded-external-storage-replay') {
        throw new Error(
            'custodyModel must be bounded-external-storage-replay for every width.',
        );
    }
    return {
        absoluteCapTableIdentifier: requireExactString(
            record.absoluteCapTableIdentifier,
            proofStorageWidthProfile.absoluteCapTableIdentifier,
            'absoluteCapTableIdentifier',
        ),
        backendProfileIdentifier: requireExactString(
            record.backendProfileIdentifier,
            proofStorageWidthProfile.backendProfileIdentifier,
            'backendProfileIdentifier',
        ),
        custodyModel: 'bounded-external-storage-replay',
        custodySchemaIdentifier: requireExactString(
            record.custodySchemaIdentifier,
            proofStorageWidthProfile.custodySchemaIdentifier,
            'custodySchemaIdentifier',
        ),
        custodySchemaVersion: requireExactNumber(
            record.custodySchemaVersion,
            proofStorageWidthProfile.custodySchemaVersion,
            'custodySchemaVersion',
        ) as 1,
        evaluationDomainSize: requireExactNumber(
            record.evaluationDomainSize,
            proofStorageWidthProfile.evaluationDomainSize,
            'evaluationDomainSize',
        ) as 131_072,
        frozenInputIdentityHashDomain: requireExactString(
            record.frozenInputIdentityHashDomain,
            proofStorageWidthProfile.frozenInputIdentityHashDomain,
            'frozenInputIdentityHashDomain',
        ),
        frozenInputIdentityShake256Hex: requireExactString(
            record.frozenInputIdentityShake256Hex,
            proofStorageWidthProfile.frozenInputIdentityShake256Hex,
            'frozenInputIdentityShake256Hex',
        ),
        frozenInputRecipeIdentifier: requireExactString(
            record.frozenInputRecipeIdentifier,
            proofStorageWidthProfile.frozenInputRecipeIdentifier,
            'frozenInputRecipeIdentifier',
        ),
        intendedReleaseRuntime: requireExactString(
            record.intendedReleaseRuntime,
            proofStorageWidthProfile.intendedReleaseRuntime,
            'intendedReleaseRuntime',
        ) as 'desktop-browser-wasm',
        measurementRuntime: requireExactString(
            record.measurementRuntime,
            proofStorageWidthProfile.measurementRuntime,
            'measurementRuntime',
        ) as 'native-rust',
        maximumNativeCustodyPathByteLength: requireExactNumber(
            record.maximumNativeCustodyPathByteLength,
            proofStorageWidthProfile.maximumNativeCustodyPathByteLength,
            'maximumNativeCustodyPathByteLength',
        ) as 1_024,
        publicColumnDerivationAlgorithm: requireExactString(
            record.publicColumnDerivationAlgorithm,
            proofStorageWidthProfile.publicColumnDerivationAlgorithm,
            'publicColumnDerivationAlgorithm',
        ),
        publicColumnInputDomain: requireExactString(
            record.publicColumnInputDomain,
            proofStorageWidthProfile.publicColumnInputDomain,
            'publicColumnInputDomain',
        ),
        publicColumnSeedHex: requireExactString(
            record.publicColumnSeedHex,
            proofStorageWidthProfile.publicColumnSeedHex,
            'publicColumnSeedHex',
        ),
        releaseProfileIdentifier: requireExactString(
            record.releaseProfileIdentifier,
            proofStorageWidthProfile.releaseProfileIdentifier,
            'releaseProfileIdentifier',
        ),
        representativeBrowserWidth: requireExactNumber(
            record.representativeBrowserWidth,
            proofStorageWidthProfile.representativeBrowserWidth,
            'representativeBrowserWidth',
        ) as 512,
        traceRowCount: requireExactNumber(
            record.traceRowCount,
            proofStorageWidthProfile.traceRowCount,
            'traceRowCount',
        ) as 16_384,
        widthInputIdentityHashDomain: requireExactString(
            record.widthInputIdentityHashDomain,
            proofStorageWidthProfile.widthInputIdentityHashDomain,
            'widthInputIdentityHashDomain',
        ),
    };
};

export type ValidatedProofStorageWidthStaticPreflightPoint = Readonly<{
    absorbedLeafValueCount: bigint;
    activeColumnLdeScratchByteLength: bigint;
    baseLeafObjectReadByteLength: bigint;
    baseLeafObjectWrittenByteLength: bigint;
    boundaryTransferByteLengthCeiling: bigint;
    browserOperationRegistryByteLengthCeiling: bigint;
    canonicalArtifactContainerByteLengthCeiling: bigint;
    canonicalArtifactLiveCopyByteLengthCeiling: bigint;
    canonicalArtifactNonleafRangeChunkCountCeiling: bigint;
    canonicalProofByteLengthCeiling: bigint;
    committedTransactionCountCeiling: bigint;
    copiedBufferByteLengthCeiling: bigint;
    digestStateByteLengthCeiling: bigint;
    digestStateContainerByteLengthCeiling: bigint;
    externalIoByteLengthCeiling: bigint;
    externalReadByteLengthCeiling: bigint;
    externalWrittenByteLengthCeiling: bigint;
    extensionDomainWorkingByteLengthCeiling: bigint;
    freshVerifierPublicOpeningWorkspaceByteLengthCeiling: bigint;
    freshVerifierOuterVectorContainerByteLengthCeiling: bigint;
    frozenFixtureAndContainerByteLengthCeiling: bigint;
    inputIdentityShake256Hex: string;
    ldeTransformCount: bigint;
    legacyBaseLeafObjectByteLength: bigint;
    localRecordSealInvocationCount: bigint;
    maximumTransactionPayloadByteLength: bigint;
    openedLeafElementByteLength: bigint;
    openedLeafRangeChunkCount: bigint;
    openedValueCount: bigint;
    openingArtifactAndTranscriptByteLengthCeiling: bigint;
    persistedLdeByteLength: bigint;
    physicalObjectPeak: bigint;
    proofObjectSealTransactionCount: bigint;
    proofPhysicalObjectCount: bigint;
    proverPublicOpeningWorkspaceByteLengthCeiling: bigint;
    publicBaseLeafByteLength: bigint;
    publicBaseLeafColumnCount: ProofStorageWidth;
    queriedLeafPayloadByteLength: bigint;
    retainedAlgebraicCoefficientByteLengthCeiling: bigint;
    rawAbiRequestCopyWorkspaceByteLengthCeiling: bigint;
    rawAbiResponseDecodeWorkspaceByteLengthCeiling: bigint;
    rawAbiTransferWorkspaceByteLengthCeiling: bigint;
    sealedSecretPlaintextByteLength: 0n;
    sourceCommittedTransactionCount: bigint;
    sourceObjectSealTransactionCount: bigint;
    sourcePhysicalObjectCount: bigint;
    sourceReplayByteLength: bigint;
    storedScratchPeakByteLengthCeiling: bigint;
    nativeCustodyMetadataByteLengthCeiling: bigint;
    transportByteLengthCeiling: bigint;
    wasmMemoryByteLengthCeiling: bigint;
    widthDependentQueriedBaseOpeningByteLength: bigint;
}>;

export type ValidatedProofStorageWidthStaticPreflight = Readonly<{
    absoluteCaps: typeof proofStorageWidthProfile;
    points: readonly ValidatedProofStorageWidthStaticPreflightPoint[];
    profile: ProofStorageWidthProfileBinding;
}>;

const staticPreflightCapFields = [
    ['maximumCommonProofByteLengthDecimal', 'maximumCommonProofByteLength'],
    ['maximumCopiedBufferByteLengthDecimal', 'maximumCopiedBufferByteLength'],
    [
        'maximumLocalRecordSealInvocationCountDecimal',
        'maximumLocalRecordSealInvocationCount',
    ],
    [
        'maximumLocalRecordSealedPlaintextByteLengthDecimal',
        'maximumLocalRecordSealedPlaintextByteLength',
    ],
    ['maximumPhysicalObjectCountDecimal', 'maximumPhysicalObjectCount'],
    ['maximumStoredScratchByteLengthDecimal', 'maximumStoredScratchByteLength'],
    ['maximumTransportByteLengthDecimal', 'maximumTransportByteLength'],
    ['maximumWasmMemoryByteLengthDecimal', 'maximumWasmMemoryByteLength'],
] as const;

export const validateProofStorageWidthStaticPreflightResult = (
    input: unknown,
): ValidatedProofStorageWidthStaticPreflight => {
    const record = requireJsonObject(
        input,
        'Proof-storage width static preflight',
    );
    requireExactNumber(record.formatVersion, 1, 'formatVersion');
    const profile = validateProofStorageWidthProfileBinding(record);
    const exactCandidate = requireJsonObject(
        record.exactCandidate,
        'exactCandidate',
    );
    requireExactNumber(
        exactCandidate.rosterSize,
        proofStorageWidthProfile.rosterSize,
        'exactCandidate.rosterSize',
    );
    requireExactNumber(
        exactCandidate.ringDimension,
        proofStorageWidthProfile.ringDimension,
        'exactCandidate.ringDimension',
    );
    requireExactNumber(
        exactCandidate.plaintextModulus,
        proofStorageWidthProfile.plaintextModulus,
        'exactCandidate.plaintextModulus',
    );
    requireExactNumber(
        exactCandidate.firstDataModulus,
        proofStorageWidthProfile.firstDataModulus,
        'exactCandidate.firstDataModulus',
    );
    requireExactNumber(
        exactCandidate.materialRadix,
        proofStorageWidthProfile.materialRadix,
        'exactCandidate.materialRadix',
    );
    requireExactNumber(
        record.algebraicBaseColumnCount,
        proofStorageWidthProfile.algebraicBaseColumnCount,
        'algebraicBaseColumnCount',
    );
    requireExactNumber(
        record.sourceOpeningClaimCount,
        proofStorageWidthProfile.sourceOpeningClaimCount,
        'sourceOpeningClaimCount',
    );
    requireExactNumber(
        record.batchingFunctionCount,
        proofStorageWidthProfile.batchingFunctionCount,
        'batchingFunctionCount',
    );
    if (
        !Array.isArray(record.widths) ||
        record.widths.length !== proofStorageWidthSchedule.length ||
        record.widths.some(
            (width, index) => width !== proofStorageWidthSchedule[index],
        )
    ) {
        throw new Error(
            'The static preflight widths must equal the exact precommitted schedule.',
        );
    }
    const capRecord = requireJsonObject(record.absoluteCaps, 'absoluteCaps');
    for (const [
        serializedFieldName,
        profileFieldName,
    ] of staticPreflightCapFields) {
        requireExpectedUnsigned64(
            parseCanonicalUnsigned64Decimal(
                capRecord[serializedFieldName],
                `absoluteCaps.${serializedFieldName}`,
            ),
            proofStorageWidthProfile[profileFieldName],
            `absoluteCaps.${serializedFieldName}`,
        );
    }
    if (
        !Array.isArray(record.points) ||
        record.points.length !== proofStorageWidthSchedule.length
    ) {
        throw new Error(
            `The static preflight must contain exactly ${proofStorageWidthSchedule.length} points.`,
        );
    }
    const externalMemoryFramingGeometry =
        deriveProofStorageWidthExternalMemoryFramingGeometry();
    const externalMemoryFramingProfileChecks = [
        [
            proofStorageWidthProfile.externalMemoryAppendRequestByteLengthCeiling,
            externalMemoryFramingGeometry.appendRequestByteLengthCeiling,
            'proofStorageWidthProfile.externalMemoryAppendRequestByteLengthCeiling',
        ],
        [
            proofStorageWidthProfile.externalMemoryEmptyResponseByteLength,
            externalMemoryFramingGeometry.emptyResponseByteLength,
            'proofStorageWidthProfile.externalMemoryEmptyResponseByteLength',
        ],
        [
            proofStorageWidthProfile.externalMemoryReadRequestByteLength,
            externalMemoryFramingGeometry.readRequestByteLength,
            'proofStorageWidthProfile.externalMemoryReadRequestByteLength',
        ],
        [
            proofStorageWidthProfile.externalMemoryReadResponseByteLengthCeiling,
            externalMemoryFramingGeometry.readResponseByteLengthCeiling,
            'proofStorageWidthProfile.externalMemoryReadResponseByteLengthCeiling',
        ],
        [
            proofStorageWidthProfile.externalMemoryCopiedBufferByteLengthCeiling,
            externalMemoryFramingGeometry.copiedBufferByteLengthCeiling,
            'proofStorageWidthProfile.externalMemoryCopiedBufferByteLengthCeiling',
        ],
        [
            proofStorageWidthProfile.externalMemoryBoundaryTransferLiveByteLengthCeiling,
            externalMemoryFramingGeometry.boundaryTransferLiveByteLengthCeiling,
            'proofStorageWidthProfile.externalMemoryBoundaryTransferLiveByteLengthCeiling',
        ],
    ] as const;
    for (const [
        profileValue,
        derivedValue,
        fieldName,
    ] of externalMemoryFramingProfileChecks) {
        requireExpectedUnsigned64(profileValue, derivedValue, fieldName);
    }

    const points = record.points.map((pointInput, pointIndex) => {
        const point = requireJsonObject(pointInput, `points[${pointIndex}]`);
        const width = proofStorageWidthSchedule[pointIndex];
        if (width === undefined || point.publicBaseLeafColumnCount !== width) {
            throw new Error(
                `points[${pointIndex}].publicBaseLeafColumnCount must preserve the exact schedule.`,
            );
        }
        const geometry = deriveProofStorageWidthGeometry(width);
        const parsePointValue = (fieldName: string): bigint =>
            parseCanonicalUnsigned64Decimal(
                point[`${fieldName}Decimal`],
                `points[${pointIndex}].${fieldName}Decimal`,
            );
        const requireGeometryValue = (
            fieldName: string,
            expected: bigint,
        ): bigint => {
            const value = parsePointValue(fieldName);
            requireExpectedUnsigned64(
                value,
                expected,
                `points[${pointIndex}].${fieldName}Decimal`,
            );
            return value;
        };
        const sourceReplayByteLength = requireGeometryValue(
            'sourceReplayByteLength',
            geometry.sourceReplayByteLength,
        );
        const publicBaseLeafByteLength = requireGeometryValue(
            'publicBaseLeafByteLength',
            geometry.publicBaseLeafByteLength,
        );
        const queriedLeafPayloadByteLength = requireGeometryValue(
            'queriedLeafPayloadByteLength',
            geometry.queriedLeafPayloadByteLength,
        );
        const openedLeafElementByteLength = requireGeometryValue(
            'openedLeafElementByteLength',
            geometry.openedLeafElementByteLength,
        );
        const legacyBaseLeafObjectByteLength = requireGeometryValue(
            'legacyBaseLeafObjectByteLength',
            geometry.legacyBaseLeafObjectByteLength,
        );
        const widthDependentQueriedBaseOpeningByteLength = requireGeometryValue(
            'widthDependentQueriedBaseOpeningByteLength',
            geometry.widthDependentQueriedBaseOpeningByteLength,
        );
        const openedLeafRangeChunkCount = requireGeometryValue(
            'openedLeafRangeChunkCount',
            geometry.openedLeafRangeChunkCount,
        );
        const physicalObjectPeak = requireGeometryValue(
            'physicalObjectPeak',
            geometry.physicalObjectPeak,
        );
        const sourcePhysicalObjectCount = requireGeometryValue(
            'sourcePhysicalObjectCount',
            BigInt(width),
        );
        const proofPhysicalObjectCount = requireGeometryValue(
            'proofPhysicalObjectCount',
            1n,
        );
        const sourceObjectSealTransactionCount = requireGeometryValue(
            'sourceObjectSealTransactionCount',
            geometry.sourceObjectSealTransactionCount,
        );
        const proofObjectSealTransactionCount = requireGeometryValue(
            'proofObjectSealTransactionCount',
            geometry.proofObjectSealTransactionCount,
        );
        const sourceCommittedTransactionCount = requireGeometryValue(
            'sourceCommittedTransactionCount',
            24n * BigInt(width),
        );
        const localRecordSealInvocationCount = requireGeometryValue(
            'localRecordSealInvocationCount',
            geometry.localRecordSealInvocationCount,
        );
        const sealedSecretPlaintextByteLength = requireGeometryValue(
            'sealedSecretPlaintextByteLength',
            0n,
        );
        const activeColumnLdeScratchByteLength = requireGeometryValue(
            'activeColumnLdeScratchByteLength',
            geometry.activeColumnLdeScratchByteLength,
        );
        const persistedLdeByteLength = requireGeometryValue(
            'persistedLdeByteLength',
            0n,
        );
        const baseLeafObjectReadByteLength = requireGeometryValue(
            'baseLeafObjectReadByteLength',
            0n,
        );
        const baseLeafObjectWrittenByteLength = requireGeometryValue(
            'baseLeafObjectWrittenByteLength',
            0n,
        );
        const ldeTransformCount = requireGeometryValue(
            'ldeTransformCount',
            geometry.ldeTransformCount,
        );
        const absorbedLeafValueCount = requireGeometryValue(
            'absorbedLeafValueCount',
            geometry.absorbedLeafValueCount,
        );
        const openedValueCount = requireGeometryValue(
            'openedValueCount',
            geometry.openedValueCount,
        );
        const maximumTransactionPayloadByteLength = requireGeometryValue(
            'maximumTransactionPayloadByteLength',
            proofStorageWidthProfile.externalMemoryChunkByteLength,
        );
        const canonicalProofByteLengthCeiling = parsePointValue(
            'canonicalProofByteLengthCeiling',
        );
        const canonicalArtifactNonleafRangeChunkCountCeiling = parsePointValue(
            'canonicalArtifactNonleafRangeChunkCountCeiling',
        );
        const transportByteLengthCeiling = parsePointValue(
            'transportByteLengthCeiling',
        );
        const storedScratchPeakByteLengthCeiling = parsePointValue(
            'storedScratchPeakByteLengthCeiling',
        );
        const externalReadByteLengthCeiling = parsePointValue(
            'externalReadByteLengthCeiling',
        );
        const externalWrittenByteLengthCeiling = parsePointValue(
            'externalWrittenByteLengthCeiling',
        );
        const externalIoByteLengthCeiling = parsePointValue(
            'externalIoByteLengthCeiling',
        );
        const committedTransactionCountCeiling = parsePointValue(
            'committedTransactionCountCeiling',
        );
        const copiedBufferByteLengthCeiling = parsePointValue(
            'copiedBufferByteLengthCeiling',
        );
        const digestStateByteLengthCeiling = parsePointValue(
            'digestStateByteLengthCeiling',
        );
        const digestStateContainerByteLengthCeiling = parsePointValue(
            'digestStateContainerByteLengthCeiling',
        );
        const frozenFixtureAndContainerByteLengthCeiling = parsePointValue(
            'frozenFixtureAndContainerByteLengthCeiling',
        );
        const retainedAlgebraicCoefficientByteLengthCeiling = parsePointValue(
            'retainedAlgebraicCoefficientByteLengthCeiling',
        );
        const extensionDomainWorkingByteLengthCeiling = parsePointValue(
            'extensionDomainWorkingByteLengthCeiling',
        );
        const proverPublicOpeningWorkspaceByteLengthCeiling = parsePointValue(
            'proverPublicOpeningWorkspaceByteLengthCeiling',
        );
        const freshVerifierPublicOpeningWorkspaceByteLengthCeiling =
            parsePointValue(
                'freshVerifierPublicOpeningWorkspaceByteLengthCeiling',
            );
        const freshVerifierOuterVectorContainerByteLengthCeiling =
            parsePointValue(
                'freshVerifierOuterVectorContainerByteLengthCeiling',
            );
        const canonicalArtifactLiveCopyByteLengthCeiling = parsePointValue(
            'canonicalArtifactLiveCopyByteLengthCeiling',
        );
        const canonicalArtifactContainerByteLengthCeiling = parsePointValue(
            'canonicalArtifactContainerByteLengthCeiling',
        );
        const openingArtifactAndTranscriptByteLengthCeiling = parsePointValue(
            'openingArtifactAndTranscriptByteLengthCeiling',
        );
        const boundaryTransferByteLengthCeiling = parsePointValue(
            'boundaryTransferByteLengthCeiling',
        );
        const rawAbiRequestCopyWorkspaceByteLengthCeiling = parsePointValue(
            'rawAbiRequestCopyWorkspaceByteLengthCeiling',
        );
        const rawAbiResponseDecodeWorkspaceByteLengthCeiling = parsePointValue(
            'rawAbiResponseDecodeWorkspaceByteLengthCeiling',
        );
        const rawAbiTransferWorkspaceByteLengthCeiling = parsePointValue(
            'rawAbiTransferWorkspaceByteLengthCeiling',
        );
        const browserOperationRegistryByteLengthCeiling = parsePointValue(
            'browserOperationRegistryByteLengthCeiling',
        );
        const nativeCustodyMetadataByteLengthCeiling = parsePointValue(
            'nativeCustodyMetadataByteLengthCeiling',
        );
        const wasmMemoryByteLengthCeiling = parsePointValue(
            'wasmMemoryByteLengthCeiling',
        );
        const inputIdentityShake256Hex = requireHash512Hex(
            point.inputIdentityShake256Hex,
            `points[${pointIndex}].inputIdentityShake256Hex`,
        );
        requirePositiveUnsigned64(
            canonicalProofByteLengthCeiling,
            `points[${pointIndex}].canonicalProofByteLengthCeilingDecimal`,
        );
        requirePositiveUnsigned64(
            canonicalArtifactNonleafRangeChunkCountCeiling,
            `points[${pointIndex}].canonicalArtifactNonleafRangeChunkCountCeilingDecimal`,
        );
        requirePositiveUnsigned64(
            digestStateByteLengthCeiling,
            `points[${pointIndex}].digestStateByteLengthCeilingDecimal`,
        );
        requirePositiveUnsigned64(
            browserOperationRegistryByteLengthCeiling,
            `points[${pointIndex}].browserOperationRegistryByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            canonicalArtifactNonleafRangeChunkCountCeiling,
            (canonicalProofByteLengthCeiling +
                proofStorageWidthProfile.externalMemoryChunkByteLength -
                1n) /
                proofStorageWidthProfile.externalMemoryChunkByteLength +
                1n,
            `points[${pointIndex}].canonicalArtifactNonleafRangeChunkCountCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            storedScratchPeakByteLengthCeiling,
            checkedAddUnsigned64(
                sourceReplayByteLength,
                canonicalProofByteLengthCeiling,
                `points[${pointIndex}].storedScratchPeakByteLengthCeilingDecimal`,
            ),
            `points[${pointIndex}].storedScratchPeakByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            externalReadByteLengthCeiling,
            6n * sourceReplayByteLength + canonicalProofByteLengthCeiling,
            `points[${pointIndex}].externalReadByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            externalWrittenByteLengthCeiling,
            sourceReplayByteLength + canonicalProofByteLengthCeiling,
            `points[${pointIndex}].externalWrittenByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            externalIoByteLengthCeiling,
            externalReadByteLengthCeiling + externalWrittenByteLengthCeiling,
            `points[${pointIndex}].externalIoByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            committedTransactionCountCeiling,
            sourceCommittedTransactionCount +
                3n +
                2n *
                    (openedLeafRangeChunkCount +
                        canonicalArtifactNonleafRangeChunkCountCeiling),
            `points[${pointIndex}].committedTransactionCountCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            transportByteLengthCeiling,
            canonicalProofByteLengthCeiling,
            `points[${pointIndex}].transportByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            copiedBufferByteLengthCeiling,
            externalMemoryFramingGeometry.copiedBufferByteLengthCeiling,
            `points[${pointIndex}].copiedBufferByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            retainedAlgebraicCoefficientByteLengthCeiling,
            proofStorageWidthProfile.retainedAlgebraicCoefficientByteLength,
            `points[${pointIndex}].retainedAlgebraicCoefficientByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            extensionDomainWorkingByteLengthCeiling,
            proofStorageWidthProfile.extensionDomainWorkingByteLength,
            `points[${pointIndex}].extensionDomainWorkingByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            canonicalArtifactLiveCopyByteLengthCeiling,
            2n * canonicalProofByteLengthCeiling,
            `points[${pointIndex}].canonicalArtifactLiveCopyByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            openingArtifactAndTranscriptByteLengthCeiling,
            canonicalProofByteLengthCeiling,
            `points[${pointIndex}].openingArtifactAndTranscriptByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            boundaryTransferByteLengthCeiling,
            externalMemoryFramingGeometry.boundaryTransferLiveByteLengthCeiling,
            `points[${pointIndex}].boundaryTransferByteLengthCeilingDecimal`,
        );
        const openingWorkspaceGeometry =
            deriveProofStorageWidthOpeningWorkspaceGeometry(width);
        const canonicalArtifactContainerByteLengthCeilingExpected =
            3n *
            (proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
                proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength);
        requireExpectedUnsigned64(
            digestStateContainerByteLengthCeiling,
            proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
                proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength,
            `points[${pointIndex}].digestStateContainerByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            canonicalArtifactContainerByteLengthCeiling,
            canonicalArtifactContainerByteLengthCeilingExpected,
            `points[${pointIndex}].canonicalArtifactContainerByteLengthCeilingDecimal`,
        );
        requirePositiveUnsigned64(
            frozenFixtureAndContainerByteLengthCeiling,
            `points[${pointIndex}].frozenFixtureAndContainerByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            proverPublicOpeningWorkspaceByteLengthCeiling,
            openingWorkspaceGeometry.proverPublicOpeningWorkspaceByteLengthCeiling,
            `points[${pointIndex}].proverPublicOpeningWorkspaceByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            freshVerifierPublicOpeningWorkspaceByteLengthCeiling,
            openingWorkspaceGeometry.freshVerifierPublicOpeningWorkspaceByteLengthCeiling,
            `points[${pointIndex}].freshVerifierPublicOpeningWorkspaceByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            freshVerifierOuterVectorContainerByteLengthCeiling,
            openingWorkspaceGeometry.freshVerifierOuterVectorContainerByteLengthCeiling,
            `points[${pointIndex}].freshVerifierOuterVectorContainerByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            rawAbiRequestCopyWorkspaceByteLengthCeiling,
            externalMemoryFramingGeometry.rawAbiRequestCopyWorkspaceByteLengthCeiling,
            `points[${pointIndex}].rawAbiRequestCopyWorkspaceByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            rawAbiResponseDecodeWorkspaceByteLengthCeiling,
            externalMemoryFramingGeometry.rawAbiResponseDecodeWorkspaceByteLengthCeiling,
            `points[${pointIndex}].rawAbiResponseDecodeWorkspaceByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            rawAbiTransferWorkspaceByteLengthCeiling,
            externalMemoryFramingGeometry.rawAbiTransferWorkspaceByteLengthCeiling,
            `points[${pointIndex}].rawAbiTransferWorkspaceByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            nativeCustodyMetadataByteLengthCeiling,
            deriveProofStorageWidthNativeCustodyMetadataByteLengthCeiling(
                width,
            ),
            `points[${pointIndex}].nativeCustodyMetadataByteLengthCeilingDecimal`,
        );
        requireExpectedUnsigned64(
            wasmMemoryByteLengthCeiling,
            digestStateByteLengthCeiling +
                digestStateContainerByteLengthCeiling +
                frozenFixtureAndContainerByteLengthCeiling +
                activeColumnLdeScratchByteLength +
                retainedAlgebraicCoefficientByteLengthCeiling +
                extensionDomainWorkingByteLengthCeiling +
                canonicalArtifactLiveCopyByteLengthCeiling +
                canonicalArtifactContainerByteLengthCeiling +
                openingArtifactAndTranscriptByteLengthCeiling +
                proverPublicOpeningWorkspaceByteLengthCeiling +
                freshVerifierPublicOpeningWorkspaceByteLengthCeiling +
                freshVerifierOuterVectorContainerByteLengthCeiling +
                rawAbiTransferWorkspaceByteLengthCeiling +
                browserOperationRegistryByteLengthCeiling,
            `points[${pointIndex}].wasmMemoryByteLengthCeilingDecimal`,
        );
        const capChecks = [
            [
                canonicalProofByteLengthCeiling,
                proofStorageWidthProfile.maximumCommonProofByteLength,
                'common proof bytes',
            ],
            [
                transportByteLengthCeiling,
                proofStorageWidthProfile.maximumTransportByteLength,
                'transport bytes',
            ],
            [
                storedScratchPeakByteLengthCeiling,
                proofStorageWidthProfile.maximumStoredScratchByteLength,
                'stored scratch bytes',
            ],
            [
                physicalObjectPeak,
                proofStorageWidthProfile.maximumPhysicalObjectCount,
                'physical objects',
            ],
            [
                localRecordSealInvocationCount,
                proofStorageWidthProfile.maximumLocalRecordSealInvocationCount,
                'local record seals',
            ],
            [
                sealedSecretPlaintextByteLength,
                proofStorageWidthProfile.maximumLocalRecordSealedPlaintextByteLength,
                'sealed secret plaintext bytes',
            ],
            [
                copiedBufferByteLengthCeiling,
                proofStorageWidthProfile.maximumCopiedBufferByteLength,
                'copied buffer bytes',
            ],
            [
                wasmMemoryByteLengthCeiling,
                proofStorageWidthProfile.maximumWasmMemoryByteLength,
                'WASM memory bytes',
            ],
        ] as const;
        for (const [value, cap, description] of capChecks) {
            if (value > cap) {
                throw new Error(
                    `Static width ${width} ${description} ceiling ${value.toString()} exceeds cap ${cap.toString()}.`,
                );
            }
        }
        if (
            maximumTransactionPayloadByteLength > copiedBufferByteLengthCeiling
        ) {
            throw new Error(
                `Static width ${width} copied-buffer ceiling cannot hold one maximum transaction payload.`,
            );
        }

        return {
            absorbedLeafValueCount,
            activeColumnLdeScratchByteLength,
            baseLeafObjectReadByteLength,
            baseLeafObjectWrittenByteLength,
            boundaryTransferByteLengthCeiling,
            browserOperationRegistryByteLengthCeiling,
            canonicalArtifactContainerByteLengthCeiling,
            canonicalArtifactLiveCopyByteLengthCeiling,
            canonicalArtifactNonleafRangeChunkCountCeiling,
            canonicalProofByteLengthCeiling,
            committedTransactionCountCeiling,
            copiedBufferByteLengthCeiling,
            digestStateByteLengthCeiling,
            digestStateContainerByteLengthCeiling,
            externalIoByteLengthCeiling,
            externalReadByteLengthCeiling,
            externalWrittenByteLengthCeiling,
            extensionDomainWorkingByteLengthCeiling,
            freshVerifierPublicOpeningWorkspaceByteLengthCeiling,
            freshVerifierOuterVectorContainerByteLengthCeiling,
            frozenFixtureAndContainerByteLengthCeiling,
            inputIdentityShake256Hex,
            ldeTransformCount,
            legacyBaseLeafObjectByteLength,
            localRecordSealInvocationCount,
            maximumTransactionPayloadByteLength,
            openedLeafElementByteLength,
            openedLeafRangeChunkCount,
            openedValueCount,
            openingArtifactAndTranscriptByteLengthCeiling,
            persistedLdeByteLength,
            physicalObjectPeak,
            proofObjectSealTransactionCount,
            proofPhysicalObjectCount,
            proverPublicOpeningWorkspaceByteLengthCeiling,
            publicBaseLeafByteLength,
            publicBaseLeafColumnCount: width,
            queriedLeafPayloadByteLength,
            rawAbiRequestCopyWorkspaceByteLengthCeiling,
            rawAbiResponseDecodeWorkspaceByteLengthCeiling,
            rawAbiTransferWorkspaceByteLengthCeiling,
            retainedAlgebraicCoefficientByteLengthCeiling,
            sealedSecretPlaintextByteLength: 0n as const,
            sourceCommittedTransactionCount,
            sourceObjectSealTransactionCount,
            sourcePhysicalObjectCount,
            sourceReplayByteLength,
            storedScratchPeakByteLengthCeiling,
            nativeCustodyMetadataByteLengthCeiling,
            transportByteLengthCeiling,
            wasmMemoryByteLengthCeiling,
            widthDependentQueriedBaseOpeningByteLength,
        };
    });

    if (
        new Set(points.map((point) => point.inputIdentityShake256Hex)).size !==
        points.length
    ) {
        throw new Error(
            'Every scheduled static width must derive a distinct input identity.',
        );
    }

    return {
        absoluteCaps: proofStorageWidthProfile,
        points,
        profile,
    };
};

export type ValidatedProofStorageWidthResult = Readonly<{
    absorbedLeafValueCount: bigint;
    activeColumnLdeScratchByteLength: bigint;
    artifactShake256Hex: string;
    baseLeafObjectReadByteLength: 0n;
    baseLeafObjectWrittenByteLength: 0n;
    baseRootShake256Hex: string;
    canonicalArtifactNonleafRangeChunkCount: bigint;
    canonicalArtifactPostleafRangeChunkCount: bigint;
    canonicalArtifactPreleafRangeChunkCount: bigint;
    canonicalArtifactByteLength: bigint;
    custodyCleanupCompleted: true;
    custodyModel: 'bounded-external-storage-replay';
    elapsedNanoseconds: bigint;
    externalCommittedTransactionCount: bigint;
    externalIoByteLength: bigint;
    externalReadByteLength: bigint;
    externalWrittenByteLength: bigint;
    formatVersion: 1;
    inputIdentityShake256Hex: string;
    ldeTransformCount: bigint;
    localRecordSealInvocationCount: 0n;
    manifestIdentityShake256Hex: string;
    maximumTransactionPayloadByteLength: bigint;
    openedLeafElementByteLength: bigint;
    openedLeafRangeChunkCount: bigint;
    openedValueCount: bigint;
    operationFinishedAtUnixMilliseconds: bigint;
    operationStartedAtUnixMilliseconds: bigint;
    persistedBaseLeafByteLength: 0n;
    persistedLdeByteLength: 0n;
    physicalObjectPeak: bigint;
    proofObjectSealTransactionCount: 1n;
    proofPhysicalObjectCount: 1n;
    proofByteLength: bigint;
    publicBaseLeafByteLength: bigint;
    publicBaseLeafColumnCount: ProofStorageWidth;
    queriedLeafPayloadByteLength: bigint;
    recomputedCanonicalArtifactByteLength: bigint;
    profile: ProofStorageWidthProfileBinding;
    sourceCommittedTransactionCount: bigint;
    sourceObjectSealTransactionCount: bigint;
    sourcePhysicalObjectCount: bigint;
    sourceReplayByteLength: bigint;
    sealedSecretPlaintextByteLength: 0n;
    storedScratchPeakByteLength: bigint;
    widthDependentQueriedBaseOpeningByteLength: bigint;
}>;

const requireProofStorageWidth = (value: unknown): ProofStorageWidth => {
    if (
        typeof value === 'number' &&
        proofStorageWidthSchedule.some((width) => width === value)
    ) {
        return value as ProofStorageWidth;
    }
    throw new Error(
        `publicBaseLeafColumnCount must be one of ${proofStorageWidthSchedule.join(', ')}.`,
    );
};

export const validateProofStorageWidthResult = (
    input: unknown,
): ValidatedProofStorageWidthResult => {
    const record = requireJsonObject(input, 'Proof-storage width result');
    requireExactNumber(record.formatVersion, 1, 'formatVersion');
    const profile = validateProofStorageWidthProfileBinding(record);
    const exactCandidate = requireJsonObject(
        record.exactCandidate,
        'exactCandidate',
    );
    requireExactNumber(
        exactCandidate.rosterSize,
        proofStorageWidthProfile.rosterSize,
        'exactCandidate.rosterSize',
    );
    requireExactNumber(
        exactCandidate.ringDimension,
        proofStorageWidthProfile.ringDimension,
        'exactCandidate.ringDimension',
    );
    requireExactNumber(
        exactCandidate.plaintextModulus,
        proofStorageWidthProfile.plaintextModulus,
        'exactCandidate.plaintextModulus',
    );
    requireExactNumber(
        exactCandidate.firstDataModulus,
        proofStorageWidthProfile.firstDataModulus,
        'exactCandidate.firstDataModulus',
    );
    requireExactNumber(
        exactCandidate.materialRadix,
        proofStorageWidthProfile.materialRadix,
        'exactCandidate.materialRadix',
    );
    requireExactNumber(
        record.algebraicBaseColumnCount,
        proofStorageWidthProfile.algebraicBaseColumnCount,
        'algebraicBaseColumnCount',
    );
    requireExactNumber(
        record.sourceOpeningClaimCount,
        proofStorageWidthProfile.sourceOpeningClaimCount,
        'sourceOpeningClaimCount',
    );
    requireExactNumber(
        record.batchingFunctionCount,
        proofStorageWidthProfile.batchingFunctionCount,
        'batchingFunctionCount',
    );
    const width = requireProofStorageWidth(record.publicBaseLeafColumnCount);
    requireExactNumber(record.width, width, 'width');
    const geometry = deriveProofStorageWidthGeometry(width);
    const publicBaseLeafByteLength = parseCanonicalUnsigned64Decimal(
        record.publicBaseLeafByteLengthDecimal,
        'publicBaseLeafByteLengthDecimal',
    );
    const openedLeafElementByteLength = parseCanonicalUnsigned64Decimal(
        record.openedLeafElementByteLengthDecimal,
        'openedLeafElementByteLengthDecimal',
    );
    const sourceReplayByteLength = parseCanonicalUnsigned64Decimal(
        record.sourceReplayByteLengthDecimal,
        'sourceReplayByteLengthDecimal',
    );
    const proofByteLength = parseCanonicalUnsigned64Decimal(
        record.proofByteLengthDecimal,
        'proofByteLengthDecimal',
    );
    const canonicalArtifactByteLength = parseCanonicalUnsigned64Decimal(
        record.canonicalArtifactByteLengthDecimal,
        'canonicalArtifactByteLengthDecimal',
    );
    const canonicalArtifactNonleafRangeChunkCount =
        parseCanonicalUnsigned64Decimal(
            record.canonicalArtifactNonleafRangeChunkCountDecimal,
            'canonicalArtifactNonleafRangeChunkCountDecimal',
        );
    const canonicalArtifactPreleafRangeChunkCount =
        parseCanonicalUnsigned64Decimal(
            record.canonicalArtifactPreleafRangeChunkCountDecimal,
            'canonicalArtifactPreleafRangeChunkCountDecimal',
        );
    const canonicalArtifactPostleafRangeChunkCount =
        parseCanonicalUnsigned64Decimal(
            record.canonicalArtifactPostleafRangeChunkCountDecimal,
            'canonicalArtifactPostleafRangeChunkCountDecimal',
        );
    const recomputedCanonicalArtifactByteLength =
        parseCanonicalUnsigned64Decimal(
            record.recomputedCanonicalArtifactByteLengthDecimal,
            'recomputedCanonicalArtifactByteLengthDecimal',
        );
    const physicalObjectPeak = parseCanonicalUnsigned64Decimal(
        record.physicalObjectPeakDecimal,
        'physicalObjectPeakDecimal',
    );
    const storedScratchPeakByteLength = parseCanonicalUnsigned64Decimal(
        record.storedScratchPeakByteLengthDecimal,
        'storedScratchPeakByteLengthDecimal',
    );
    const maximumTransactionPayloadByteLength = parseCanonicalUnsigned64Decimal(
        record.maximumTransactionPayloadByteLengthDecimal,
        'maximumTransactionPayloadByteLengthDecimal',
    );
    const activeColumnLdeScratchByteLength = parseCanonicalUnsigned64Decimal(
        record.activeColumnLdeScratchByteLengthDecimal,
        'activeColumnLdeScratchByteLengthDecimal',
    );
    const baseLeafObjectReadByteLength = parseCanonicalUnsigned64Decimal(
        record.baseLeafObjectReadByteLengthDecimal,
        'baseLeafObjectReadByteLengthDecimal',
    );
    const baseLeafObjectWrittenByteLength = parseCanonicalUnsigned64Decimal(
        record.baseLeafObjectWrittenByteLengthDecimal,
        'baseLeafObjectWrittenByteLengthDecimal',
    );
    const persistedLdeByteLength = parseCanonicalUnsigned64Decimal(
        record.persistedLdeByteLengthDecimal,
        'persistedLdeByteLengthDecimal',
    );
    const persistedBaseLeafByteLength = parseCanonicalUnsigned64Decimal(
        record.persistedBaseLeafByteLengthDecimal,
        'persistedBaseLeafByteLengthDecimal',
    );
    const ldeTransformCount = parseCanonicalUnsigned64Decimal(
        record.ldeTransformCountDecimal,
        'ldeTransformCountDecimal',
    );
    const absorbedLeafValueCount = parseCanonicalUnsigned64Decimal(
        record.absorbedLeafValueCountDecimal,
        'absorbedLeafValueCountDecimal',
    );
    const openedValueCount = parseCanonicalUnsigned64Decimal(
        record.openedValueCountDecimal,
        'openedValueCountDecimal',
    );
    const queriedLeafPayloadByteLength = parseCanonicalUnsigned64Decimal(
        record.queriedLeafPayloadByteLengthDecimal,
        'queriedLeafPayloadByteLengthDecimal',
    );
    const openedLeafRangeChunkCount = parseCanonicalUnsigned64Decimal(
        record.openedLeafRangeChunkCountDecimal,
        'openedLeafRangeChunkCountDecimal',
    );
    const localRecordSealInvocationCount = parseCanonicalUnsigned64Decimal(
        record.localRecordSealInvocationCountDecimal,
        'localRecordSealInvocationCountDecimal',
    );
    const sealedSecretPlaintextByteLength = parseCanonicalUnsigned64Decimal(
        record.sealedSecretPlaintextByteLengthDecimal,
        'sealedSecretPlaintextByteLengthDecimal',
    );
    const sourcePhysicalObjectCount = parseCanonicalUnsigned64Decimal(
        record.sourcePhysicalObjectCountDecimal,
        'sourcePhysicalObjectCountDecimal',
    );
    const proofPhysicalObjectCount = parseCanonicalUnsigned64Decimal(
        record.proofPhysicalObjectCountDecimal,
        'proofPhysicalObjectCountDecimal',
    );
    const sourceObjectSealTransactionCount = parseCanonicalUnsigned64Decimal(
        record.sourceObjectSealTransactionCountDecimal,
        'sourceObjectSealTransactionCountDecimal',
    );
    const proofObjectSealTransactionCount = parseCanonicalUnsigned64Decimal(
        record.proofObjectSealTransactionCountDecimal,
        'proofObjectSealTransactionCountDecimal',
    );
    const sourceCommittedTransactionCount = parseCanonicalUnsigned64Decimal(
        record.sourceCommittedTransactionCountDecimal,
        'sourceCommittedTransactionCountDecimal',
    );
    const widthDependentQueriedBaseOpeningByteLength =
        parseCanonicalUnsigned64Decimal(
            record.widthDependentQueriedBaseOpeningByteLengthDecimal,
            'widthDependentQueriedBaseOpeningByteLengthDecimal',
        );
    requireExpectedUnsigned64(
        sourceReplayByteLength,
        geometry.sourceReplayByteLength,
        'sourceReplayByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        publicBaseLeafByteLength,
        geometry.publicBaseLeafByteLength,
        'publicBaseLeafByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        openedLeafElementByteLength,
        geometry.openedLeafElementByteLength,
        'openedLeafElementByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        canonicalArtifactByteLength,
        recomputedCanonicalArtifactByteLength,
        'canonicalArtifactByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        proofByteLength,
        recomputedCanonicalArtifactByteLength,
        'proofByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        maximumTransactionPayloadByteLength,
        proofStorageWidthProfile.externalMemoryChunkByteLength,
        'maximumTransactionPayloadByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        activeColumnLdeScratchByteLength,
        geometry.activeColumnLdeScratchByteLength,
        'activeColumnLdeScratchByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        baseLeafObjectReadByteLength,
        0n,
        'baseLeafObjectReadByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        baseLeafObjectWrittenByteLength,
        0n,
        'baseLeafObjectWrittenByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        persistedLdeByteLength,
        0n,
        'persistedLdeByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        persistedBaseLeafByteLength,
        0n,
        'persistedBaseLeafByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        ldeTransformCount,
        geometry.ldeTransformCount,
        'ldeTransformCountDecimal',
    );
    requireExpectedUnsigned64(
        absorbedLeafValueCount,
        geometry.absorbedLeafValueCount,
        'absorbedLeafValueCountDecimal',
    );
    requireExpectedUnsigned64(
        openedValueCount,
        geometry.openedValueCount,
        'openedValueCountDecimal',
    );
    requireExpectedUnsigned64(
        queriedLeafPayloadByteLength,
        geometry.queriedLeafPayloadByteLength,
        'queriedLeafPayloadByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        openedLeafRangeChunkCount,
        geometry.openedLeafRangeChunkCount,
        'openedLeafRangeChunkCountDecimal',
    );
    requireExpectedUnsigned64(
        localRecordSealInvocationCount,
        geometry.localRecordSealInvocationCount,
        'localRecordSealInvocationCountDecimal',
    );
    requireExpectedUnsigned64(
        sealedSecretPlaintextByteLength,
        geometry.sealedSecretPlaintextByteLength,
        'sealedSecretPlaintextByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        sourcePhysicalObjectCount,
        BigInt(width),
        'sourcePhysicalObjectCountDecimal',
    );
    requireExpectedUnsigned64(
        proofPhysicalObjectCount,
        1n,
        'proofPhysicalObjectCountDecimal',
    );
    requireExpectedUnsigned64(
        sourceObjectSealTransactionCount,
        geometry.sourceObjectSealTransactionCount,
        'sourceObjectSealTransactionCountDecimal',
    );
    requireExpectedUnsigned64(
        proofObjectSealTransactionCount,
        geometry.proofObjectSealTransactionCount,
        'proofObjectSealTransactionCountDecimal',
    );
    requireExpectedUnsigned64(
        sourceCommittedTransactionCount,
        24n * BigInt(width),
        'sourceCommittedTransactionCountDecimal',
    );
    requireExpectedUnsigned64(
        widthDependentQueriedBaseOpeningByteLength,
        geometry.widthDependentQueriedBaseOpeningByteLength,
        'widthDependentQueriedBaseOpeningByteLengthDecimal',
    );
    if (record.custodyCleanupCompleted !== true) {
        throw new Error('custodyCleanupCompleted must be true.');
    }
    const externalReadByteLength = parseCanonicalUnsigned64Decimal(
        record.externalReadByteLengthDecimal,
        'externalReadByteLengthDecimal',
    );
    const externalWrittenByteLength = parseCanonicalUnsigned64Decimal(
        record.externalWrittenByteLengthDecimal,
        'externalWrittenByteLengthDecimal',
    );
    const externalCommittedTransactionCount = parseCanonicalUnsigned64Decimal(
        record.externalCommittedTransactionCountDecimal,
        'externalCommittedTransactionCountDecimal',
    );
    if (canonicalArtifactNonleafRangeChunkCount === 0n) {
        throw new Error(
            'canonicalArtifactNonleafRangeChunkCountDecimal must be positive.',
        );
    }
    requireExpectedUnsigned64(
        canonicalArtifactNonleafRangeChunkCount,
        canonicalArtifactPreleafRangeChunkCount +
            canonicalArtifactPostleafRangeChunkCount,
        'canonicalArtifactNonleafRangeChunkCountDecimal',
    );
    const expectedExternalCommittedTransactionCount =
        sourceCommittedTransactionCount +
        3n +
        2n *
            (canonicalArtifactPreleafRangeChunkCount +
                openedLeafRangeChunkCount +
                canonicalArtifactPostleafRangeChunkCount);
    const expectedStoredScratchPeakByteLength = checkedAddUnsigned64(
        geometry.sourceReplayByteLength,
        recomputedCanonicalArtifactByteLength,
        'expectedStoredScratchPeakByteLength',
    );
    const expectedExternalReadByteLength = checkedAddUnsigned64(
        6n * geometry.sourceReplayByteLength,
        recomputedCanonicalArtifactByteLength,
        'expectedExternalReadByteLength',
    );
    const expectedExternalWrittenByteLength = checkedAddUnsigned64(
        geometry.sourceReplayByteLength,
        recomputedCanonicalArtifactByteLength,
        'expectedExternalWrittenByteLength',
    );
    requireExpectedUnsigned64(
        physicalObjectPeak,
        geometry.physicalObjectPeak,
        'physicalObjectPeakDecimal',
    );
    requireExpectedUnsigned64(
        storedScratchPeakByteLength,
        expectedStoredScratchPeakByteLength,
        'storedScratchPeakByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        externalReadByteLength,
        expectedExternalReadByteLength,
        'externalReadByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        externalWrittenByteLength,
        expectedExternalWrittenByteLength,
        'externalWrittenByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        externalCommittedTransactionCount,
        expectedExternalCommittedTransactionCount,
        'externalCommittedTransactionCountDecimal',
    );
    if (
        externalReadByteLength === 0n ||
        externalWrittenByteLength === 0n ||
        externalCommittedTransactionCount === 0n
    ) {
        throw new Error(
            'External reads, writes, and committed transactions must be measured rather than omitted or reported as zero.',
        );
    }
    const elapsedNanoseconds = parseCanonicalUnsigned64Decimal(
        record.elapsedNanosecondsDecimal,
        'elapsedNanosecondsDecimal',
    );
    if (elapsedNanoseconds === 0n || proofByteLength === 0n) {
        throw new Error('Elapsed time and proof bytes must be positive.');
    }
    const operationStartedAtUnixMilliseconds = parseGuardUnsigned64(
        record.operationStartedAtUnixMilliseconds,
        'operationStartedAtUnixMilliseconds',
    );
    const operationFinishedAtUnixMilliseconds = parseGuardUnsigned64(
        record.operationFinishedAtUnixMilliseconds,
        'operationFinishedAtUnixMilliseconds',
    );
    if (
        operationFinishedAtUnixMilliseconds < operationStartedAtUnixMilliseconds
    ) {
        throw new Error('The width-evidence operation window is reversed.');
    }

    return {
        absorbedLeafValueCount,
        activeColumnLdeScratchByteLength,
        artifactShake256Hex: requireHash512Hex(
            record.artifactShake256Hex,
            'artifactShake256Hex',
        ),
        baseLeafObjectReadByteLength: 0n,
        baseLeafObjectWrittenByteLength: 0n,
        baseRootShake256Hex: requireHash512Hex(
            record.baseRootShake256Hex,
            'baseRootShake256Hex',
        ),
        canonicalArtifactNonleafRangeChunkCount,
        canonicalArtifactPostleafRangeChunkCount,
        canonicalArtifactPreleafRangeChunkCount,
        canonicalArtifactByteLength,
        custodyCleanupCompleted: true,
        custodyModel: 'bounded-external-storage-replay',
        elapsedNanoseconds,
        externalCommittedTransactionCount,
        externalIoByteLength: checkedAddUnsigned64(
            externalReadByteLength,
            externalWrittenByteLength,
            'externalIoByteLength',
        ),
        externalReadByteLength,
        externalWrittenByteLength,
        formatVersion: 1,
        inputIdentityShake256Hex: requireHash512Hex(
            record.inputIdentityShake256Hex,
            'inputIdentityShake256Hex',
        ),
        ldeTransformCount,
        localRecordSealInvocationCount: 0n,
        manifestIdentityShake256Hex: requireHash512Hex(
            record.manifestIdentityShake256Hex,
            'manifestIdentityShake256Hex',
        ),
        maximumTransactionPayloadByteLength,
        openedLeafElementByteLength,
        openedLeafRangeChunkCount,
        openedValueCount,
        operationFinishedAtUnixMilliseconds,
        operationStartedAtUnixMilliseconds,
        persistedBaseLeafByteLength: 0n,
        persistedLdeByteLength: 0n,
        physicalObjectPeak,
        proofObjectSealTransactionCount: 1n,
        proofPhysicalObjectCount: 1n,
        proofByteLength,
        profile,
        publicBaseLeafByteLength,
        publicBaseLeafColumnCount: width,
        queriedLeafPayloadByteLength,
        recomputedCanonicalArtifactByteLength,
        sealedSecretPlaintextByteLength: 0n,
        sourceCommittedTransactionCount,
        sourceObjectSealTransactionCount,
        sourcePhysicalObjectCount,
        sourceReplayByteLength,
        storedScratchPeakByteLength,
        widthDependentQueriedBaseOpeningByteLength,
    };
};

type ProofStorageWidthOperationMemory = Readonly<{
    baselineProcessTreeResidentMemoryByteLength: bigint;
    inWindowSampleCount: number;
    peakProcessTreeResidentMemoryByteLength: bigint;
    resourceSampleIntervalMilliseconds: 100n;
}>;

const maximum = (values: readonly bigint[]): bigint => {
    const first = values[0];
    if (first === undefined) {
        throw new Error('Cannot find a maximum of an empty collection.');
    }
    return values
        .slice(1)
        .reduce((current, value) => (value > current ? value : current), first);
};

export const extractProofStorageWidthOperationMemory = (input: {
    readonly guardJsonLines: string;
    readonly operationFinishedAtUnixMilliseconds: bigint;
    readonly operationStartedAtUnixMilliseconds: bigint;
}): ProofStorageWidthOperationMemory => {
    const records = input.guardJsonLines
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) => {
            let parsed: unknown;
            try {
                parsed = JSON.parse(line) as unknown;
            } catch (error) {
                throw Object.assign(
                    new Error(
                        `Process-memory guard line ${lineIndex + 1} is not valid JSON.`,
                    ),
                    { cause: error },
                );
            }
            const record = requireJsonObject(
                parsed,
                `Process-memory guard line ${lineIndex + 1}`,
            );
            return {
                elapsedMilliseconds: parseGuardUnsigned64(
                    record.elapsedMilliseconds,
                    `Process-memory guard line ${lineIndex + 1} elapsedMilliseconds`,
                ),
                record,
                recordedAtUnixMilliseconds: parseGuardUnsigned64(
                    record.recordedAtUnixMilliseconds,
                    `Process-memory guard line ${lineIndex + 1} recordedAtUnixMilliseconds`,
                ),
                sequence: parseGuardUnsigned64(
                    record.sequence,
                    `Process-memory guard line ${lineIndex + 1} sequence`,
                ),
            };
        });
    if (records.length === 0) {
        throw new Error('Process-memory guard telemetry is empty.');
    }
    for (const [recordIndex, current] of records.entries()) {
        if (current.sequence !== BigInt(recordIndex)) {
            throw new Error(
                'Process-memory guard telemetry sequence must start at zero and remain contiguous.',
            );
        }
        const previous = records[recordIndex - 1];
        if (
            previous !== undefined &&
            (current.elapsedMilliseconds < previous.elapsedMilliseconds ||
                current.recordedAtUnixMilliseconds <
                    previous.recordedAtUnixMilliseconds)
        ) {
            throw new Error(
                'Process-memory guard elapsed and wall time must be nondecreasing.',
            );
        }
    }
    const guardStartedRecord = records[0];
    const childStartedRecord = records[1];
    const childExitedRecord = records[records.length - 1];
    if (
        guardStartedRecord?.record.eventType !== 'guard-started' ||
        childStartedRecord?.record.eventType !== 'child-started' ||
        childExitedRecord?.record.eventType !== 'child-exited' ||
        records
            .slice(2, -1)
            .some(({ record }) => record.eventType !== 'resource-sample')
    ) {
        throw new Error(
            'Process-memory guard telemetry must contain one contiguous guard-started, child-started, resource-sample, and child-exited lifecycle.',
        );
    }
    if (
        input.operationStartedAtUnixMilliseconds <
            childStartedRecord.recordedAtUnixMilliseconds ||
        input.operationFinishedAtUnixMilliseconds >
            childExitedRecord.recordedAtUnixMilliseconds
    ) {
        throw new Error(
            'The width-evidence operation must stay inside the guarded child lifecycle.',
        );
    }
    if (
        childExitedRecord.record.memoryEvidence !== 'completed' ||
        childExitedRecord.record.terminationClassification !== 'completed' ||
        childExitedRecord.record.exitCode !== 0
    ) {
        throw new Error(
            'Process-memory guard telemetry lacks a terminal completed child-exited record.',
        );
    }
    const resourceSampleIntervalMilliseconds = parseGuardUnsigned64(
        guardStartedRecord.record.resourceSampleIntervalMilliseconds,
        'resourceSampleIntervalMilliseconds',
    );
    if (resourceSampleIntervalMilliseconds !== 100n) {
        throw new Error(
            'Process-memory guard sampling cadence must be exactly 100 milliseconds.',
        );
    }
    if (guardStartedRecord.record.aggregateProcessTreeMemoryLimit !== true) {
        throw new Error(
            'Process-memory guard telemetry must cover the aggregate process tree.',
        );
    }
    const samples = records
        .slice(2, -1)
        .map(({ elapsedMilliseconds, record, recordedAtUnixMilliseconds }) => {
            if (
                record.sampleError !== null ||
                record.confirmedMemoryLimitViolation !== false
            ) {
                throw new Error(
                    'Every process-memory guard sample must report no sampling error and no memory-limit violation.',
                );
            }
            const residentMemoryByteLength = parseGuardUnsigned64(
                record.processTreeResidentMemoryBytes,
                'processTreeResidentMemoryBytes',
            );
            if (residentMemoryByteLength === 0n) {
                throw new Error(
                    'Every process-memory guard resident sample must be positive.',
                );
            }
            return {
                elapsedMilliseconds,
                recordedAtUnixMilliseconds,
                residentMemoryByteLength,
            };
        });
    const baselineSamples = samples.filter(
        (sample) =>
            sample.recordedAtUnixMilliseconds <
            input.operationStartedAtUnixMilliseconds,
    );
    const baselineSample = baselineSamples[baselineSamples.length - 1];
    if (baselineSample === undefined) {
        throw new Error(
            'Process-memory guard telemetry lacks a pre-operation resident baseline.',
        );
    }
    const inWindowSamples = samples.filter(
        (sample) =>
            sample.recordedAtUnixMilliseconds >=
                input.operationStartedAtUnixMilliseconds &&
            sample.recordedAtUnixMilliseconds <=
                input.operationFinishedAtUnixMilliseconds,
    );
    const firstInWindowSample = inWindowSamples[0];
    const lastInWindowSample = inWindowSamples[inWindowSamples.length - 1];
    if (firstInWindowSample === undefined || lastInWindowSample === undefined) {
        throw new Error(
            'Process-memory guard telemetry lacks an in-window resident sample.',
        );
    }
    if (
        input.operationStartedAtUnixMilliseconds -
            baselineSample.recordedAtUnixMilliseconds >
            500n ||
        firstInWindowSample.recordedAtUnixMilliseconds -
            input.operationStartedAtUnixMilliseconds >
            500n ||
        input.operationFinishedAtUnixMilliseconds -
            lastInWindowSample.recordedAtUnixMilliseconds >
            500n
    ) {
        throw new Error(
            'Process-memory guard telemetry does not cover both operation boundaries within 500 milliseconds.',
        );
    }
    const operationWindowSamples = [baselineSample, ...inWindowSamples];
    for (let index = 1; index < operationWindowSamples.length; index += 1) {
        const previous = operationWindowSamples[index - 1];
        const current = operationWindowSamples[index];
        if (
            previous === undefined ||
            current === undefined ||
            current.elapsedMilliseconds - previous.elapsedMilliseconds > 500n
        ) {
            throw new Error(
                'Process-memory guard telemetry contains an operation-window gap greater than 500 milliseconds.',
            );
        }
    }
    return {
        baselineProcessTreeResidentMemoryByteLength:
            baselineSample.residentMemoryByteLength,
        inWindowSampleCount: inWindowSamples.length,
        peakProcessTreeResidentMemoryByteLength: maximum(
            inWindowSamples.map((sample) => sample.residentMemoryByteLength),
        ),
        resourceSampleIntervalMilliseconds: 100n,
    };
};

export type ValidatedProofStorageWidthPoint = Readonly<{
    baselineProcessTreeResidentMemoryByteLength: bigint;
    peakProcessTreeResidentMemoryByteLength: bigint;
    result: ValidatedProofStorageWidthResult;
    scheduleOrdinal: number;
}>;

export const validateProofStorageWidthPointAgainstStaticPreflight = (input: {
    readonly point: ValidatedProofStorageWidthPoint;
    readonly staticPoint: ValidatedProofStorageWidthStaticPreflightPoint;
}): void => {
    if (
        input.point.result.publicBaseLeafColumnCount !==
        input.staticPoint.publicBaseLeafColumnCount
    ) {
        throw new Error(
            'The measured width does not match its static preflight point.',
        );
    }
    if (
        input.point.result.inputIdentityShake256Hex !==
        input.staticPoint.inputIdentityShake256Hex
    ) {
        throw new Error(
            'The measured width input identity does not match the identity derived by its static core-and-recipe preflight.',
        );
    }
    const ceilings = [
        [
            input.point.result.proofByteLength,
            input.staticPoint.canonicalProofByteLengthCeiling,
            'canonical proof bytes',
        ],
        [
            input.point.result.canonicalArtifactNonleafRangeChunkCount,
            input.staticPoint.canonicalArtifactNonleafRangeChunkCountCeiling,
            'canonical nonleaf range chunks',
        ],
        [
            input.point.result.externalReadByteLength,
            input.staticPoint.externalReadByteLengthCeiling,
            'external read bytes',
        ],
        [
            input.point.result.externalWrittenByteLength,
            input.staticPoint.externalWrittenByteLengthCeiling,
            'external written bytes',
        ],
        [
            input.point.result.externalIoByteLength,
            input.staticPoint.externalIoByteLengthCeiling,
            'external I/O bytes',
        ],
        [
            input.point.result.externalCommittedTransactionCount,
            input.staticPoint.committedTransactionCountCeiling,
            'committed transactions',
        ],
        [
            input.point.result.storedScratchPeakByteLength,
            input.staticPoint.storedScratchPeakByteLengthCeiling,
            'stored scratch bytes',
        ],
    ] as const;
    for (const [actual, ceiling, description] of ceilings) {
        if (actual > ceiling) {
            throw new Error(
                `Measured width ${input.point.result.publicBaseLeafColumnCount} ${description} ${actual.toString()} exceeds its precommitted static ceiling ${ceiling.toString()}.`,
            );
        }
    }
};

export const validateProofStorageWidthPoint = (input: {
    readonly expectedScheduleOrdinal: number;
    readonly guardJsonLines: string;
    readonly result: unknown;
}): ValidatedProofStorageWidthPoint => {
    const expectedWidth =
        proofStorageWidthSchedule[input.expectedScheduleOrdinal - 1];
    if (expectedWidth === undefined) {
        throw new Error(
            'The width-evidence schedule ordinal is outside one through seven.',
        );
    }
    const result = validateProofStorageWidthResult(input.result);
    if (result.publicBaseLeafColumnCount !== expectedWidth) {
        throw new Error(
            `Schedule ordinal ${input.expectedScheduleOrdinal} requires width ${expectedWidth}, not ${result.publicBaseLeafColumnCount}.`,
        );
    }
    const memory = extractProofStorageWidthOperationMemory({
        guardJsonLines: input.guardJsonLines,
        operationFinishedAtUnixMilliseconds:
            result.operationFinishedAtUnixMilliseconds,
        operationStartedAtUnixMilliseconds:
            result.operationStartedAtUnixMilliseconds,
    });
    return {
        baselineProcessTreeResidentMemoryByteLength:
            memory.baselineProcessTreeResidentMemoryByteLength,
        peakProcessTreeResidentMemoryByteLength:
            memory.peakProcessTreeResidentMemoryByteLength,
        result,
        scheduleOrdinal: input.expectedScheduleOrdinal,
    };
};

export type ProofStorageWidthCurveDecision = Readonly<{
    capViolations: readonly string[];
    outcome:
        | 'absolute-cap-violation'
        | 'continue'
        | 'full-width-complete'
        | 'unexplained-superlinear-scaling';
    pendingReleaseDesktopBrowserCaps: readonly [
        'copied-buffer-byte-length',
        'wasm-memory-byte-length',
    ];
    superlinearViolations: readonly string[];
    transactionChunkBoundaryExempted: boolean;
}>;

const pendingReleaseDesktopBrowserCaps = [
    'copied-buffer-byte-length',
    'wasm-memory-byte-length',
] as const;

const exceedsFactorTwoLinearEnvelope = (input: {
    readonly currentMetric: bigint;
    readonly currentWidth: bigint;
    readonly previousMetric: bigint;
    readonly previousWidth: bigint;
}): boolean =>
    input.currentMetric * input.previousWidth >
    2n * input.previousMetric * input.currentWidth;

export const evaluateProofStorageWidthCurve = (
    points: readonly ValidatedProofStorageWidthPoint[],
): ProofStorageWidthCurveDecision => {
    if (points.length === 0) {
        throw new Error('The width curve requires at least one point.');
    }
    for (const [index, point] of points.entries()) {
        const expectedWidth = proofStorageWidthSchedule[index];
        if (
            expectedWidth === undefined ||
            point.scheduleOrdinal !== index + 1 ||
            point.result.publicBaseLeafColumnCount !== expectedWidth
        ) {
            throw new Error(
                'The width curve must be an exact prefix of the precommitted schedule.',
            );
        }
    }
    const currentPoint = points[points.length - 1];
    if (currentPoint === undefined) {
        throw new Error('The width curve current point is missing.');
    }
    const capViolations: string[] = [];
    if (
        currentPoint.result.physicalObjectPeak >
        proofStorageWidthProfile.maximumPhysicalObjectCount
    ) {
        capViolations.push('physical-external-object-count');
    }
    if (
        currentPoint.result.storedScratchPeakByteLength >
        proofStorageWidthProfile.maximumStoredScratchByteLength
    ) {
        capViolations.push('stored-scratch-byte-length');
    }
    if (
        currentPoint.result.proofByteLength >
        proofStorageWidthProfile.maximumCommonProofByteLength
    ) {
        capViolations.push('common-proof-byte-length');
    }
    if (
        currentPoint.result.proofByteLength >
        proofStorageWidthProfile.maximumTransportByteLength
    ) {
        capViolations.push('transport-byte-length');
    }
    if (
        currentPoint.result.localRecordSealInvocationCount >
        proofStorageWidthProfile.maximumLocalRecordSealInvocationCount
    ) {
        capViolations.push('local-record-seal-invocation-count');
    }
    if (
        currentPoint.result.sealedSecretPlaintextByteLength >
        proofStorageWidthProfile.maximumLocalRecordSealedPlaintextByteLength
    ) {
        capViolations.push('local-record-sealed-plaintext-byte-length');
    }
    if (capViolations.length !== 0) {
        return {
            capViolations,
            outcome: 'absolute-cap-violation',
            pendingReleaseDesktopBrowserCaps,
            superlinearViolations: [],
            transactionChunkBoundaryExempted: false,
        };
    }

    const superlinearViolations: string[] = [];
    const firstPoint = points[0];
    const previousPoint = points[points.length - 2];
    if (firstPoint === undefined) {
        throw new Error('The width curve baseline is missing.');
    }
    if (previousPoint !== undefined) {
        const currentWidth = BigInt(
            currentPoint.result.publicBaseLeafColumnCount,
        );
        const previousWidth = BigInt(
            previousPoint.result.publicBaseLeafColumnCount,
        );
        const metrics = [
            [
                'proof-bytes',
                currentPoint.result.proofByteLength,
                previousPoint.result.proofByteLength,
            ],
            [
                'external-io',
                currentPoint.result.externalIoByteLength,
                previousPoint.result.externalIoByteLength,
            ],
            [
                'stored-scratch',
                currentPoint.result.storedScratchPeakByteLength,
                previousPoint.result.storedScratchPeakByteLength,
            ],
            [
                'process-tree-rss',
                currentPoint.peakProcessTreeResidentMemoryByteLength,
                previousPoint.peakProcessTreeResidentMemoryByteLength,
            ],
        ] as const;
        for (const [metricName, currentMetric, previousMetric] of metrics) {
            if (
                exceedsFactorTwoLinearEnvelope({
                    currentMetric,
                    currentWidth,
                    previousMetric,
                    previousWidth,
                })
            ) {
                superlinearViolations.push(`${metricName}-adjacent`);
            }
        }
        const currentChunksPerLeaf =
            currentPoint.result.openedLeafRangeChunkCount /
            proofStorageWidthProfile.queryRepresentativeCount;
        const previousChunksPerLeaf =
            previousPoint.result.openedLeafRangeChunkCount /
            proofStorageWidthProfile.queryRepresentativeCount;
        const transactionChunkBoundaryExempted =
            currentChunksPerLeaf !== previousChunksPerLeaf;
        const currentAdditionalLeafRangeTransactions =
            2n *
            (currentPoint.result.openedLeafRangeChunkCount -
                proofStorageWidthProfile.queryRepresentativeCount);
        const previousAdditionalLeafRangeTransactions =
            2n *
            (previousPoint.result.openedLeafRangeChunkCount -
                proofStorageWidthProfile.queryRepresentativeCount);
        if (
            exceedsFactorTwoLinearEnvelope({
                currentMetric:
                    currentPoint.result.externalCommittedTransactionCount -
                    currentAdditionalLeafRangeTransactions,
                currentWidth,
                previousMetric:
                    previousPoint.result.externalCommittedTransactionCount -
                    previousAdditionalLeafRangeTransactions,
                previousWidth,
            })
        ) {
            superlinearViolations.push('external-transactions-adjacent');
        }

        const width32Point = points[1];
        if (width32Point !== undefined && points.length > 2) {
            const baselineElapsed = firstPoint.result.elapsedNanoseconds;
            if (width32Point.result.elapsedNanoseconds <= baselineElapsed) {
                superlinearViolations.push(
                    'elapsed-time-anchor-nonpositive-slope',
                );
            } else {
                const currentVariableElapsed =
                    currentPoint.result.elapsedNanoseconds - baselineElapsed;
                const anchorVariableElapsed =
                    width32Point.result.elapsedNanoseconds - baselineElapsed;
                const currentVariableWidth = currentWidth - 8n;
                const adjacentElapsedIncrement =
                    currentPoint.result.elapsedNanoseconds -
                    previousPoint.result.elapsedNanoseconds;
                const adjacentWidthIncrement = currentWidth - previousWidth;
                if (
                    adjacentElapsedIncrement > 0n &&
                    adjacentElapsedIncrement * 24n >
                        2n * anchorVariableElapsed * adjacentWidthIncrement
                ) {
                    superlinearViolations.push('elapsed-time-adjacent');
                }
                if (
                    currentVariableElapsed * 24n >
                    2n * anchorVariableElapsed * currentVariableWidth
                ) {
                    superlinearViolations.push('elapsed-time-global');
                }
            }
        }
        if (superlinearViolations.length !== 0) {
            return {
                capViolations: [],
                outcome: 'unexplained-superlinear-scaling',
                pendingReleaseDesktopBrowserCaps,
                superlinearViolations,
                transactionChunkBoundaryExempted,
            };
        }
        if (points.length === proofStorageWidthSchedule.length) {
            return {
                capViolations: [],
                outcome: 'full-width-complete',
                pendingReleaseDesktopBrowserCaps,
                superlinearViolations: [],
                transactionChunkBoundaryExempted,
            };
        }
        return {
            capViolations: [],
            outcome: 'continue',
            pendingReleaseDesktopBrowserCaps,
            superlinearViolations: [],
            transactionChunkBoundaryExempted,
        };
    }
    return {
        capViolations: [],
        outcome: 'continue',
        pendingReleaseDesktopBrowserCaps,
        superlinearViolations: [],
        transactionChunkBoundaryExempted: false,
    };
};
