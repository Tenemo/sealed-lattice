import {
    deriveProofStorageWidthGeometry,
    proofStorageWidthProfile,
    validateProofStorageWidthResult,
    type ProofStorageWidthProfileBinding,
} from '#tools/ci/proof-storage-width-evidence';

export const proofStorageWidthBrowserEvidenceConsolePrefix =
    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_EVIDENCE ';
export const proofStorageWidthBrowserEvidenceProjectLabel =
    'proof-storage-width-browser-evidence';

export const proofStorageWidthBrowserEvidenceProfile = Object.freeze({
    arithmeticProgressPollsPerYield: 8,
    maximumCopiedBufferByteLength: 8_388_608n,
    maximumPhysicalObjectCount: 4_096n,
    maximumProofByteLength: 268_435_456n,
    maximumStoredScratchByteLength: 1_073_741_824n,
    maximumTransactionPayloadByteLength: 49_152n,
    maximumWasmLinearMemoryByteLength: 671_088_640n,
    representativeWidth: 512 as const,
    storageTransactionsPerYield: 64,
});

const representativeGeometry = deriveProofStorageWidthGeometry(
    proofStorageWidthBrowserEvidenceProfile.representativeWidth,
);
const maximumUnsigned64 = (1n << 64n) - 1n;
const hash256HexPattern = /^[0-9a-f]{64}$/u;
const hash512HexPattern = /^[0-9a-f]{128}$/u;

type JsonObject = Readonly<Record<string, unknown>>;

const requireJsonObject = (value: unknown, fieldName: string): JsonObject => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be a JSON object.`);
    }
    return value as JsonObject;
};

const requireExactNumber = (
    value: unknown,
    expected: number,
    fieldName: string,
): number => {
    if (value !== expected) {
        throw new TypeError(`${fieldName} must be ${String(expected)}.`);
    }
    return expected;
};

const requireExactString = <Expected extends string>(
    value: unknown,
    expected: Expected,
    fieldName: string,
): Expected => {
    if (value !== expected) {
        throw new TypeError(`${fieldName} must be ${expected}.`);
    }
    return expected;
};

const requireCanonicalUnsigned64Decimal = (
    value: unknown,
    fieldName: string,
): bigint => {
    if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
        throw new TypeError(
            `${fieldName} must be a canonical unsigned decimal string.`,
        );
    }
    const parsed = BigInt(value);
    if (parsed > maximumUnsigned64) {
        throw new RangeError(`${fieldName} exceeds u64.`);
    }
    return parsed;
};

const requireHashHex = (
    value: unknown,
    pattern: RegExp,
    byteLength: number,
    fieldName: string,
): string => {
    if (typeof value !== 'string' || !pattern.test(value)) {
        throw new TypeError(
            `${fieldName} must be a lowercase ${String(byteLength)}-byte hexadecimal digest.`,
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
            `${fieldName} must be ${expected.toString()}, received ${actual.toString()}.`,
        );
    }
};

export type ProofStorageWidthBrowserNativeBinding = Readonly<{
    absorbedLeafValueCount: bigint;
    activeColumnLdeScratchByteLength: bigint;
    artifactShake256Hex: string;
    backendProfileIdentifier: typeof proofStorageWidthProfile.backendProfileIdentifier;
    baseLeafObjectReadByteLength: 0n;
    baseLeafObjectWrittenByteLength: 0n;
    baseRootShake256Hex: string;
    canonicalArtifactByteLength: bigint;
    canonicalArtifactNonleafRangeChunkCount: bigint;
    canonicalArtifactPostleafRangeChunkCount: bigint;
    canonicalArtifactPreleafRangeChunkCount: bigint;
    custodyCleanupCompleted: true;
    custodySchemaIdentifier: typeof proofStorageWidthProfile.custodySchemaIdentifier;
    exactCandidate: Readonly<{
        firstDataModulus: typeof proofStorageWidthProfile.firstDataModulus;
        materialRadix: typeof proofStorageWidthProfile.materialRadix;
        plaintextModulus: typeof proofStorageWidthProfile.plaintextModulus;
        ringDimension: typeof proofStorageWidthProfile.ringDimension;
        rosterSize: typeof proofStorageWidthProfile.rosterSize;
    }>;
    externalCommittedTransactionCount: bigint;
    externalReadByteLength: bigint;
    externalWrittenByteLength: bigint;
    inputIdentityShake256Hex: string;
    frozenInputIdentityHashDomain: typeof proofStorageWidthProfile.frozenInputIdentityHashDomain;
    frozenInputIdentityShake256Hex: typeof proofStorageWidthProfile.frozenInputIdentityShake256Hex;
    frozenInputRecipeIdentifier: typeof proofStorageWidthProfile.frozenInputRecipeIdentifier;
    intendedReleaseRuntime: typeof proofStorageWidthProfile.intendedReleaseRuntime;
    ldeTransformCount: bigint;
    localRecordSealInvocationCount: 0n;
    manifestIdentityShake256Hex: string;
    measurementRuntime: typeof proofStorageWidthProfile.measurementRuntime;
    maximumTransactionPayloadByteLength: bigint;
    openedLeafElementByteLength: bigint;
    openedLeafRangeChunkCount: bigint;
    openedValueCount: bigint;
    persistedBaseLeafByteLength: 0n;
    persistedLdeByteLength: 0n;
    physicalObjectPeak: bigint;
    profile: ProofStorageWidthProfileBinding;
    proofObjectSealTransactionCount: 1n;
    proofPhysicalObjectCount: 1n;
    proofByteLength: bigint;
    publicColumnDerivationAlgorithm: typeof proofStorageWidthProfile.publicColumnDerivationAlgorithm;
    publicColumnInputDomain: typeof proofStorageWidthProfile.publicColumnInputDomain;
    publicColumnSeedHex: typeof proofStorageWidthProfile.publicColumnSeedHex;
    publicBaseLeafByteLength: bigint;
    publicBaseLeafColumnCount: 512;
    queriedLeafPayloadByteLength: bigint;
    recomputedCanonicalArtifactByteLength: bigint;
    sealedSecretPlaintextByteLength: 0n;
    sourceCommittedTransactionCount: bigint;
    sourceObjectSealTransactionCount: bigint;
    sourcePhysicalObjectCount: bigint;
    sourceReplayByteLength: bigint;
    storedScratchPeakByteLength: bigint;
    releaseProfileIdentifier: typeof proofStorageWidthProfile.releaseProfileIdentifier;
    widthDependentQueriedBaseOpeningByteLength: bigint;
    widthInputIdentityHashDomain: typeof proofStorageWidthProfile.widthInputIdentityHashDomain;
}>;

export const parseProofStorageWidthBrowserNativeBinding = (
    value: unknown,
): ProofStorageWidthBrowserNativeBinding => {
    const record = requireJsonObject(value, 'Native width-512 binding');
    const validated = validateProofStorageWidthResult(value);
    if (
        validated.publicBaseLeafColumnCount !==
        proofStorageWidthBrowserEvidenceProfile.representativeWidth
    ) {
        throw new Error(
            'The native browser binding is not the width-512 point.',
        );
    }
    const width = requireExactNumber(
        record.publicBaseLeafColumnCount,
        proofStorageWidthBrowserEvidenceProfile.representativeWidth,
        'publicBaseLeafColumnCount',
    ) as 512;
    const parsed = {
        absorbedLeafValueCount: requireCanonicalUnsigned64Decimal(
            record.absorbedLeafValueCountDecimal,
            'absorbedLeafValueCountDecimal',
        ),
        activeColumnLdeScratchByteLength:
            validated.activeColumnLdeScratchByteLength,
        artifactShake256Hex: requireHashHex(
            record.artifactShake256Hex,
            hash512HexPattern,
            64,
            'artifactShake256Hex',
        ),
        backendProfileIdentifier: requireExactString(
            record.backendProfileIdentifier,
            proofStorageWidthProfile.backendProfileIdentifier,
            'backendProfileIdentifier',
        ),
        baseLeafObjectReadByteLength: validated.baseLeafObjectReadByteLength,
        baseLeafObjectWrittenByteLength:
            validated.baseLeafObjectWrittenByteLength,
        baseRootShake256Hex: requireHashHex(
            record.baseRootShake256Hex,
            hash512HexPattern,
            64,
            'baseRootShake256Hex',
        ),
        canonicalArtifactByteLength: validated.canonicalArtifactByteLength,
        canonicalArtifactNonleafRangeChunkCount:
            validated.canonicalArtifactNonleafRangeChunkCount,
        canonicalArtifactPostleafRangeChunkCount:
            validated.canonicalArtifactPostleafRangeChunkCount,
        canonicalArtifactPreleafRangeChunkCount:
            validated.canonicalArtifactPreleafRangeChunkCount,
        custodyCleanupCompleted: validated.custodyCleanupCompleted,
        custodySchemaIdentifier: requireExactString(
            record.custodySchemaIdentifier,
            proofStorageWidthProfile.custodySchemaIdentifier,
            'custodySchemaIdentifier',
        ),
        exactCandidate: Object.freeze({
            firstDataModulus: proofStorageWidthProfile.firstDataModulus,
            materialRadix: proofStorageWidthProfile.materialRadix,
            plaintextModulus: proofStorageWidthProfile.plaintextModulus,
            ringDimension: proofStorageWidthProfile.ringDimension,
            rosterSize: proofStorageWidthProfile.rosterSize,
        }),
        externalCommittedTransactionCount: requireCanonicalUnsigned64Decimal(
            record.externalCommittedTransactionCountDecimal,
            'externalCommittedTransactionCountDecimal',
        ),
        externalReadByteLength: requireCanonicalUnsigned64Decimal(
            record.externalReadByteLengthDecimal,
            'externalReadByteLengthDecimal',
        ),
        externalWrittenByteLength: requireCanonicalUnsigned64Decimal(
            record.externalWrittenByteLengthDecimal,
            'externalWrittenByteLengthDecimal',
        ),
        inputIdentityShake256Hex: requireHashHex(
            record.inputIdentityShake256Hex,
            hash512HexPattern,
            64,
            'inputIdentityShake256Hex',
        ),
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
        ),
        ldeTransformCount: requireCanonicalUnsigned64Decimal(
            record.ldeTransformCountDecimal,
            'ldeTransformCountDecimal',
        ),
        localRecordSealInvocationCount:
            validated.localRecordSealInvocationCount,
        manifestIdentityShake256Hex: validated.manifestIdentityShake256Hex,
        measurementRuntime: requireExactString(
            record.measurementRuntime,
            proofStorageWidthProfile.measurementRuntime,
            'measurementRuntime',
        ),
        maximumTransactionPayloadByteLength:
            validated.maximumTransactionPayloadByteLength,
        openedLeafElementByteLength: validated.openedLeafElementByteLength,
        openedLeafRangeChunkCount: requireCanonicalUnsigned64Decimal(
            record.openedLeafRangeChunkCountDecimal,
            'openedLeafRangeChunkCountDecimal',
        ),
        openedValueCount: requireCanonicalUnsigned64Decimal(
            record.openedValueCountDecimal,
            'openedValueCountDecimal',
        ),
        persistedBaseLeafByteLength: validated.persistedBaseLeafByteLength,
        persistedLdeByteLength: validated.persistedLdeByteLength,
        physicalObjectPeak: requireCanonicalUnsigned64Decimal(
            record.physicalObjectPeakDecimal,
            'physicalObjectPeakDecimal',
        ),
        profile: validated.profile,
        proofObjectSealTransactionCount:
            validated.proofObjectSealTransactionCount,
        proofPhysicalObjectCount: validated.proofPhysicalObjectCount,
        proofByteLength: requireCanonicalUnsigned64Decimal(
            record.proofByteLengthDecimal,
            'proofByteLengthDecimal',
        ),
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
        publicBaseLeafByteLength: validated.publicBaseLeafByteLength,
        publicBaseLeafColumnCount: width,
        queriedLeafPayloadByteLength: requireCanonicalUnsigned64Decimal(
            record.queriedLeafPayloadByteLengthDecimal,
            'queriedLeafPayloadByteLengthDecimal',
        ),
        recomputedCanonicalArtifactByteLength:
            validated.recomputedCanonicalArtifactByteLength,
        sealedSecretPlaintextByteLength:
            validated.sealedSecretPlaintextByteLength,
        sourceCommittedTransactionCount:
            validated.sourceCommittedTransactionCount,
        sourceObjectSealTransactionCount:
            validated.sourceObjectSealTransactionCount,
        sourcePhysicalObjectCount: validated.sourcePhysicalObjectCount,
        sourceReplayByteLength: requireCanonicalUnsigned64Decimal(
            record.sourceReplayByteLengthDecimal,
            'sourceReplayByteLengthDecimal',
        ),
        storedScratchPeakByteLength: requireCanonicalUnsigned64Decimal(
            record.storedScratchPeakByteLengthDecimal,
            'storedScratchPeakByteLengthDecimal',
        ),
        releaseProfileIdentifier: requireExactString(
            record.releaseProfileIdentifier,
            proofStorageWidthProfile.releaseProfileIdentifier,
            'releaseProfileIdentifier',
        ),
        widthDependentQueriedBaseOpeningByteLength:
            validated.widthDependentQueriedBaseOpeningByteLength,
        widthInputIdentityHashDomain: requireExactString(
            record.widthInputIdentityHashDomain,
            proofStorageWidthProfile.widthInputIdentityHashDomain,
            'widthInputIdentityHashDomain',
        ),
    } satisfies ProofStorageWidthBrowserNativeBinding;

    requireExpectedUnsigned64(
        parsed.sourceReplayByteLength,
        representativeGeometry.sourceReplayByteLength,
        'sourceReplayByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        parsed.ldeTransformCount,
        representativeGeometry.ldeTransformCount,
        'ldeTransformCountDecimal',
    );
    requireExpectedUnsigned64(
        parsed.absorbedLeafValueCount,
        representativeGeometry.absorbedLeafValueCount,
        'absorbedLeafValueCountDecimal',
    );
    requireExpectedUnsigned64(
        parsed.openedValueCount,
        representativeGeometry.openedValueCount,
        'openedValueCountDecimal',
    );
    requireExpectedUnsigned64(
        parsed.queriedLeafPayloadByteLength,
        representativeGeometry.queriedLeafPayloadByteLength,
        'queriedLeafPayloadByteLengthDecimal',
    );
    requireExpectedUnsigned64(
        parsed.openedLeafRangeChunkCount,
        representativeGeometry.openedLeafRangeChunkCount,
        'openedLeafRangeChunkCountDecimal',
    );
    requireExpectedUnsigned64(
        parsed.physicalObjectPeak,
        representativeGeometry.physicalObjectPeak,
        'physicalObjectPeakDecimal',
    );
    if (
        parsed.externalReadByteLength === 0n ||
        parsed.externalWrittenByteLength === 0n ||
        parsed.externalCommittedTransactionCount === 0n ||
        parsed.proofByteLength === 0n ||
        parsed.physicalObjectPeak === 0n ||
        parsed.storedScratchPeakByteLength === 0n
    ) {
        throw new Error(
            'Native width-512 binding must include measured external-storage work.',
        );
    }
    if (
        parsed.proofByteLength >
            proofStorageWidthBrowserEvidenceProfile.maximumProofByteLength ||
        parsed.physicalObjectPeak >
            proofStorageWidthBrowserEvidenceProfile.maximumPhysicalObjectCount ||
        parsed.storedScratchPeakByteLength >
            proofStorageWidthBrowserEvidenceProfile.maximumStoredScratchByteLength
    ) {
        throw new Error('Native width-512 binding exceeds an absolute cap.');
    }
    return Object.freeze(parsed);
};

export type ProofStorageWidthBrowserMeasurement = Readonly<{
    absorbedLeafValueCount: bigint;
    activeColumnLdeScratchByteLength: bigint;
    arithmeticNanoseconds: bigint;
    artifactShake256Hex: string;
    backendProfileIdentifier: typeof proofStorageWidthProfile.backendProfileIdentifier;
    baseLeafObjectReadByteLength: 0n;
    baseLeafObjectWrittenByteLength: 0n;
    baseRootShake256Hex: string;
    canonicalArtifactByteLength: bigint;
    canonicalArtifactNonleafRangeChunkCount: bigint;
    canonicalArtifactPostleafRangeChunkCount: bigint;
    canonicalArtifactPreleafRangeChunkCount: bigint;
    coordinatorNanoseconds: bigint;
    copiedBufferPeakByteLength: bigint;
    custodyCleanupCompleted: true;
    custodyModel: 'bounded-external-storage-replay';
    custodySchemaIdentifier: typeof proofStorageWidthProfile.custodySchemaIdentifier;
    exactCandidate: Readonly<{
        firstDataModulus: typeof proofStorageWidthProfile.firstDataModulus;
        materialRadix: typeof proofStorageWidthProfile.materialRadix;
        plaintextModulus: 257;
        ringDimension: 32_768;
        rosterSize: 10;
    }>;
    externalCommittedCreateTransactionCount: bigint;
    externalCommittedDeleteTransactionCount: bigint;
    externalCommittedReadTransactionCount: bigint;
    externalCommittedTransactionCount: bigint;
    externalCommittedSealTransactionCount: bigint;
    externalCommittedWriteTransactionCount: bigint;
    externalReadByteLength: bigint;
    externalStorageWaitNanoseconds: bigint;
    externalWrittenByteLength: bigint;
    formatVersion: 1;
    frozenInputIdentityHashDomain: typeof proofStorageWidthProfile.frozenInputIdentityHashDomain;
    frozenInputIdentityShake256Hex: typeof proofStorageWidthProfile.frozenInputIdentityShake256Hex;
    frozenInputRecipeIdentifier: typeof proofStorageWidthProfile.frozenInputRecipeIdentifier;
    inputIdentityShake256Hex: string;
    intendedReleaseRuntime: typeof proofStorageWidthProfile.intendedReleaseRuntime;
    ldeTransformCount: bigint;
    localRecordSealInvocationCount: 0n;
    manifestIdentityShake256Hex: string;
    measurementRuntime: 'desktop-browser-wasm';
    maximumArithmeticSliceNanoseconds: bigint;
    maximumTransactionPayloadByteLength: 49_152n;
    openedLeafRangeChunkCount: bigint;
    openedLeafElementByteLength: bigint;
    openedValueCount: bigint;
    operationElapsedNanoseconds: bigint;
    operationFinishedAtUnixMilliseconds: bigint;
    operationStartedAtUnixMilliseconds: bigint;
    persistedBaseLeafByteLength: 0n;
    persistedLdeByteLength: 0n;
    physicalObjectPeak: bigint;
    proofObjectSealTransactionCount: 1n;
    proofPhysicalObjectCount: 1n;
    providerCleanupInspectionTransactionCount: 2n;
    providerRecordPeak: bigint;
    providerDataRecordPeak: bigint;
    providerMetadataRecordPeak: bigint;
    providerMetadataWrittenByteLength: bigint;
    providerMutationTransactionCount: bigint;
    providerReadTransactionCount: bigint;
    providerTransactionCount: bigint;
    proofByteLength: bigint;
    publicColumnDerivationAlgorithm: typeof proofStorageWidthProfile.publicColumnDerivationAlgorithm;
    publicColumnInputDomain: typeof proofStorageWidthProfile.publicColumnInputDomain;
    publicColumnSeedHex: typeof proofStorageWidthProfile.publicColumnSeedHex;
    publicBaseLeafByteLength: bigint;
    publicBaseLeafColumnCount: 512;
    queriedLeafPayloadByteLength: bigint;
    recomputedCanonicalArtifactByteLength: bigint;
    sealedSecretPlaintextByteLength: 0n;
    sourceCommittedTransactionCount: bigint;
    sourceObjectSealTransactionCount: bigint;
    sourcePhysicalObjectCount: bigint;
    sourceReplayByteLength: bigint;
    storedScratchPeakByteLength: bigint;
    releaseProfileIdentifier: typeof proofStorageWidthProfile.releaseProfileIdentifier;
    wasmLinearMemoryEndByteLength: bigint;
    wasmLinearMemoryPeakByteLength: bigint;
    wasmLinearMemoryStartByteLength: bigint;
    wasmSha256Hex: string;
    workerYieldCount: bigint;
    workerYieldNanoseconds: bigint;
    widthDependentQueriedBaseOpeningByteLength: bigint;
    widthInputIdentityHashDomain: typeof proofStorageWidthProfile.widthInputIdentityHashDomain;
}>;

export const parseProofStorageWidthBrowserMeasurement = (
    value: unknown,
): ProofStorageWidthBrowserMeasurement => {
    const record = requireJsonObject(
        value,
        'Proof-storage width browser measurement',
    );
    requireExactNumber(record.formatVersion, 1, 'formatVersion');
    if (record.custodyModel !== 'bounded-external-storage-replay') {
        throw new TypeError(
            'custodyModel must be bounded-external-storage-replay.',
        );
    }
    const backendProfileIdentifier = requireExactString(
        record.backendProfileIdentifier,
        proofStorageWidthProfile.backendProfileIdentifier,
        'backendProfileIdentifier',
    );
    const custodySchemaIdentifier = requireExactString(
        record.custodySchemaIdentifier,
        proofStorageWidthProfile.custodySchemaIdentifier,
        'custodySchemaIdentifier',
    );
    const publicColumnDerivationAlgorithm = requireExactString(
        record.publicColumnDerivationAlgorithm,
        proofStorageWidthProfile.publicColumnDerivationAlgorithm,
        'publicColumnDerivationAlgorithm',
    );
    const publicColumnInputDomain = requireExactString(
        record.publicColumnInputDomain,
        proofStorageWidthProfile.publicColumnInputDomain,
        'publicColumnInputDomain',
    );
    const publicColumnSeedHex = requireExactString(
        record.publicColumnSeedHex,
        proofStorageWidthProfile.publicColumnSeedHex,
        'publicColumnSeedHex',
    );
    const releaseProfileIdentifier = requireExactString(
        record.releaseProfileIdentifier,
        proofStorageWidthProfile.releaseProfileIdentifier,
        'releaseProfileIdentifier',
    );
    const frozenInputIdentityHashDomain = requireExactString(
        record.frozenInputIdentityHashDomain,
        proofStorageWidthProfile.frozenInputIdentityHashDomain,
        'frozenInputIdentityHashDomain',
    );
    const frozenInputIdentityShake256Hex = requireExactString(
        record.frozenInputIdentityShake256Hex,
        proofStorageWidthProfile.frozenInputIdentityShake256Hex,
        'frozenInputIdentityShake256Hex',
    );
    const frozenInputRecipeIdentifier = requireExactString(
        record.frozenInputRecipeIdentifier,
        proofStorageWidthProfile.frozenInputRecipeIdentifier,
        'frozenInputRecipeIdentifier',
    );
    const intendedReleaseRuntime = requireExactString(
        record.intendedReleaseRuntime,
        proofStorageWidthProfile.intendedReleaseRuntime,
        'intendedReleaseRuntime',
    );
    const measurementRuntime = requireExactString(
        record.measurementRuntime,
        'desktop-browser-wasm',
        'measurementRuntime',
    );
    const widthInputIdentityHashDomain = requireExactString(
        record.widthInputIdentityHashDomain,
        proofStorageWidthProfile.widthInputIdentityHashDomain,
        'widthInputIdentityHashDomain',
    );
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
    const width = requireExactNumber(
        record.publicBaseLeafColumnCount,
        proofStorageWidthBrowserEvidenceProfile.representativeWidth,
        'publicBaseLeafColumnCount',
    ) as 512;
    const unsignedFields = {
        absorbedLeafValueCount: 'absorbedLeafValueCountDecimal',
        activeColumnLdeScratchByteLength:
            'activeColumnLdeScratchByteLengthDecimal',
        arithmeticNanoseconds: 'arithmeticNanosecondsDecimal',
        coordinatorNanoseconds: 'coordinatorNanosecondsDecimal',
        copiedBufferPeakByteLength: 'copiedBufferPeakByteLengthDecimal',
        baseLeafObjectReadByteLength: 'baseLeafObjectReadByteLengthDecimal',
        baseLeafObjectWrittenByteLength:
            'baseLeafObjectWrittenByteLengthDecimal',
        canonicalArtifactByteLength: 'canonicalArtifactByteLengthDecimal',
        canonicalArtifactNonleafRangeChunkCount:
            'canonicalArtifactNonleafRangeChunkCountDecimal',
        canonicalArtifactPostleafRangeChunkCount:
            'canonicalArtifactPostleafRangeChunkCountDecimal',
        canonicalArtifactPreleafRangeChunkCount:
            'canonicalArtifactPreleafRangeChunkCountDecimal',
        externalCommittedDeleteTransactionCount:
            'externalCommittedDeleteTransactionCountDecimal',
        externalCommittedCreateTransactionCount:
            'externalCommittedCreateTransactionCountDecimal',
        externalCommittedReadTransactionCount:
            'externalCommittedReadTransactionCountDecimal',
        externalCommittedTransactionCount:
            'externalCommittedTransactionCountDecimal',
        externalCommittedSealTransactionCount:
            'externalCommittedSealTransactionCountDecimal',
        externalCommittedWriteTransactionCount:
            'externalCommittedWriteTransactionCountDecimal',
        externalReadByteLength: 'externalReadByteLengthDecimal',
        externalStorageWaitNanoseconds: 'externalStorageWaitNanosecondsDecimal',
        externalWrittenByteLength: 'externalWrittenByteLengthDecimal',
        ldeTransformCount: 'ldeTransformCountDecimal',
        localRecordSealInvocationCount: 'localRecordSealInvocationCountDecimal',
        maximumArithmeticSliceNanoseconds:
            'maximumArithmeticSliceNanosecondsDecimal',
        maximumTransactionPayloadByteLength:
            'maximumTransactionPayloadByteLengthDecimal',
        openedLeafRangeChunkCount: 'openedLeafRangeChunkCountDecimal',
        openedLeafElementByteLength: 'openedLeafElementByteLengthDecimal',
        openedValueCount: 'openedValueCountDecimal',
        operationElapsedNanoseconds: 'operationElapsedNanosecondsDecimal',
        operationFinishedAtUnixMilliseconds:
            'operationFinishedAtUnixMilliseconds',
        operationStartedAtUnixMilliseconds:
            'operationStartedAtUnixMilliseconds',
        persistedLdeByteLength: 'persistedLdeByteLengthDecimal',
        persistedBaseLeafByteLength: 'persistedBaseLeafByteLengthDecimal',
        physicalObjectPeak: 'physicalObjectPeakDecimal',
        proofObjectSealTransactionCount:
            'proofObjectSealTransactionCountDecimal',
        proofPhysicalObjectCount: 'proofPhysicalObjectCountDecimal',
        providerCleanupInspectionTransactionCount:
            'providerCleanupInspectionTransactionCountDecimal',
        providerDataRecordPeak: 'providerDataRecordPeakDecimal',
        providerMetadataRecordPeak: 'providerMetadataRecordPeakDecimal',
        providerMetadataWrittenByteLength:
            'providerMetadataWrittenByteLengthDecimal',
        providerMutationTransactionCount:
            'providerMutationTransactionCountDecimal',
        providerReadTransactionCount: 'providerReadTransactionCountDecimal',
        providerRecordPeak: 'providerRecordPeakDecimal',
        providerTransactionCount: 'providerTransactionCountDecimal',
        proofByteLength: 'proofByteLengthDecimal',
        publicBaseLeafByteLength: 'publicBaseLeafByteLengthDecimal',
        queriedLeafPayloadByteLength: 'queriedLeafPayloadByteLengthDecimal',
        recomputedCanonicalArtifactByteLength:
            'recomputedCanonicalArtifactByteLengthDecimal',
        sealedSecretPlaintextByteLength:
            'sealedSecretPlaintextByteLengthDecimal',
        sourceCommittedTransactionCount:
            'sourceCommittedTransactionCountDecimal',
        sourceObjectSealTransactionCount:
            'sourceObjectSealTransactionCountDecimal',
        sourcePhysicalObjectCount: 'sourcePhysicalObjectCountDecimal',
        sourceReplayByteLength: 'sourceReplayByteLengthDecimal',
        storedScratchPeakByteLength: 'storedScratchPeakByteLengthDecimal',
        wasmLinearMemoryEndByteLength: 'wasmLinearMemoryEndByteLengthDecimal',
        wasmLinearMemoryPeakByteLength: 'wasmLinearMemoryPeakByteLengthDecimal',
        wasmLinearMemoryStartByteLength:
            'wasmLinearMemoryStartByteLengthDecimal',
        workerYieldCount: 'workerYieldCountDecimal',
        workerYieldNanoseconds: 'workerYieldNanosecondsDecimal',
        widthDependentQueriedBaseOpeningByteLength:
            'widthDependentQueriedBaseOpeningByteLengthDecimal',
    } as const;
    const parsedUnsigned = Object.fromEntries(
        Object.entries(unsignedFields).map(([propertyName, fieldName]) => [
            propertyName,
            requireCanonicalUnsigned64Decimal(record[fieldName], fieldName),
        ]),
    ) as Record<keyof typeof unsignedFields, bigint>;

    requireExpectedUnsigned64(
        parsedUnsigned.sourceReplayByteLength,
        representativeGeometry.sourceReplayByteLength,
        unsignedFields.sourceReplayByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.publicBaseLeafByteLength,
        representativeGeometry.publicBaseLeafByteLength,
        unsignedFields.publicBaseLeafByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.openedLeafElementByteLength,
        representativeGeometry.openedLeafElementByteLength,
        unsignedFields.openedLeafElementByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.activeColumnLdeScratchByteLength,
        representativeGeometry.activeColumnLdeScratchByteLength,
        unsignedFields.activeColumnLdeScratchByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.ldeTransformCount,
        representativeGeometry.ldeTransformCount,
        unsignedFields.ldeTransformCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.absorbedLeafValueCount,
        representativeGeometry.absorbedLeafValueCount,
        unsignedFields.absorbedLeafValueCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.openedValueCount,
        representativeGeometry.openedValueCount,
        unsignedFields.openedValueCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.queriedLeafPayloadByteLength,
        representativeGeometry.queriedLeafPayloadByteLength,
        unsignedFields.queriedLeafPayloadByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.openedLeafRangeChunkCount,
        representativeGeometry.openedLeafRangeChunkCount,
        unsignedFields.openedLeafRangeChunkCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.maximumTransactionPayloadByteLength,
        proofStorageWidthBrowserEvidenceProfile.maximumTransactionPayloadByteLength,
        unsignedFields.maximumTransactionPayloadByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.persistedLdeByteLength,
        0n,
        unsignedFields.persistedLdeByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.persistedBaseLeafByteLength,
        0n,
        unsignedFields.persistedBaseLeafByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.baseLeafObjectReadByteLength,
        0n,
        unsignedFields.baseLeafObjectReadByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.baseLeafObjectWrittenByteLength,
        0n,
        unsignedFields.baseLeafObjectWrittenByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.localRecordSealInvocationCount,
        0n,
        unsignedFields.localRecordSealInvocationCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.sealedSecretPlaintextByteLength,
        0n,
        unsignedFields.sealedSecretPlaintextByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.sourcePhysicalObjectCount,
        BigInt(width),
        unsignedFields.sourcePhysicalObjectCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.proofPhysicalObjectCount,
        1n,
        unsignedFields.proofPhysicalObjectCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.sourceObjectSealTransactionCount,
        BigInt(width),
        unsignedFields.sourceObjectSealTransactionCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.proofObjectSealTransactionCount,
        1n,
        unsignedFields.proofObjectSealTransactionCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.providerCleanupInspectionTransactionCount,
        2n,
        unsignedFields.providerCleanupInspectionTransactionCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.sourceCommittedTransactionCount,
        24n * BigInt(width),
        unsignedFields.sourceCommittedTransactionCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.widthDependentQueriedBaseOpeningByteLength,
        representativeGeometry.widthDependentQueriedBaseOpeningByteLength,
        unsignedFields.widthDependentQueriedBaseOpeningByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.canonicalArtifactByteLength,
        parsedUnsigned.recomputedCanonicalArtifactByteLength,
        unsignedFields.canonicalArtifactByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.proofByteLength,
        parsedUnsigned.recomputedCanonicalArtifactByteLength,
        unsignedFields.proofByteLength,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.canonicalArtifactNonleafRangeChunkCount,
        parsedUnsigned.canonicalArtifactPreleafRangeChunkCount +
            parsedUnsigned.canonicalArtifactPostleafRangeChunkCount,
        unsignedFields.canonicalArtifactNonleafRangeChunkCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.physicalObjectPeak,
        representativeGeometry.physicalObjectPeak,
        unsignedFields.physicalObjectPeak,
    );
    const transactionBreakdown =
        parsedUnsigned.externalCommittedCreateTransactionCount +
        parsedUnsigned.externalCommittedReadTransactionCount +
        parsedUnsigned.externalCommittedSealTransactionCount +
        parsedUnsigned.externalCommittedWriteTransactionCount +
        parsedUnsigned.externalCommittedDeleteTransactionCount;
    requireExpectedUnsigned64(
        parsedUnsigned.externalCommittedTransactionCount,
        transactionBreakdown,
        unsignedFields.externalCommittedTransactionCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.providerTransactionCount,
        parsedUnsigned.providerMutationTransactionCount +
            parsedUnsigned.providerReadTransactionCount +
            parsedUnsigned.providerCleanupInspectionTransactionCount,
        unsignedFields.providerTransactionCount,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.providerMetadataRecordPeak,
        parsedUnsigned.physicalObjectPeak,
        unsignedFields.providerMetadataRecordPeak,
    );
    requireExpectedUnsigned64(
        parsedUnsigned.providerRecordPeak,
        parsedUnsigned.providerDataRecordPeak +
            parsedUnsigned.providerMetadataRecordPeak,
        unsignedFields.providerRecordPeak,
    );
    const classifiedNanoseconds =
        parsedUnsigned.arithmeticNanoseconds +
        parsedUnsigned.externalStorageWaitNanoseconds +
        parsedUnsigned.workerYieldNanoseconds +
        parsedUnsigned.coordinatorNanoseconds;
    requireExpectedUnsigned64(
        parsedUnsigned.operationElapsedNanoseconds,
        classifiedNanoseconds,
        unsignedFields.operationElapsedNanoseconds,
    );
    if (
        parsedUnsigned.operationFinishedAtUnixMilliseconds <
        parsedUnsigned.operationStartedAtUnixMilliseconds
    ) {
        throw new Error('The browser operation window is reversed.');
    }
    if (
        parsedUnsigned.externalReadByteLength === 0n ||
        parsedUnsigned.externalWrittenByteLength === 0n ||
        parsedUnsigned.externalCommittedTransactionCount === 0n ||
        parsedUnsigned.externalCommittedCreateTransactionCount === 0n ||
        parsedUnsigned.externalCommittedReadTransactionCount === 0n ||
        parsedUnsigned.externalCommittedSealTransactionCount === 0n ||
        parsedUnsigned.externalCommittedWriteTransactionCount === 0n ||
        parsedUnsigned.externalCommittedDeleteTransactionCount === 0n ||
        parsedUnsigned.proofByteLength === 0n ||
        parsedUnsigned.physicalObjectPeak === 0n ||
        parsedUnsigned.providerRecordPeak === 0n ||
        parsedUnsigned.providerDataRecordPeak === 0n ||
        parsedUnsigned.providerCleanupInspectionTransactionCount === 0n ||
        parsedUnsigned.providerMetadataRecordPeak === 0n ||
        parsedUnsigned.providerMetadataWrittenByteLength === 0n ||
        parsedUnsigned.providerMutationTransactionCount === 0n ||
        parsedUnsigned.providerReadTransactionCount === 0n ||
        parsedUnsigned.providerTransactionCount === 0n ||
        parsedUnsigned.storedScratchPeakByteLength === 0n ||
        parsedUnsigned.workerYieldCount === 0n ||
        parsedUnsigned.maximumArithmeticSliceNanoseconds === 0n ||
        parsedUnsigned.copiedBufferPeakByteLength === 0n ||
        parsedUnsigned.wasmLinearMemoryPeakByteLength === 0n
    ) {
        throw new Error(
            'The browser measurement omitted external custody or worker-yield work.',
        );
    }
    if (
        parsedUnsigned.maximumArithmeticSliceNanoseconds >
        parsedUnsigned.arithmeticNanoseconds
    ) {
        throw new Error(
            'The maximum arithmetic slice exceeds total arithmetic time.',
        );
    }
    if (
        parsedUnsigned.copiedBufferPeakByteLength >
        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
    ) {
        throw new Error(
            'The browser measurement exceeds the copied-buffer bound.',
        );
    }
    requireExpectedUnsigned64(
        parsedUnsigned.copiedBufferPeakByteLength,
        proofStorageWidthProfile.externalMemoryCopiedBufferByteLengthCeiling,
        unsignedFields.copiedBufferPeakByteLength,
    );
    if (
        parsedUnsigned.physicalObjectPeak >
            proofStorageWidthBrowserEvidenceProfile.maximumPhysicalObjectCount ||
        parsedUnsigned.proofByteLength >
            proofStorageWidthBrowserEvidenceProfile.maximumProofByteLength ||
        parsedUnsigned.storedScratchPeakByteLength >
            proofStorageWidthBrowserEvidenceProfile.maximumStoredScratchByteLength
    ) {
        throw new Error(
            'The browser measurement exceeds an external-custody cap.',
        );
    }
    if (parsedUnsigned.providerRecordPeak < parsedUnsigned.physicalObjectPeak) {
        throw new Error(
            'The provider record peak cannot be smaller than the external-object peak.',
        );
    }
    if (
        parsedUnsigned.providerTransactionCount <
        parsedUnsigned.externalCommittedTransactionCount
    ) {
        throw new Error(
            'The provider transaction count cannot be smaller than the logical custody count.',
        );
    }
    if (record.custodyCleanupCompleted !== true) {
        throw new Error('custodyCleanupCompleted must be true.');
    }
    if (
        parsedUnsigned.wasmLinearMemoryStartByteLength >
            parsedUnsigned.wasmLinearMemoryPeakByteLength ||
        parsedUnsigned.wasmLinearMemoryEndByteLength >
            parsedUnsigned.wasmLinearMemoryPeakByteLength ||
        parsedUnsigned.wasmLinearMemoryPeakByteLength >
            proofStorageWidthBrowserEvidenceProfile.maximumWasmLinearMemoryByteLength
    ) {
        throw new Error(
            'The browser measurement has an invalid or over-cap WebAssembly memory window.',
        );
    }
    return Object.freeze({
        ...parsedUnsigned,
        artifactShake256Hex: requireHashHex(
            record.artifactShake256Hex,
            hash512HexPattern,
            64,
            'artifactShake256Hex',
        ),
        backendProfileIdentifier,
        baseLeafObjectReadByteLength: 0n,
        baseLeafObjectWrittenByteLength: 0n,
        baseRootShake256Hex: requireHashHex(
            record.baseRootShake256Hex,
            hash512HexPattern,
            64,
            'baseRootShake256Hex',
        ),
        custodyModel: 'bounded-external-storage-replay',
        custodyCleanupCompleted: true,
        custodySchemaIdentifier,
        exactCandidate: Object.freeze({
            firstDataModulus: proofStorageWidthProfile.firstDataModulus,
            materialRadix: proofStorageWidthProfile.materialRadix,
            plaintextModulus: 257,
            ringDimension: 32_768,
            rosterSize: 10,
        }),
        formatVersion: 1,
        frozenInputIdentityHashDomain,
        frozenInputIdentityShake256Hex,
        frozenInputRecipeIdentifier,
        inputIdentityShake256Hex: requireHashHex(
            record.inputIdentityShake256Hex,
            hash512HexPattern,
            64,
            'inputIdentityShake256Hex',
        ),
        intendedReleaseRuntime,
        localRecordSealInvocationCount: 0n,
        manifestIdentityShake256Hex: requireHashHex(
            record.manifestIdentityShake256Hex,
            hash512HexPattern,
            64,
            'manifestIdentityShake256Hex',
        ),
        measurementRuntime,
        maximumTransactionPayloadByteLength: 49_152n,
        persistedBaseLeafByteLength: 0n,
        persistedLdeByteLength: 0n,
        proofObjectSealTransactionCount: 1n,
        proofPhysicalObjectCount: 1n,
        providerCleanupInspectionTransactionCount: 2n,
        publicColumnDerivationAlgorithm,
        publicColumnInputDomain,
        publicColumnSeedHex,
        publicBaseLeafColumnCount: width,
        releaseProfileIdentifier,
        sealedSecretPlaintextByteLength: 0n,
        wasmSha256Hex: requireHashHex(
            record.wasmSha256Hex,
            hash256HexPattern,
            32,
            'wasmSha256Hex',
        ),
        widthInputIdentityHashDomain,
    });
};

export const serializeProofStorageWidthBrowserMeasurement = (
    measurement: ProofStorageWidthBrowserMeasurement,
): Readonly<Record<string, unknown>> =>
    Object.freeze({
        absorbedLeafValueCountDecimal:
            measurement.absorbedLeafValueCount.toString(),
        activeColumnLdeScratchByteLengthDecimal:
            measurement.activeColumnLdeScratchByteLength.toString(),
        arithmeticNanosecondsDecimal:
            measurement.arithmeticNanoseconds.toString(),
        artifactShake256Hex: measurement.artifactShake256Hex,
        backendProfileIdentifier: measurement.backendProfileIdentifier,
        baseLeafObjectReadByteLengthDecimal:
            measurement.baseLeafObjectReadByteLength.toString(),
        baseLeafObjectWrittenByteLengthDecimal:
            measurement.baseLeafObjectWrittenByteLength.toString(),
        baseRootShake256Hex: measurement.baseRootShake256Hex,
        canonicalArtifactByteLengthDecimal:
            measurement.canonicalArtifactByteLength.toString(),
        canonicalArtifactNonleafRangeChunkCountDecimal:
            measurement.canonicalArtifactNonleafRangeChunkCount.toString(),
        canonicalArtifactPostleafRangeChunkCountDecimal:
            measurement.canonicalArtifactPostleafRangeChunkCount.toString(),
        canonicalArtifactPreleafRangeChunkCountDecimal:
            measurement.canonicalArtifactPreleafRangeChunkCount.toString(),
        coordinatorNanosecondsDecimal:
            measurement.coordinatorNanoseconds.toString(),
        copiedBufferPeakByteLengthDecimal:
            measurement.copiedBufferPeakByteLength.toString(),
        custodyModel: measurement.custodyModel,
        custodyCleanupCompleted: measurement.custodyCleanupCompleted,
        custodySchemaIdentifier: measurement.custodySchemaIdentifier,
        exactCandidate: measurement.exactCandidate,
        externalCommittedDeleteTransactionCountDecimal:
            measurement.externalCommittedDeleteTransactionCount.toString(),
        externalCommittedCreateTransactionCountDecimal:
            measurement.externalCommittedCreateTransactionCount.toString(),
        externalCommittedReadTransactionCountDecimal:
            measurement.externalCommittedReadTransactionCount.toString(),
        externalCommittedTransactionCountDecimal:
            measurement.externalCommittedTransactionCount.toString(),
        externalCommittedSealTransactionCountDecimal:
            measurement.externalCommittedSealTransactionCount.toString(),
        externalCommittedWriteTransactionCountDecimal:
            measurement.externalCommittedWriteTransactionCount.toString(),
        externalReadByteLengthDecimal:
            measurement.externalReadByteLength.toString(),
        externalStorageWaitNanosecondsDecimal:
            measurement.externalStorageWaitNanoseconds.toString(),
        externalWrittenByteLengthDecimal:
            measurement.externalWrittenByteLength.toString(),
        formatVersion: measurement.formatVersion,
        frozenInputIdentityHashDomain:
            measurement.frozenInputIdentityHashDomain,
        frozenInputIdentityShake256Hex:
            measurement.frozenInputIdentityShake256Hex,
        frozenInputRecipeIdentifier: measurement.frozenInputRecipeIdentifier,
        inputIdentityShake256Hex: measurement.inputIdentityShake256Hex,
        intendedReleaseRuntime: measurement.intendedReleaseRuntime,
        ldeTransformCountDecimal: measurement.ldeTransformCount.toString(),
        localRecordSealInvocationCountDecimal:
            measurement.localRecordSealInvocationCount.toString(),
        manifestIdentityShake256Hex: measurement.manifestIdentityShake256Hex,
        measurementRuntime: measurement.measurementRuntime,
        maximumArithmeticSliceNanosecondsDecimal:
            measurement.maximumArithmeticSliceNanoseconds.toString(),
        maximumTransactionPayloadByteLengthDecimal:
            measurement.maximumTransactionPayloadByteLength.toString(),
        openedLeafRangeChunkCountDecimal:
            measurement.openedLeafRangeChunkCount.toString(),
        openedLeafElementByteLengthDecimal:
            measurement.openedLeafElementByteLength.toString(),
        openedValueCountDecimal: measurement.openedValueCount.toString(),
        operationElapsedNanosecondsDecimal:
            measurement.operationElapsedNanoseconds.toString(),
        operationFinishedAtUnixMilliseconds:
            measurement.operationFinishedAtUnixMilliseconds.toString(),
        operationStartedAtUnixMilliseconds:
            measurement.operationStartedAtUnixMilliseconds.toString(),
        persistedBaseLeafByteLengthDecimal:
            measurement.persistedBaseLeafByteLength.toString(),
        persistedLdeByteLengthDecimal:
            measurement.persistedLdeByteLength.toString(),
        physicalObjectPeakDecimal: measurement.physicalObjectPeak.toString(),
        proofObjectSealTransactionCountDecimal:
            measurement.proofObjectSealTransactionCount.toString(),
        proofPhysicalObjectCountDecimal:
            measurement.proofPhysicalObjectCount.toString(),
        providerCleanupInspectionTransactionCountDecimal:
            measurement.providerCleanupInspectionTransactionCount.toString(),
        providerDataRecordPeakDecimal:
            measurement.providerDataRecordPeak.toString(),
        providerMetadataRecordPeakDecimal:
            measurement.providerMetadataRecordPeak.toString(),
        providerMetadataWrittenByteLengthDecimal:
            measurement.providerMetadataWrittenByteLength.toString(),
        providerMutationTransactionCountDecimal:
            measurement.providerMutationTransactionCount.toString(),
        providerReadTransactionCountDecimal:
            measurement.providerReadTransactionCount.toString(),
        proofByteLengthDecimal: measurement.proofByteLength.toString(),
        providerRecordPeakDecimal: measurement.providerRecordPeak.toString(),
        providerTransactionCountDecimal:
            measurement.providerTransactionCount.toString(),
        publicColumnDerivationAlgorithm:
            measurement.publicColumnDerivationAlgorithm,
        publicColumnInputDomain: measurement.publicColumnInputDomain,
        publicColumnSeedHex: measurement.publicColumnSeedHex,
        publicBaseLeafByteLengthDecimal:
            measurement.publicBaseLeafByteLength.toString(),
        publicBaseLeafColumnCount: measurement.publicBaseLeafColumnCount,
        queriedLeafPayloadByteLengthDecimal:
            measurement.queriedLeafPayloadByteLength.toString(),
        recomputedCanonicalArtifactByteLengthDecimal:
            measurement.recomputedCanonicalArtifactByteLength.toString(),
        sourceReplayByteLengthDecimal:
            measurement.sourceReplayByteLength.toString(),
        storedScratchPeakByteLengthDecimal:
            measurement.storedScratchPeakByteLength.toString(),
        releaseProfileIdentifier: measurement.releaseProfileIdentifier,
        sealedSecretPlaintextByteLengthDecimal:
            measurement.sealedSecretPlaintextByteLength.toString(),
        sourceCommittedTransactionCountDecimal:
            measurement.sourceCommittedTransactionCount.toString(),
        sourceObjectSealTransactionCountDecimal:
            measurement.sourceObjectSealTransactionCount.toString(),
        sourcePhysicalObjectCountDecimal:
            measurement.sourcePhysicalObjectCount.toString(),
        wasmLinearMemoryEndByteLengthDecimal:
            measurement.wasmLinearMemoryEndByteLength.toString(),
        wasmLinearMemoryPeakByteLengthDecimal:
            measurement.wasmLinearMemoryPeakByteLength.toString(),
        wasmLinearMemoryStartByteLengthDecimal:
            measurement.wasmLinearMemoryStartByteLength.toString(),
        wasmSha256Hex: measurement.wasmSha256Hex,
        workerYieldCountDecimal: measurement.workerYieldCount.toString(),
        workerYieldNanosecondsDecimal:
            measurement.workerYieldNanoseconds.toString(),
        widthDependentQueriedBaseOpeningByteLengthDecimal:
            measurement.widthDependentQueriedBaseOpeningByteLength.toString(),
        widthInputIdentityHashDomain: measurement.widthInputIdentityHashDomain,
    });

export const requireProofStorageWidthBrowserNativeMatch = (
    measurement: ProofStorageWidthBrowserMeasurement,
    nativeBinding: ProofStorageWidthBrowserNativeBinding,
): void => {
    const exactFields = [
        'absorbedLeafValueCount',
        'activeColumnLdeScratchByteLength',
        'artifactShake256Hex',
        'backendProfileIdentifier',
        'baseLeafObjectReadByteLength',
        'baseLeafObjectWrittenByteLength',
        'baseRootShake256Hex',
        'canonicalArtifactByteLength',
        'canonicalArtifactNonleafRangeChunkCount',
        'canonicalArtifactPostleafRangeChunkCount',
        'canonicalArtifactPreleafRangeChunkCount',
        'custodyCleanupCompleted',
        'custodySchemaIdentifier',
        'externalCommittedTransactionCount',
        'externalReadByteLength',
        'externalWrittenByteLength',
        'frozenInputIdentityHashDomain',
        'frozenInputIdentityShake256Hex',
        'frozenInputRecipeIdentifier',
        'inputIdentityShake256Hex',
        'intendedReleaseRuntime',
        'ldeTransformCount',
        'localRecordSealInvocationCount',
        'manifestIdentityShake256Hex',
        'maximumTransactionPayloadByteLength',
        'openedLeafElementByteLength',
        'openedLeafRangeChunkCount',
        'openedValueCount',
        'persistedBaseLeafByteLength',
        'persistedLdeByteLength',
        'physicalObjectPeak',
        'proofObjectSealTransactionCount',
        'proofPhysicalObjectCount',
        'proofByteLength',
        'publicColumnDerivationAlgorithm',
        'publicColumnInputDomain',
        'publicColumnSeedHex',
        'publicBaseLeafByteLength',
        'publicBaseLeafColumnCount',
        'queriedLeafPayloadByteLength',
        'recomputedCanonicalArtifactByteLength',
        'sealedSecretPlaintextByteLength',
        'sourceCommittedTransactionCount',
        'sourceObjectSealTransactionCount',
        'sourcePhysicalObjectCount',
        'sourceReplayByteLength',
        'storedScratchPeakByteLength',
        'releaseProfileIdentifier',
        'widthDependentQueriedBaseOpeningByteLength',
        'widthInputIdentityHashDomain',
    ] as const;
    for (const fieldName of exactFields) {
        if (measurement[fieldName] !== nativeBinding[fieldName]) {
            throw new Error(
                `The browser width-512 ${fieldName} does not match the native point.`,
            );
        }
    }
    for (const candidateField of [
        'firstDataModulus',
        'materialRadix',
        'plaintextModulus',
        'ringDimension',
        'rosterSize',
    ] as const) {
        if (
            measurement.exactCandidate[candidateField] !==
            nativeBinding.exactCandidate[candidateField]
        ) {
            throw new Error(
                `The browser width-512 exactCandidate.${candidateField} does not match the native point.`,
            );
        }
    }
};
