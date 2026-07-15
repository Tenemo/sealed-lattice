import { shake256 } from '@noble/hashes/sha3.js';

const canonicalTupleSchemaIdentifier = 0x0001;
const canonicalTupleVersion = 1;
const runtimeAssetReferenceSchemaIdentifier = 0x1801;
const runtimeBuildManifestSchemaIdentifier = 0x1802;
const checkpointRandomUseProfileSchemaIdentifier = 0x1806;
const checkpointBoundaryProfileSchemaIdentifier = 0x1807;
const runtimeOperationProfileSchemaIdentifier = 0x1808;
const suiteRecordSchemaIdentifier = 0x0118;
const suiteArtifactReferenceSchemaIdentifier = 0x0117;
const protocolVersion = 1;
const maximumRuntimeBuildManifestByteLength = 65_536;
const maximumCopiedExecutableAssetByteLength = 1_572_864;
const maximumFoundationVariableValueByteLength = 8 * 1024 * 1024 - 4;
const maximumCanonicalListCount = 4_096;
const hashByteLength = 64;
const requiredSuiteArtifactCount = 6;
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const textEncoder = new TextEncoder();

const canonicalItemTypes = {
    rawBytes: 0x01,
    ascii: 0x02,
    unsigned16: 0x03,
    unsigned32: 0x04,
    unsigned64: 0x05,
    hash512: 0x06,
    nestedTuple: 0x09,
    homogeneousList: 0x0e,
} as const;

export type RuntimeAssetRole = 1 | 2 | 3 | 4;

export type RuntimeAssetReference = Readonly<{
    assetHash: Uint8Array;
    assetRole: RuntimeAssetRole;
    byteLength: bigint;
    canonicalPath: string;
}>;

export type CheckpointRandomUseProfile = Readonly<{
    family: number;
    purpose: number;
}>;

export type CheckpointBoundaryProfile = Readonly<{
    orderedRandomUses: readonly CheckpointRandomUseProfile[];
    safeBoundaryOrdinal: number;
    stateSchemaIdentifier: number;
}>;

export type RuntimeOperationProfile = Readonly<{
    operationKind: number;
    safeBoundaries: readonly CheckpointBoundaryProfile[];
}>;

export type RuntimeBuildManifest = Readonly<{
    operationProfiles: readonly RuntimeOperationProfile[];
    orderedAssets: readonly RuntimeAssetReference[];
    orderedSuiteArtifactPaths: readonly string[];
    protocolVersion: number;
    releaseIdentifier: string;
    suiteIdentifier: Uint8Array;
    suiteRecordPath: string;
}>;

export type SuiteArtifactReference = Readonly<{
    artifactHash: Uint8Array;
    artifactKind: number;
    byteLength: bigint;
}>;

class RuntimeBuildCanonicalError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'RuntimeBuildCanonicalError';
    }
}

type CanonicalItemView = Readonly<{
    itemType: number;
    value: Uint8Array;
}>;

type CanonicalTupleView = Readonly<{
    byteLength: number;
    items: readonly CanonicalItemView[];
    schemaIdentifier: number;
}>;

const fail = (message: string): never => {
    throw new RuntimeBuildCanonicalError(message);
};

const unsigned16 = (bytes: Uint8Array, offset: number): number =>
    new DataView(bytes.buffer, bytes.byteOffset + offset, 2).getUint16(0, true);

const unsigned32 = (bytes: Uint8Array, offset: number): number =>
    new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, true);

const unsigned64 = (bytes: Uint8Array, offset: number): bigint =>
    new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(
        0,
        true,
    );

const unsigned16Bytes = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32Bytes = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const unsigned64Bytes = (value: bigint): Uint8Array => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

export const runtimeBuildBytesEqual = (
    left: Uint8Array,
    right: Uint8Array,
): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.byteLength; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
};

export const runtimeBuildBytesToHex = (bytes: Uint8Array): string =>
    [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

export const runtimeBuildHexToBytes = (
    value: string,
    expectedByteLength: number,
): Uint8Array => {
    if (
        value.length !== expectedByteLength * 2 ||
        !/^(?:[0-9a-f]{2})+$/u.test(value)
    ) {
        return fail(
            'The pinned runtime hash is not canonical lowercase hexadecimal.',
        );
    }
    const bytes = new Uint8Array(expectedByteLength);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const parseCanonicalTuplePrefix = (
    bytes: Uint8Array,
    startOffset = 0,
): CanonicalTupleView => {
    if (startOffset < 0 || startOffset + 8 > bytes.byteLength) {
        return fail('The canonical runtime tuple header is truncated.');
    }
    const schemaIdentifier = unsigned16(bytes, startOffset);
    if (unsigned16(bytes, startOffset + 2) !== canonicalTupleVersion) {
        return fail('The canonical runtime tuple version is unsupported.');
    }
    const itemCount = unsigned32(bytes, startOffset + 4);
    if (itemCount > maximumCanonicalListCount) {
        return fail(
            'The canonical runtime tuple item count exceeds its ceiling.',
        );
    }
    const items: CanonicalItemView[] = [];
    let offset = startOffset + 8;
    for (let itemIndex = 0; itemIndex < itemCount; itemIndex += 1) {
        if (offset + 6 > bytes.byteLength) {
            return fail('A canonical runtime item header is truncated.');
        }
        const itemType = unsigned16(bytes, offset);
        const valueByteLength = unsigned32(bytes, offset + 2);
        offset += 6;
        const valueEnd = offset + valueByteLength;
        if (!Number.isSafeInteger(valueEnd) || valueEnd > bytes.byteLength) {
            return fail('A canonical runtime item value is truncated.');
        }
        items.push({ itemType, value: bytes.subarray(offset, valueEnd) });
        offset = valueEnd;
    }
    return {
        byteLength: offset - startOffset,
        items,
        schemaIdentifier,
    };
};

const parseCanonicalTuple = (
    bytes: Uint8Array,
    expectedSchemaIdentifier: number,
    expectedItemCount: number,
): CanonicalTupleView => {
    const tuple = parseCanonicalTuplePrefix(bytes);
    if (
        tuple.byteLength !== bytes.byteLength ||
        tuple.schemaIdentifier !== expectedSchemaIdentifier ||
        tuple.items.length !== expectedItemCount
    ) {
        return fail(
            'The canonical runtime tuple has the wrong schema, shape, or trailing bytes.',
        );
    }
    return tuple;
};

const requiredItem = (
    tuple: CanonicalTupleView,
    itemIndex: number,
    expectedItemType: number,
): Uint8Array => {
    const item = tuple.items[itemIndex];
    if (item?.itemType !== expectedItemType) {
        return fail('A canonical runtime item has the wrong type.');
    }
    return item.value;
};

const readUnsigned16Item = (
    tuple: CanonicalTupleView,
    itemIndex: number,
): number => {
    const value = requiredItem(tuple, itemIndex, canonicalItemTypes.unsigned16);
    if (value.byteLength !== 2) {
        return fail(
            'A canonical unsigned-16 runtime item has the wrong length.',
        );
    }
    return unsigned16(value, 0);
};

const readUnsigned32Item = (
    tuple: CanonicalTupleView,
    itemIndex: number,
): number => {
    const value = requiredItem(tuple, itemIndex, canonicalItemTypes.unsigned32);
    if (value.byteLength !== 4) {
        return fail(
            'A canonical unsigned-32 runtime item has the wrong length.',
        );
    }
    return unsigned32(value, 0);
};

const readUnsigned64Item = (
    tuple: CanonicalTupleView,
    itemIndex: number,
): bigint => {
    const value = requiredItem(tuple, itemIndex, canonicalItemTypes.unsigned64);
    if (value.byteLength !== 8) {
        return fail(
            'A canonical unsigned-64 runtime item has the wrong length.',
        );
    }
    return unsigned64(value, 0);
};

const readHashItem = (
    tuple: CanonicalTupleView,
    itemIndex: number,
): Uint8Array => {
    const value = requiredItem(tuple, itemIndex, canonicalItemTypes.hash512);
    if (value.byteLength !== hashByteLength) {
        return fail('A canonical runtime hash has the wrong length.');
    }
    return value.slice();
};

const decodeCanonicalAsciiValue = (
    value: Uint8Array,
    requireNonempty: boolean,
): string => {
    if (value.byteLength < 4) {
        return fail('A canonical ASCII value is truncated.');
    }
    const byteLength = unsigned32(value, 0);
    if (
        byteLength + 4 !== value.byteLength ||
        (requireNonempty && byteLength === 0)
    ) {
        return fail('A canonical ASCII value has a noncanonical length.');
    }
    const asciiBytes = value.subarray(4);
    if (asciiBytes.some((byte) => byte < 0x20 || byte > 0x7e)) {
        return fail('A canonical ASCII value contains a non-ASCII byte.');
    }
    try {
        return textDecoder.decode(asciiBytes);
    } catch (error) {
        throw new RuntimeBuildCanonicalError(
            `A canonical ASCII value could not be decoded: ${String(error)}`,
        );
    }
};

const readAsciiItem = (
    tuple: CanonicalTupleView,
    itemIndex: number,
    requireNonempty = false,
): string =>
    decodeCanonicalAsciiValue(
        requiredItem(tuple, itemIndex, canonicalItemTypes.ascii),
        requireNonempty,
    );

const readHomogeneousList = (
    tuple: CanonicalTupleView,
    itemIndex: number,
    expectedElementType: number,
): Readonly<{ count: number; values: Uint8Array }> => {
    const list = requiredItem(
        tuple,
        itemIndex,
        canonicalItemTypes.homogeneousList,
    );
    if (list.byteLength < 6 || unsigned16(list, 0) !== expectedElementType) {
        return fail('A canonical runtime list has the wrong element type.');
    }
    const count = unsigned32(list, 2);
    if (count > maximumCanonicalListCount) {
        return fail('A canonical runtime list count exceeds its ceiling.');
    }
    return { count, values: list.subarray(6) };
};

const readAsciiList = (
    tuple: CanonicalTupleView,
    itemIndex: number,
): readonly string[] => {
    const list = readHomogeneousList(
        tuple,
        itemIndex,
        canonicalItemTypes.ascii,
    );
    const values: string[] = [];
    let offset = 0;
    for (let valueIndex = 0; valueIndex < list.count; valueIndex += 1) {
        if (offset + 4 > list.values.byteLength) {
            return fail('A canonical runtime ASCII list is truncated.');
        }
        const byteLength = unsigned32(list.values, offset);
        const valueEnd = offset + 4 + byteLength;
        if (valueEnd > list.values.byteLength) {
            return fail('A canonical runtime ASCII list value is truncated.');
        }
        values.push(
            decodeCanonicalAsciiValue(
                list.values.subarray(offset, valueEnd),
                false,
            ),
        );
        offset = valueEnd;
    }
    if (offset !== list.values.byteLength) {
        return fail('A canonical runtime ASCII list contains trailing bytes.');
    }
    return values;
};

const readNestedTupleList = (
    tuple: CanonicalTupleView,
    itemIndex: number,
): readonly CanonicalTupleView[] => {
    const list = readHomogeneousList(
        tuple,
        itemIndex,
        canonicalItemTypes.nestedTuple,
    );
    const tuples: CanonicalTupleView[] = [];
    let offset = 0;
    for (let tupleIndex = 0; tupleIndex < list.count; tupleIndex += 1) {
        const nestedTuple = parseCanonicalTuplePrefix(list.values, offset);
        tuples.push(nestedTuple);
        offset += nestedTuple.byteLength;
    }
    if (offset !== list.values.byteLength) {
        return fail('A canonical nested-tuple list contains trailing bytes.');
    }
    return tuples;
};

export const requireCanonicalRuntimePath = (path: string): string => {
    if (
        path.length === 0 ||
        !/^[\x20-\x7e]+$/u.test(path) ||
        !path.startsWith('/') ||
        path.startsWith('//') ||
        /[?#\\%]/u.test(path) ||
        path
            .split('/')
            .slice(1)
            .some(
                (segment) =>
                    segment.length === 0 || segment === '.' || segment === '..',
            )
    ) {
        return fail('A runtime path is not canonical root-relative ASCII.');
    }
    return path;
};

const privateProofSaltPurpose = 0xfffe;
const proofRandomnessPurposeRanges: ReadonlyMap<
    number,
    readonly [firstPurpose: number, lastPurpose: number]
> = new Map([
    [0x1211, [1, 2]],
    [0x1212, [3, 4]],
    [0x1214, [5, 6]],
    [0x1216, [7, 8]],
    [0x1217, [9, 40]],
    [0x1302, [41, 42]],
    [0x1621, [43, 44]],
    [0x2110, [45, 46]],
    [0x2111, [47, 48]],
]);

const isAssignedRandomUse = (family: number, purpose: number): boolean => {
    if (purpose === 0 || purpose === 0xffff) {
        return false;
    }
    if (family === 0x0116) {
        return purpose >= 1 && purpose <= 12 && purpose !== 0;
    }
    if (family === 0x1201 || family === 0x2120) {
        return purpose <= 4;
    }
    if (family === 0x0200) {
        return purpose <= 3;
    }
    if (family === 0x1630) {
        return purpose <= 2;
    }
    const proofPurposeRange = proofRandomnessPurposeRanges.get(family);
    return (
        proofPurposeRange !== undefined &&
        (purpose === privateProofSaltPurpose ||
            (purpose >= proofPurposeRange[0] &&
                purpose <= proofPurposeRange[1]))
    );
};

const parseRuntimeAssetReference = (
    tuple: CanonicalTupleView,
): RuntimeAssetReference => {
    if (
        tuple.schemaIdentifier !== runtimeAssetReferenceSchemaIdentifier ||
        tuple.items.length !== 4
    ) {
        return fail('A runtime asset reference has the wrong schema or shape.');
    }
    const assetRole = readUnsigned16Item(tuple, 0);
    if (assetRole < 1 || assetRole > 4) {
        return fail('A runtime asset reference has an unassigned role.');
    }
    const canonicalPath = requireCanonicalRuntimePath(readAsciiItem(tuple, 1));
    const byteLength = readUnsigned64Item(tuple, 2);
    if (byteLength === 0n) {
        return fail('A runtime asset reference cannot name an empty asset.');
    }
    if (
        (assetRole === 1 || assetRole === 2) &&
        byteLength > BigInt(maximumCopiedExecutableAssetByteLength)
    ) {
        return fail('A runtime executable exceeds the copied-buffer ceiling.');
    }
    if (byteLength > BigInt(maximumFoundationVariableValueByteLength)) {
        return fail(
            'A runtime asset exceeds the canonical hash-input ceiling.',
        );
    }
    return Object.freeze({
        assetHash: readHashItem(tuple, 3),
        assetRole: assetRole as RuntimeAssetRole,
        byteLength,
        canonicalPath,
    });
};

const parseCheckpointRandomUse = (
    tuple: CanonicalTupleView,
): CheckpointRandomUseProfile => {
    if (
        tuple.schemaIdentifier !== checkpointRandomUseProfileSchemaIdentifier ||
        tuple.items.length !== 2
    ) {
        return fail(
            'A checkpoint random-use profile has the wrong schema or shape.',
        );
    }
    const family = readUnsigned16Item(tuple, 0);
    const purpose = readUnsigned16Item(tuple, 1);
    if (!isAssignedRandomUse(family, purpose)) {
        return fail('A checkpoint random-use profile is unassigned.');
    }
    return Object.freeze({ family, purpose });
};

const parseCheckpointBoundary = (
    tuple: CanonicalTupleView,
): CheckpointBoundaryProfile => {
    if (
        tuple.schemaIdentifier !== checkpointBoundaryProfileSchemaIdentifier ||
        tuple.items.length !== 3
    ) {
        return fail(
            'A checkpoint boundary profile has the wrong schema or shape.',
        );
    }
    const stateSchemaIdentifier = readUnsigned16Item(tuple, 1);
    if (stateSchemaIdentifier === 0) {
        return fail('A checkpoint boundary must name a state schema.');
    }
    const orderedRandomUses = readNestedTupleList(tuple, 2).map(
        parseCheckpointRandomUse,
    );
    for (let index = 1; index < orderedRandomUses.length; index += 1) {
        const previous = orderedRandomUses[index - 1];
        const current = orderedRandomUses[index];
        if (
            previous === undefined ||
            current === undefined ||
            previous.family > current.family ||
            (previous.family === current.family &&
                previous.purpose >= current.purpose)
        ) {
            return fail('Checkpoint random uses are not strictly ordered.');
        }
    }
    return Object.freeze({
        orderedRandomUses: Object.freeze(orderedRandomUses),
        safeBoundaryOrdinal: readUnsigned32Item(tuple, 0),
        stateSchemaIdentifier,
    });
};

const parseRuntimeOperationProfile = (
    tuple: CanonicalTupleView,
): RuntimeOperationProfile => {
    if (
        tuple.schemaIdentifier !== runtimeOperationProfileSchemaIdentifier ||
        tuple.items.length !== 2
    ) {
        return fail(
            'A runtime operation profile has the wrong schema or shape.',
        );
    }
    const operationKind = readUnsigned16Item(tuple, 0);
    const safeBoundaries = readNestedTupleList(tuple, 1).map(
        parseCheckpointBoundary,
    );
    if (operationKind === 0 || safeBoundaries.length === 0) {
        return fail('A runtime operation profile is empty or unassigned.');
    }
    safeBoundaries.forEach((boundary, expectedOrdinal) => {
        if (boundary.safeBoundaryOrdinal !== expectedOrdinal) {
            fail('Checkpoint boundaries are not contiguous from zero.');
        }
    });
    return Object.freeze({
        operationKind,
        safeBoundaries: Object.freeze(safeBoundaries),
    });
};

export const decodeRuntimeBuildManifest = (
    canonicalManifestBytes: Uint8Array,
): RuntimeBuildManifest => {
    if (
        canonicalManifestBytes.byteLength === 0 ||
        canonicalManifestBytes.byteLength >
            maximumRuntimeBuildManifestByteLength
    ) {
        return fail('The runtime build manifest exceeds its byte ceiling.');
    }
    const tuple = parseCanonicalTuple(
        canonicalManifestBytes,
        runtimeBuildManifestSchemaIdentifier,
        7,
    );
    const parsedProtocolVersion = readUnsigned16Item(tuple, 0);
    const releaseIdentifier = readAsciiItem(tuple, 1, true);
    if (
        parsedProtocolVersion !== protocolVersion ||
        releaseIdentifier.length > 256
    ) {
        return fail(
            'The runtime build release or protocol version is unsupported.',
        );
    }
    const suiteRecordPath = requireCanonicalRuntimePath(
        readAsciiItem(tuple, 3),
    );
    const orderedSuiteArtifactPaths = readAsciiList(tuple, 4).map(
        requireCanonicalRuntimePath,
    );
    if (orderedSuiteArtifactPaths.length !== requiredSuiteArtifactCount) {
        return fail(
            'The runtime build manifest must name six suite artifacts.',
        );
    }
    const orderedAssets = readNestedTupleList(tuple, 5).map(
        parseRuntimeAssetReference,
    );
    if (
        orderedAssets.length < 3 ||
        orderedAssets[0]?.assetRole !== 1 ||
        orderedAssets[1]?.assetRole !== 2 ||
        orderedAssets[2]?.assetRole !== 3
    ) {
        return fail(
            'The runtime build manifest lacks one required executable asset.',
        );
    }
    for (let index = 1; index < orderedAssets.length; index += 1) {
        const previous = orderedAssets[index - 1];
        const current = orderedAssets[index];
        if (
            previous === undefined ||
            current === undefined ||
            previous.assetRole > current.assetRole ||
            (previous.assetRole === current.assetRole &&
                previous.canonicalPath >= current.canonicalPath) ||
            (index > 2 && current.assetRole !== 4)
        ) {
            return fail(
                'Runtime assets are not strictly role-and-path ordered.',
            );
        }
    }

    const allPaths = [
        suiteRecordPath,
        ...orderedSuiteArtifactPaths,
        ...orderedAssets.map((asset) => asset.canonicalPath),
    ];
    if (new Set(allPaths).size !== allPaths.length) {
        return fail('Runtime manifest paths are not pairwise distinct.');
    }

    const operationProfiles = readNestedTupleList(tuple, 6).map(
        parseRuntimeOperationProfile,
    );
    for (let index = 1; index < operationProfiles.length; index += 1) {
        const previous = operationProfiles[index - 1];
        const current = operationProfiles[index];
        if (
            previous === undefined ||
            current === undefined ||
            previous.operationKind >= current.operationKind
        ) {
            return fail('Runtime operation profiles are not strictly ordered.');
        }
    }

    return Object.freeze({
        operationProfiles: Object.freeze(operationProfiles),
        orderedAssets: Object.freeze(orderedAssets),
        orderedSuiteArtifactPaths: Object.freeze(orderedSuiteArtifactPaths),
        protocolVersion: parsedProtocolVersion,
        releaseIdentifier,
        suiteIdentifier: readHashItem(tuple, 2),
        suiteRecordPath,
    });
};

export const decodeSuiteArtifactReferences = (
    canonicalSuiteRecordBytes: Uint8Array,
): readonly SuiteArtifactReference[] => {
    if (
        canonicalSuiteRecordBytes.byteLength === 0 ||
        canonicalSuiteRecordBytes.byteLength >
            maximumRuntimeBuildManifestByteLength
    ) {
        return fail('The canonical suite record exceeds its byte ceiling.');
    }
    const tuple = parseCanonicalTuple(
        canonicalSuiteRecordBytes,
        suiteRecordSchemaIdentifier,
        27,
    );
    const references = readNestedTupleList(tuple, 26).map((referenceTuple) => {
        if (
            referenceTuple.schemaIdentifier !==
                suiteArtifactReferenceSchemaIdentifier ||
            referenceTuple.items.length !== 3
        ) {
            return fail(
                'A suite artifact reference has the wrong schema or shape.',
            );
        }
        const artifactKind = readUnsigned16Item(referenceTuple, 0);
        const byteLength = readUnsigned64Item(referenceTuple, 1);
        if (
            artifactKind < 1 ||
            artifactKind > requiredSuiteArtifactCount ||
            byteLength === 0n ||
            byteLength > BigInt(maximumFoundationVariableValueByteLength)
        ) {
            return fail(
                'A suite artifact reference is outside its accepted profile.',
            );
        }
        return Object.freeze({
            artifactHash: readHashItem(referenceTuple, 2),
            artifactKind,
            byteLength,
        });
    });
    if (
        references.length !== requiredSuiteArtifactCount ||
        references.some(
            (reference, referenceIndex) =>
                reference.artifactKind !== referenceIndex + 1,
        )
    ) {
        return fail('Suite artifact references are not complete and ordered.');
    }
    return Object.freeze(references);
};

const updateCanonicalItemHeader = (
    hash: ReturnType<typeof shake256.create>,
    itemType: number,
    valueByteLength: number,
): void => {
    hash.update(unsigned16Bytes(itemType));
    hash.update(unsigned32Bytes(valueByteLength));
};

const updateAsciiItem = (
    hash: ReturnType<typeof shake256.create>,
    value: string,
): void => {
    const bytes = textEncoder.encode(value);
    if (bytes.some((byte) => byte < 0x20 || byte > 0x7e)) {
        fail('A foundation hash domain or path is not ASCII.');
    }
    updateCanonicalItemHeader(
        hash,
        canonicalItemTypes.ascii,
        bytes.byteLength + 4,
    );
    hash.update(unsigned32Bytes(bytes.byteLength));
    hash.update(bytes);
};

export type RuntimeBuildHashAccumulator = Readonly<{
    finish(): Uint8Array;
    update(bytes: Uint8Array): void;
}>;

const createFoundationVariableBytesHash = (
    domain: string,
    fixedItems: readonly Readonly<{
        itemType: number;
        value: Uint8Array;
    }>[],
    variableByteLength: bigint,
): RuntimeBuildHashAccumulator => {
    if (
        variableByteLength < 0n ||
        variableByteLength > BigInt(maximumFoundationVariableValueByteLength)
    ) {
        return fail(
            'A foundation hash input exceeds its canonical byte ceiling.',
        );
    }
    const expectedByteLength = Number(variableByteLength);
    const hash = shake256.create({ dkLen: hashByteLength });
    hash.update(unsigned16Bytes(canonicalTupleSchemaIdentifier));
    hash.update(unsigned16Bytes(canonicalTupleVersion));
    hash.update(unsigned32Bytes(fixedItems.length + 2));
    updateAsciiItem(hash, domain);
    for (const item of fixedItems) {
        updateCanonicalItemHeader(hash, item.itemType, item.value.byteLength);
        hash.update(item.value);
    }
    updateCanonicalItemHeader(
        hash,
        canonicalItemTypes.rawBytes,
        expectedByteLength + 4,
    );
    hash.update(unsigned32Bytes(expectedByteLength));
    let observedByteLength = 0;
    let finished = false;
    return Object.freeze({
        finish: (): Uint8Array => {
            if (finished || observedByteLength !== expectedByteLength) {
                hash.destroy();
                return fail(
                    'A streamed foundation hash input has the wrong length.',
                );
            }
            finished = true;
            return hash.digest();
        },
        update: (bytes: Uint8Array): void => {
            if (finished || !(bytes instanceof Uint8Array)) {
                return fail(
                    'A streamed foundation hash input is invalid or already closed.',
                );
            }
            if (bytes.byteLength > expectedByteLength - observedByteLength) {
                hash.destroy();
                finished = true;
                return fail(
                    'A streamed foundation hash input exceeds its declared length.',
                );
            }
            observedByteLength += bytes.byteLength;
            hash.update(bytes);
        },
    });
};

export const createRuntimeAssetHashAccumulator = (
    asset: Pick<
        RuntimeAssetReference,
        'assetRole' | 'byteLength' | 'canonicalPath'
    >,
): RuntimeBuildHashAccumulator => {
    requireCanonicalRuntimePath(asset.canonicalPath);
    return createFoundationVariableBytesHash(
        'sealed-lattice/runtime/asset/v1',
        [
            {
                itemType: canonicalItemTypes.unsigned16,
                value: unsigned16Bytes(asset.assetRole),
            },
            {
                itemType: canonicalItemTypes.ascii,
                value: (() => {
                    const bytes = textEncoder.encode(asset.canonicalPath);
                    const value = new Uint8Array(bytes.byteLength + 4);
                    new DataView(value.buffer).setUint32(
                        0,
                        bytes.byteLength,
                        true,
                    );
                    value.set(bytes, 4);
                    return value;
                })(),
            },
            {
                itemType: canonicalItemTypes.unsigned64,
                value: unsigned64Bytes(asset.byteLength),
            },
        ],
        asset.byteLength,
    );
};

export const createRuntimeBuildManifestHashAccumulator = (
    byteLength: bigint,
): RuntimeBuildHashAccumulator =>
    createFoundationVariableBytesHash(
        'sealed-lattice/runtime/build-manifest/v1',
        [],
        byteLength,
    );

export const createSuiteIdentifierAccumulator = (
    byteLength: bigint,
): RuntimeBuildHashAccumulator =>
    createFoundationVariableBytesHash(
        'sealed-lattice/foundation/suite/v1',
        [],
        byteLength,
    );

export const createSuiteArtifactHashAccumulator = (
    artifactKind: number,
    byteLength: bigint,
): RuntimeBuildHashAccumulator =>
    createFoundationVariableBytesHash(
        'sealed-lattice/foundation/suite-artifact/v1',
        [
            {
                itemType: canonicalItemTypes.unsigned16,
                value: unsigned16Bytes(artifactKind),
            },
            {
                itemType: canonicalItemTypes.unsigned64,
                value: unsigned64Bytes(byteLength),
            },
        ],
        byteLength,
    );

export const runtimeBuildCanonicalLimits = Object.freeze({
    hashByteLength,
    maximumCopiedExecutableAssetByteLength,
    maximumFoundationVariableValueByteLength,
    maximumRuntimeBuildManifestByteLength,
});
