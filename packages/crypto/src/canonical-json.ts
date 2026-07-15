import { shake256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const textEncoder = new TextEncoder();
const hash512PreimagePrefix = textEncoder.encode('sealed.vote/hash512');
const canonicalJsonByteSourceFingerprintPrefix = textEncoder.encode(
    'sealed-lattice/canonical-json-byte-source/v1',
);
const maximumCanonicalJsonContainerDepth = 64;
const maximumCanonicalJsonValueCount = 1_000_000;
const maximumCanonicalJsonStringCodeUnitCount = 64 * 1024 * 1024;
const maximumCanonicalJsonByteLength = 64 * 1024 * 1024;
const maximumCanonicalJsonFragmentCodeUnitCount = 4_096;
const canonicalJsonByteSourceFingerprintByteLength = 64;

const isCanonicalInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && !Object.is(value, -0);

type CanonicalJsonSerializationState = {
    readonly activeContainers: WeakSet<object>;
    byteLength: number;
    rootObjectType: unknown;
    stringCodeUnitCount: number;
    valueCount: number;
};

const createCanonicalJsonSerializationState =
    (): CanonicalJsonSerializationState => ({
        activeContainers: new WeakSet<object>(),
        byteLength: 0,
        rootObjectType: undefined,
        stringCodeUnitCount: 0,
        valueCount: 0,
    });

const chargeCanonicalJsonByteLength = (
    state: CanonicalJsonSerializationState,
    additionalByteLength: number,
): void => {
    if (
        additionalByteLength >
        maximumCanonicalJsonByteLength - state.byteLength
    ) {
        throw new RangeError(
            'Canonical JSON exceeds the accepted byte length.',
        );
    }
    state.byteLength += additionalByteLength;
};

const chargeCanonicalJsonValue = (
    state: CanonicalJsonSerializationState,
): void => {
    if (state.valueCount >= maximumCanonicalJsonValueCount) {
        throw new RangeError(
            'Canonical JSON exceeds the accepted value count.',
        );
    }
    state.valueCount += 1;
};

const chargeCanonicalJsonString = (
    state: CanonicalJsonSerializationState,
    value: string,
): void => {
    if (
        value.length >
        maximumCanonicalJsonStringCodeUnitCount - state.stringCodeUnitCount
    ) {
        throw new RangeError(
            'Canonical JSON exceeds the accepted string size.',
        );
    }
    state.stringCodeUnitCount += value.length;
};

const containsLoneSurrogate = (value: string): boolean => {
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const nextCodeUnit = value.charCodeAt(index + 1);
            if (
                index + 1 >= value.length ||
                nextCodeUnit < 0xdc00 ||
                nextCodeUnit > 0xdfff
            ) {
                return true;
            }
            index += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            return true;
        }
    }

    return false;
};

const validateCanonicalString = (
    value: string,
    state: CanonicalJsonSerializationState,
): string => {
    chargeCanonicalJsonString(state, value);
    if (containsLoneSurrogate(value)) {
        throw new TypeError(
            'Canonical strings cannot contain lone UTF-16 surrogates.',
        );
    }

    for (
        let characterIndex = 0;
        characterIndex < value.length;
        characterIndex += 1
    ) {
        if (value.charCodeAt(characterIndex) > 0x7f) {
            throw new TypeError(
                'Canonical strings in TypeScript hash paths must contain only ASCII characters; use the Unicode 17 Rust/WASM foundation codec for display text.',
            );
        }
    }

    return value;
};

const canonicalJsonEscape = (codeUnit: number): string => {
    switch (codeUnit) {
        case 0x08:
            return '\\b';
        case 0x09:
            return '\\t';
        case 0x0a:
            return '\\n';
        case 0x0c:
            return '\\f';
        case 0x0d:
            return '\\r';
        case 0x22:
            return '\\"';
        case 0x5c:
            return '\\\\';
        default:
            return codeUnit < 0x20
                ? `\\u${codeUnit.toString(16).padStart(4, '0')}`
                : String.fromCharCode(codeUnit);
    }
};

const serializedCanonicalStringFragments = function* (
    value: string,
    state: CanonicalJsonSerializationState,
    isAlreadyValidated = false,
): Generator<string, void> {
    if (!isAlreadyValidated) {
        validateCanonicalString(value, state);
    }
    chargeCanonicalJsonByteLength(state, 1);
    yield '"';

    let fragment = '';
    for (
        let codeUnitIndex = 0;
        codeUnitIndex < value.length;
        codeUnitIndex += 1
    ) {
        const escapedCodeUnit = canonicalJsonEscape(
            value.charCodeAt(codeUnitIndex),
        );
        if (
            fragment.length > 0 &&
            escapedCodeUnit.length >
                maximumCanonicalJsonFragmentCodeUnitCount - fragment.length
        ) {
            chargeCanonicalJsonByteLength(state, fragment.length);
            yield fragment;
            fragment = escapedCodeUnit;
        } else {
            fragment += escapedCodeUnit;
        }
    }
    if (fragment.length > 0) {
        chargeCanonicalJsonByteLength(state, fragment.length);
        yield fragment;
    }

    chargeCanonicalJsonByteLength(state, 1);
    yield '"';
};

const containerPrototype = (value: object): object | null => {
    try {
        return Reflect.getPrototypeOf(value);
    } catch {
        throw new TypeError(
            'Canonical JSON containers must expose an ordinary prototype.',
        );
    }
};

const ownPropertyDescriptor = (
    value: object,
    propertyKey: PropertyKey,
): PropertyDescriptor | undefined => {
    try {
        return Object.getOwnPropertyDescriptor(value, propertyKey);
    } catch {
        throw new TypeError(
            'Canonical JSON containers must expose stable own data properties.',
        );
    }
};

const ownPropertyKeys = (value: object): readonly PropertyKey[] => {
    try {
        return Reflect.ownKeys(value);
    } catch {
        throw new TypeError(
            'Canonical JSON containers must expose stable own property keys.',
        );
    }
};

const rejectCustomJsonSerialization = (value: object): void => {
    const descriptor = ownPropertyDescriptor(value, 'toJSON');
    if (
        descriptor !== undefined &&
        ('get' in descriptor ||
            'set' in descriptor ||
            ('value' in descriptor && typeof descriptor.value === 'function'))
    ) {
        throw new TypeError(
            'Canonical JSON cannot contain custom serialization.',
        );
    }
};

const serializeCanonicalValueFragments = function* (
    value: unknown,
    state: CanonicalJsonSerializationState,
    containerDepth: number,
): Generator<string, void> {
    chargeCanonicalJsonValue(state);
    if (value === null) {
        chargeCanonicalJsonByteLength(state, 4);
        yield 'null';
        return;
    }
    if (typeof value === 'string') {
        yield* serializedCanonicalStringFragments(value, state);
        return;
    }
    if (typeof value === 'boolean') {
        const serialized = value ? 'true' : 'false';
        chargeCanonicalJsonByteLength(state, serialized.length);
        yield serialized;
        return;
    }
    if (typeof value === 'number') {
        if (!isCanonicalInteger(value)) {
            throw new TypeError(
                'Canonical numeric fields must be safe integers.',
            );
        }

        const serialized = JSON.stringify(value);
        chargeCanonicalJsonByteLength(state, serialized.length);

        yield serialized;
        return;
    }
    if (typeof value !== 'object' || value === null) {
        throw new TypeError('Unsupported canonical value.');
    }
    if (containerDepth >= maximumCanonicalJsonContainerDepth) {
        throw new RangeError(
            'Canonical JSON exceeds the accepted container depth.',
        );
    }
    const container = value;
    if (state.activeContainers.has(container)) {
        throw new TypeError('Canonical JSON cannot contain cycles.');
    }
    state.activeContainers.add(container);
    try {
        rejectCustomJsonSerialization(container);
        if (Array.isArray(container)) {
            const prototype = containerPrototype(container);
            if (prototype !== Array.prototype && prototype !== null) {
                throw new TypeError(
                    'Canonical arrays must have an ordinary prototype.',
                );
            }
            const lengthDescriptor = ownPropertyDescriptor(container, 'length');
            if (
                lengthDescriptor === undefined ||
                !('value' in lengthDescriptor) ||
                !Number.isSafeInteger(lengthDescriptor.value) ||
                lengthDescriptor.value < 0
            ) {
                throw new TypeError('Canonical arrays have an invalid length.');
            }
            const arrayLength = lengthDescriptor.value as number;
            if (
                arrayLength >
                maximumCanonicalJsonValueCount - state.valueCount
            ) {
                throw new RangeError(
                    'Canonical JSON exceeds the accepted value count.',
                );
            }
            chargeCanonicalJsonByteLength(
                state,
                2 + Math.max(0, arrayLength - 1),
            );
            yield '[';
            for (let index = 0; index < arrayLength; index += 1) {
                if (index > 0) {
                    yield ',';
                }
                const descriptor = ownPropertyDescriptor(
                    container,
                    String(index),
                );
                if (descriptor === undefined) {
                    throw new TypeError('Canonical arrays cannot be sparse.');
                }
                if ('get' in descriptor || 'set' in descriptor) {
                    throw new TypeError(
                        'Canonical arrays cannot contain accessor properties.',
                    );
                }
                yield* serializeCanonicalValueFragments(
                    descriptor.value,
                    state,
                    containerDepth + 1,
                );
            }

            yield ']';
            return;
        }

        const prototype = containerPrototype(container);
        if (prototype !== Object.prototype && prototype !== null) {
            throw new TypeError(
                'Canonical objects must have an ordinary prototype.',
            );
        }
        const entries: {
            readonly descriptor: PropertyDescriptor;
            readonly key: string;
        }[] = [];
        for (const propertyKey of ownPropertyKeys(container)) {
            if (typeof propertyKey !== 'string') {
                continue;
            }
            const descriptor = ownPropertyDescriptor(container, propertyKey);
            if (descriptor?.enumerable !== true) {
                continue;
            }
            if ('get' in descriptor || 'set' in descriptor) {
                throw new TypeError(
                    'Canonical objects cannot contain accessor properties.',
                );
            }
            validateCanonicalString(propertyKey, state);
            entries.push({ descriptor, key: propertyKey });
        }
        entries.sort((left, right) =>
            left.key < right.key ? -1 : left.key > right.key ? 1 : 0,
        );
        chargeCanonicalJsonByteLength(
            state,
            2 + Math.max(0, entries.length - 1),
        );
        yield '{';
        for (const [entryIndex, { descriptor, key }] of entries.entries()) {
            if (entryIndex > 0) {
                yield ',';
            }
            if (descriptor.value === undefined) {
                throw new TypeError(
                    'Canonical objects cannot contain undefined.',
                );
            }
            yield* serializedCanonicalStringFragments(key, state, true);
            chargeCanonicalJsonByteLength(state, 1);
            yield ':';
            if (containerDepth === 0 && key === 'objectType') {
                state.rootObjectType = descriptor.value;
            }
            yield* serializeCanonicalValueFragments(
                descriptor.value,
                state,
                containerDepth + 1,
            );
        }

        yield '}';
    } finally {
        state.activeContainers.delete(container);
    }
};

export const canonicalJsonWithRootObjectType = (
    value: unknown,
): Readonly<{ json: string; rootObjectType: unknown }> => {
    const state = createCanonicalJsonSerializationState();
    const fragments: string[] = [];
    let combinedFragment = '';
    for (const fragment of serializeCanonicalValueFragments(value, state, 0)) {
        if (
            combinedFragment.length > 0 &&
            fragment.length >
                maximumCanonicalJsonFragmentCodeUnitCount -
                    combinedFragment.length
        ) {
            fragments.push(combinedFragment);
            combinedFragment = fragment;
        } else {
            combinedFragment += fragment;
        }
    }
    if (combinedFragment.length > 0) {
        fragments.push(combinedFragment);
    }

    return { json: fragments.join(''), rootObjectType: state.rootObjectType };
};

export const canonicalJson = (value: unknown): string =>
    canonicalJsonWithRootObjectType(value).json;

export type CanonicalJsonByteSourcePullInput = Readonly<{
    chunkIndex: number;
    expectedByteLength: number;
}>;

export type CanonicalJsonByteSource = Readonly<{
    byteLength: number;
    cancel(): void;
    pullChunk(input: CanonicalJsonByteSourcePullInput): ArrayBuffer | undefined;
}>;

const requireNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): number => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

const updateHashWithCanonicalFragment = (
    hash: ReturnType<typeof shake256.create>,
    fragment: string,
): void => {
    const bytes = textEncoder.encode(fragment);
    try {
        hash.update(bytes);
    } finally {
        bytes.fill(0);
    }
};

const canonicalJsonFingerprint = (
    value: unknown,
): Readonly<{ byteLength: number; fingerprint: Uint8Array }> => {
    const state = createCanonicalJsonSerializationState();
    const hash = shake256.create({
        dkLen: canonicalJsonByteSourceFingerprintByteLength,
    });
    try {
        hash.update(canonicalJsonByteSourceFingerprintPrefix);
        let combinedFragment = '';
        for (const fragment of serializeCanonicalValueFragments(
            value,
            state,
            0,
        )) {
            if (
                combinedFragment.length > 0 &&
                fragment.length >
                    maximumCanonicalJsonFragmentCodeUnitCount -
                        combinedFragment.length
            ) {
                updateHashWithCanonicalFragment(hash, combinedFragment);
                combinedFragment = fragment;
            } else {
                combinedFragment += fragment;
            }
        }
        if (combinedFragment.length > 0) {
            updateHashWithCanonicalFragment(hash, combinedFragment);
        }

        return {
            byteLength: state.byteLength,
            fingerprint: hash.digest(),
        };
    } finally {
        hash.destroy();
    }
};

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }

    let difference = 0;
    for (let index = 0; index < left.byteLength; index += 1) {
        difference |= left[index] ^ right[index];
    }

    return difference === 0;
};

export const openCanonicalJsonByteSource = (
    value: unknown,
): CanonicalJsonByteSource => {
    const expected = canonicalJsonFingerprint(value);
    const streamingState = createCanonicalJsonSerializationState();
    let fragments: Generator<string, void> | undefined =
        serializeCanonicalValueFragments(value, streamingState, 0);
    let pendingFragment: string | undefined;
    let fragmentBytes: Uint8Array | undefined;
    let fragmentByteOffset = 0;
    let consumedByteLength = 0;
    let nextChunkIndex = 0;
    let lifecycle: 'cancelled' | 'complete' | 'failed' | 'open' = 'open';
    let trailingPullObserved = false;
    let streamingHash: ReturnType<typeof shake256.create> | undefined =
        shake256.create({
            dkLen: canonicalJsonByteSourceFingerprintByteLength,
        });
    streamingHash.update(canonicalJsonByteSourceFingerprintPrefix);

    const releaseStreamingState = (): void => {
        fragmentBytes?.fill(0);
        fragmentBytes = undefined;
        fragmentByteOffset = 0;
        pendingFragment = undefined;
        if (fragments !== undefined) {
            fragments.return(undefined);
            fragments = undefined;
        }
        if (streamingHash !== undefined) {
            streamingHash.destroy();
            streamingHash = undefined;
        }
        expected.fingerprint.fill(0);
    };

    const fail = (): void => {
        lifecycle = 'failed';
        releaseStreamingState();
    };

    const requireOpen = (): void => {
        if (lifecycle === 'cancelled') {
            throw new Error('The canonical JSON byte source was cancelled.');
        }
        if (lifecycle === 'failed') {
            throw new Error('The canonical JSON byte source has failed.');
        }
        if (trailingPullObserved) {
            throw new Error('The canonical JSON byte source is exhausted.');
        }
    };

    const loadNextFragment = (): boolean => {
        if (fragments === undefined || streamingHash === undefined) {
            return false;
        }
        let combinedFragment = '';
        for (;;) {
            const nextFragment =
                pendingFragment === undefined
                    ? fragments.next()
                    : ({ done: false, value: pendingFragment } as const);
            pendingFragment = undefined;
            if (nextFragment.done) {
                break;
            }
            if (
                combinedFragment.length > 0 &&
                nextFragment.value.length >
                    maximumCanonicalJsonFragmentCodeUnitCount -
                        combinedFragment.length
            ) {
                pendingFragment = nextFragment.value;
                break;
            }
            combinedFragment += nextFragment.value;
            if (
                combinedFragment.length ===
                maximumCanonicalJsonFragmentCodeUnitCount
            ) {
                break;
            }
        }
        if (combinedFragment.length === 0) {
            return false;
        }
        fragmentBytes = textEncoder.encode(combinedFragment);
        fragmentByteOffset = 0;
        streamingHash.update(fragmentBytes);

        return true;
    };

    const finish = (): void => {
        if (
            fragmentBytes !== undefined &&
            fragmentByteOffset < fragmentBytes.byteLength
        ) {
            throw new TypeError(
                'The canonical JSON value changed while it was streamed.',
            );
        }
        if (pendingFragment !== undefined) {
            throw new TypeError(
                'The canonical JSON value changed while it was streamed.',
            );
        }
        const finalIteratorResult = fragments?.next();
        if (
            finalIteratorResult?.done !== true ||
            streamingState.byteLength !== expected.byteLength ||
            streamingHash === undefined
        ) {
            throw new TypeError(
                'The canonical JSON value changed while it was streamed.',
            );
        }
        const actualFingerprint = streamingHash.digest();
        try {
            if (!equalBytes(actualFingerprint, expected.fingerprint)) {
                throw new TypeError(
                    'The canonical JSON value changed while it was streamed.',
                );
            }
        } finally {
            actualFingerprint.fill(0);
        }
        lifecycle = 'complete';
        releaseStreamingState();
    };

    const pullChunk = ({
        chunkIndex,
        expectedByteLength,
    }: CanonicalJsonByteSourcePullInput): ArrayBuffer | undefined => {
        requireOpen();
        requireNonNegativeSafeInteger(chunkIndex, 'chunkIndex');
        requireNonNegativeSafeInteger(expectedByteLength, 'expectedByteLength');
        if (chunkIndex !== nextChunkIndex) {
            throw new Error(
                'Canonical JSON byte-source chunks must be pulled in order.',
            );
        }
        if (expectedByteLength === 0) {
            if (
                lifecycle !== 'complete' ||
                consumedByteLength !== expected.byteLength
            ) {
                throw new Error(
                    'The canonical JSON byte source has not reached its exact length.',
                );
            }
            trailingPullObserved = true;
            nextChunkIndex += 1;
            return undefined;
        }
        if (
            lifecycle !== 'open' ||
            expectedByteLength > expected.byteLength - consumedByteLength
        ) {
            throw new RangeError(
                'The requested canonical JSON chunk exceeds the exact byte length.',
            );
        }

        const output = new Uint8Array(expectedByteLength);
        try {
            let outputByteOffset = 0;
            while (outputByteOffset < output.byteLength) {
                if (
                    fragmentBytes === undefined ||
                    fragmentByteOffset === fragmentBytes.byteLength
                ) {
                    fragmentBytes?.fill(0);
                    fragmentBytes = undefined;
                    if (!loadNextFragment()) {
                        throw new TypeError(
                            'The canonical JSON value changed while it was streamed.',
                        );
                    }
                }
                const availableByteLength =
                    fragmentBytes!.byteLength - fragmentByteOffset;
                const copiedByteLength = Math.min(
                    availableByteLength,
                    output.byteLength - outputByteOffset,
                );
                output.set(
                    fragmentBytes!.subarray(
                        fragmentByteOffset,
                        fragmentByteOffset + copiedByteLength,
                    ),
                    outputByteOffset,
                );
                fragmentByteOffset += copiedByteLength;
                outputByteOffset += copiedByteLength;
            }

            consumedByteLength += output.byteLength;
            nextChunkIndex += 1;
            if (consumedByteLength === expected.byteLength) {
                finish();
            }

            return output.buffer;
        } catch (error) {
            output.fill(0);
            fail();
            throw error;
        }
    };

    return Object.freeze({
        byteLength: expected.byteLength,
        cancel: (): void => {
            if (lifecycle === 'cancelled' || lifecycle === 'failed') {
                return;
            }
            lifecycle = 'cancelled';
            releaseStreamingState();
        },
        pullChunk,
    });
};

const appendVarUintToHash = (
    hash: ReturnType<typeof shake256.create>,
    value: number,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'Varuint values must be non-negative safe integers.',
        );
    }

    // LEB128 unsigned varint. Used as a length prefix so every hashed part is
    // framed (length || bytes); this makes the preimage injective and prevents
    // length-extension / concatenation ambiguity across parts.
    const encodedBytes: number[] = [];
    let remainingValue = value;
    for (;;) {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        encodedBytes.push(byte);
        if (remainingValue === 0) {
            break;
        }
    }

    hash.update(Uint8Array.from(encodedBytes));
};

const appendBytesToHash = (
    hash: ReturnType<typeof shake256.create>,
    value: Uint8Array,
): void => {
    appendVarUintToHash(hash, value.byteLength);
    hash.update(value);
};

const hash512 = (domain: string, parts: readonly Uint8Array[]): Uint8Array => {
    const hash = shake256.create({ dkLen: 64 });

    try {
        // Security-critical anti-collision preimage layout that every protocol
        // hash relies on, and that must byte-match the Rust kernel:
        //   prefix || len(domain) || domain || count(parts) || (len(part) || part)*
        // The varint length prefixes make the layout unambiguous/injective.
        hash.update(hash512PreimagePrefix);
        appendBytesToHash(hash, textEncoder.encode(domain));
        appendVarUintToHash(hash, parts.length);
        for (const part of parts) {
            appendBytesToHash(hash, part);
        }

        return hash.digest();
    } finally {
        hash.destroy();
    }
};

export const hash512Hex = (
    domain: string,
    parts: readonly Uint8Array[],
): string => bytesToHex(hash512(domain, parts));
