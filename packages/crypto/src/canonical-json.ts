import { shake256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const textEncoder = new TextEncoder();
const hash512PreimagePrefix = textEncoder.encode('sealed.vote/hash512');
const maximumCanonicalJsonContainerDepth = 64;
const maximumCanonicalJsonValueCount = 1_000_000;
const maximumCanonicalJsonStringCodeUnitCount = 64 * 1024 * 1024;
const maximumCanonicalJsonByteLength = 64 * 1024 * 1024;

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

const serializedCanonicalString = (
    value: string,
    state: CanonicalJsonSerializationState,
): string => {
    const serialized = JSON.stringify(validateCanonicalString(value, state));
    chargeCanonicalJsonByteLength(state, serialized.length);

    return serialized;
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

const serializeCanonicalValue = (
    value: unknown,
    state: CanonicalJsonSerializationState,
    containerDepth: number,
): string => {
    chargeCanonicalJsonValue(state);
    if (value === null) {
        chargeCanonicalJsonByteLength(state, 4);
        return 'null';
    }
    if (typeof value === 'string') {
        return serializedCanonicalString(value, state);
    }
    if (typeof value === 'boolean') {
        chargeCanonicalJsonByteLength(state, value ? 4 : 5);
        return value ? 'true' : 'false';
    }
    if (typeof value === 'number') {
        if (!isCanonicalInteger(value)) {
            throw new TypeError(
                'Canonical numeric fields must be safe integers.',
            );
        }

        const serialized = JSON.stringify(value);
        chargeCanonicalJsonByteLength(state, serialized.length);

        return serialized;
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
            const serializedItems: string[] = [];
            for (let index = 0; index < arrayLength; index += 1) {
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
                serializedItems.push(
                    serializeCanonicalValue(
                        descriptor.value,
                        state,
                        containerDepth + 1,
                    ),
                );
            }

            return `[${serializedItems.join(',')}]`;
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
        const serializedEntries: string[] = [];
        for (const { descriptor, key } of entries) {
            if (descriptor.value === undefined) {
                throw new TypeError(
                    'Canonical objects cannot contain undefined.',
                );
            }
            const serializedKey = JSON.stringify(key);
            chargeCanonicalJsonByteLength(state, serializedKey.length + 1);
            if (containerDepth === 0 && key === 'objectType') {
                state.rootObjectType = descriptor.value;
            }
            serializedEntries.push(
                `${serializedKey}:${serializeCanonicalValue(
                    descriptor.value,
                    state,
                    containerDepth + 1,
                )}`,
            );
        }

        return `{${serializedEntries.join(',')}}`;
    } finally {
        state.activeContainers.delete(container);
    }
};

export const canonicalJsonWithRootObjectType = (
    value: unknown,
): Readonly<{ json: string; rootObjectType: unknown }> => {
    const state = createCanonicalJsonSerializationState();
    const json = serializeCanonicalValue(value, state, 0);

    return { json, rootObjectType: state.rootObjectType };
};

export const canonicalJson = (value: unknown): string =>
    canonicalJsonWithRootObjectType(value).json;

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
