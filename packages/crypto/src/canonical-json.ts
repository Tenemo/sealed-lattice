import { shake256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const textEncoder = new TextEncoder();
const hash512PreimagePrefix = textEncoder.encode('sealed.vote/v1/hash512');

const isCanonicalInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && !Object.is(value, -0);

const isPlainObject = (
    value: unknown,
): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;

const hasOwnProperty = (value: object, key: PropertyKey): boolean =>
    Object.prototype.hasOwnProperty.call(value, key);

const normalizeCanonicalValue = (value: unknown): unknown => {
    if (value === null) {
        return null;
    }
    if (typeof value === 'string' || typeof value === 'boolean') {
        return value;
    }
    if (typeof value === 'number') {
        if (!isCanonicalInteger(value)) {
            throw new TypeError(
                'Canonical numeric fields must be safe integers.',
            );
        }

        return value;
    }
    if (Array.isArray(value)) {
        const normalized: unknown[] = [];
        for (let index = 0; index < value.length; index += 1) {
            if (!hasOwnProperty(value, index)) {
                throw new TypeError('Canonical arrays cannot be sparse.');
            }
            normalized.push(normalizeCanonicalValue(value[index]));
        }

        return normalized;
    }
    if (isPlainObject(value)) {
        const normalized = Object.create(null) as Record<string, unknown>;
        for (const key of Object.keys(value).sort()) {
            const entry = value[key];
            if (entry === undefined) {
                throw new TypeError(
                    'Canonical objects cannot contain undefined.',
                );
            }
            normalized[key] = normalizeCanonicalValue(entry);
        }

        return normalized;
    }

    throw new TypeError('Unsupported canonical value.');
};

export const canonicalJson = (value: unknown): string =>
    JSON.stringify(normalizeCanonicalValue(value));

const appendVarUint = (output: number[], value: number): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'Varuint values must be non-negative safe integers.',
        );
    }

    let remainingValue = value;
    for (;;) {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        output.push(byte);
        if (remainingValue === 0) {
            break;
        }
    }
};

const appendBytes = (output: number[], value: Uint8Array): void => {
    appendVarUint(output, value.byteLength);
    output.push(...value);
};

export const hash512 = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array => {
    const preimage = Array.from(hash512PreimagePrefix);

    appendBytes(preimage, textEncoder.encode(domain));
    appendVarUint(preimage, parts.length);
    for (const part of parts) {
        appendBytes(preimage, part);
    }

    return shake256(Uint8Array.from(preimage), { dkLen: 64 });
};

export const hash512Hex = (
    domain: string,
    parts: readonly Uint8Array[],
): string => bytesToHex(hash512(domain, parts));
