import type {
    RefusalReason,
    VerificationResult,
} from '@sealed-lattice/types';

import type {
    DecodedProofApplicationBinding,
    TranscriptCoreKernel,
} from './transcript-core-bridge/kernel-types.js';
import { TranscriptCoreKernelCommandError } from './transcript-core-bridge/kernel-runtime.js';

const foundationHashByteLength = 64;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const lowercaseHexPattern = /^(?:[0-9a-f]{2})+$/u;
const canonicalUnsignedDecimalPattern = /^(?:0|[1-9][0-9]*)$/u;

declare const verifiedProofApplicationBindingBrand: unique symbol;

export type VerifiedProofApplicationBinding = Readonly<{
    readonly [verifiedProofApplicationBindingBrand]: true;
}>;

export type ProofApplicationAuthorityContext = Readonly<{
    actionContextHash: Uint8Array;
    ceremonyContextHash: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

export type ProofApplicationBindingDescription = Readonly<{
    actionContextHash: Uint8Array;
    applicationSlotCanonicalBytes: Uint8Array;
    applicationSlotHash: Uint8Array;
    applicationStatementSchemaIdentifier: number;
    canonicalBindingBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    producerSequence?: bigint;
    proofByteLength: bigint;
    proofHeaderHash: Uint8Array;
    proofStreamDescriptorCanonicalBytes: Uint8Array;
    rosterPosition?: number;
    schedulePosition?: number;
    suiteIdentifier: Uint8Array;
}>;

const verifiedBindingDescriptions = new WeakMap<
    object,
    ProofApplicationBindingDescription
>();

const copyDescription = (
    description: ProofApplicationBindingDescription,
): ProofApplicationBindingDescription =>
    Object.freeze({
        actionContextHash: description.actionContextHash.slice(),
        applicationSlotCanonicalBytes:
            description.applicationSlotCanonicalBytes.slice(),
        applicationSlotHash: description.applicationSlotHash.slice(),
        applicationStatementSchemaIdentifier:
            description.applicationStatementSchemaIdentifier,
        canonicalBindingBytes: description.canonicalBindingBytes.slice(),
        ceremonyContextHash: description.ceremonyContextHash.slice(),
        ...(description.producerSequence === undefined
            ? {}
            : { producerSequence: description.producerSequence }),
        proofByteLength: description.proofByteLength,
        proofHeaderHash: description.proofHeaderHash.slice(),
        proofStreamDescriptorCanonicalBytes:
            description.proofStreamDescriptorCanonicalBytes.slice(),
        ...(description.rosterPosition === undefined
            ? {}
            : { rosterPosition: description.rosterPosition }),
        ...(description.schedulePosition === undefined
            ? {}
            : { schedulePosition: description.schedulePosition }),
        suiteIdentifier: description.suiteIdentifier.slice(),
    });

export const copyVerifiedProofApplicationBinding = (
    binding: VerifiedProofApplicationBinding,
): ProofApplicationBindingDescription => {
    if (
        (typeof binding !== 'object' && typeof binding !== 'function') ||
        binding === null
    ) {
        throw new TypeError(
            'The proof application binding was not issued by the WASM verifier.',
        );
    }
    const description = verifiedBindingDescriptions.get(binding);
    if (description === undefined) {
        throw new TypeError(
            'The proof application binding was not issued by the WASM verifier.',
        );
    }
    return copyDescription(description);
};

export const verifyProofApplicationBinding = (
    kernel: TranscriptCoreKernel,
    input: Readonly<{
        authorityContext: ProofApplicationAuthorityContext;
        canonicalBindingBytes: Uint8Array;
    }>,
): VerificationResult<VerifiedProofApplicationBinding> => {
    let canonicalBindingBytes: Uint8Array;
    let authorityContext: ProofApplicationAuthorityContext;
    try {
        canonicalBindingBytes = copyBytes(
            input.canonicalBindingBytes,
            undefined,
            false,
            'canonicalBindingBytes',
        );
        authorityContext = copyAuthorityContext(input.authorityContext);
    } catch {
        return refused('wrongTypeOrLength');
    }

    let decoded: DecodedProofApplicationBinding;
    try {
        decoded = kernel.decodeProofApplicationBinding({
            canonicalBytesHex: bytesToHex(canonicalBindingBytes),
        });
    } catch (error) {
        canonicalBindingBytes.fill(0);
        if (error instanceof TranscriptCoreKernelCommandError) {
            return refused('malformedEncoding');
        }
        throw error;
    }

    let description: ProofApplicationBindingDescription;
    try {
        description = descriptionFromKernel(decoded);
    } catch {
        canonicalBindingBytes.fill(0);
        throw new Error(
            'The WASM kernel returned a malformed proof application binding description.',
        );
    }
    if (!bytesEqual(description.canonicalBindingBytes, canonicalBindingBytes)) {
        canonicalBindingBytes.fill(0);
        destroyDescription(description);
        throw new Error(
            'The WASM kernel changed canonical proof application binding bytes.',
        );
    }
    canonicalBindingBytes.fill(0);
    if (
        !bytesEqual(
            description.suiteIdentifier,
            authorityContext.suiteIdentifier,
        ) ||
        !bytesEqual(
            description.ceremonyContextHash,
            authorityContext.ceremonyContextHash,
        ) ||
        !bytesEqual(
            description.actionContextHash,
            authorityContext.actionContextHash,
        )
    ) {
        destroyDescription(description);
        return refused('wrongContext');
    }

    const binding = Object.freeze({}) as VerifiedProofApplicationBinding;
    verifiedBindingDescriptions.set(binding, copyDescription(description));
    destroyDescription(description);
    return Object.freeze({ isValid: true, value: binding });
};

const descriptionFromKernel = (
    value: DecodedProofApplicationBinding,
): ProofApplicationBindingDescription => {
    if (
        typeof value !== 'object' ||
        value === null ||
        !Number.isInteger(value.applicationStatementSchemaIdentifier) ||
        value.applicationStatementSchemaIdentifier <= 0 ||
        value.applicationStatementSchemaIdentifier > 0xffff
    ) {
        throw new TypeError('Malformed proof application binding description.');
    }
    return Object.freeze({
        actionContextHash: hexToBytes(
            value.actionContextHash,
            foundationHashByteLength,
            'actionContextHash',
        ),
        applicationSlotCanonicalBytes: hexToBytes(
            value.applicationSlotCanonicalBytesHex,
            undefined,
            'applicationSlotCanonicalBytesHex',
        ),
        applicationSlotHash: hexToBytes(
            value.applicationSlotHash,
            foundationHashByteLength,
            'applicationSlotHash',
        ),
        applicationStatementSchemaIdentifier:
            value.applicationStatementSchemaIdentifier,
        canonicalBindingBytes: hexToBytes(
            value.canonicalBytesHex,
            undefined,
            'canonicalBytesHex',
        ),
        ceremonyContextHash: hexToBytes(
            value.ceremonyContextHash,
            foundationHashByteLength,
            'ceremonyContextHash',
        ),
        ...(value.producerSequence === null
            ? {}
            : {
                  producerSequence: parseUnsigned64(
                      value.producerSequence,
                      'producerSequence',
                  ),
              }),
        proofByteLength: parsePositiveUnsigned64(
            value.proofByteLength,
            'proofByteLength',
        ),
        proofHeaderHash: hexToBytes(
            value.proofHeaderHash,
            foundationHashByteLength,
            'proofHeaderHash',
        ),
        proofStreamDescriptorCanonicalBytes: hexToBytes(
            value.proofStreamDescriptorCanonicalBytesHex,
            undefined,
            'proofStreamDescriptorCanonicalBytesHex',
        ),
        ...(value.rosterPosition === null
            ? {}
            : {
                  rosterPosition: parseUnsignedInteger(
                      value.rosterPosition,
                      0xffff,
                      'rosterPosition',
                  ),
              }),
        ...(value.schedulePosition === null
            ? {}
            : {
                  schedulePosition: parseUnsignedInteger(
                      value.schedulePosition,
                      0xffff_ffff,
                      'schedulePosition',
                  ),
              }),
        suiteIdentifier: hexToBytes(
            value.suiteIdentifier,
            foundationHashByteLength,
            'suiteIdentifier',
        ),
    });
};

const copyAuthorityContext = (
    value: ProofApplicationAuthorityContext,
): ProofApplicationAuthorityContext => {
    if (typeof value !== 'object' || value === null) {
        throw new TypeError('authorityContext must be an object.');
    }
    return Object.freeze({
        actionContextHash: copyBytes(
            value.actionContextHash,
            foundationHashByteLength,
            false,
            'actionContextHash',
        ),
        ceremonyContextHash: copyBytes(
            value.ceremonyContextHash,
            foundationHashByteLength,
            false,
            'ceremonyContextHash',
        ),
        suiteIdentifier: copyBytes(
            value.suiteIdentifier,
            foundationHashByteLength,
            false,
            'suiteIdentifier',
        ),
    });
};

const copyBytes = (
    value: unknown,
    exactByteLength: number | undefined,
    allowEmpty: boolean,
    label: string,
): Uint8Array => {
    if (
        !ArrayBuffer.isView(value) ||
        Object.prototype.toString.call(value) !== '[object Uint8Array]' ||
        (!allowEmpty && value.byteLength === 0) ||
        (exactByteLength !== undefined &&
            value.byteLength !== exactByteLength)
    ) {
        throw new TypeError(`${label} has an invalid byte length.`);
    }
    return (value as Uint8Array).slice();
};

const hexToBytes = (
    value: unknown,
    exactByteLength: number | undefined,
    label: string,
): Uint8Array => {
    if (
        typeof value !== 'string' ||
        value.length === 0 ||
        !lowercaseHexPattern.test(value) ||
        (exactByteLength !== undefined &&
            value.length !== exactByteLength * 2)
    ) {
        throw new TypeError(`${label} is not canonical lowercase hexadecimal.`);
    }
    const bytes = new Uint8Array(value.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

const parseUnsignedInteger = (
    value: unknown,
    maximum: number,
    label: string,
): number => {
    if (
        !Number.isSafeInteger(value) ||
        (value as number) < 0 ||
        (value as number) > maximum
    ) {
        throw new TypeError(`${label} is outside its unsigned range.`);
    }
    return value as number;
};

const parseUnsigned64 = (value: unknown, label: string): bigint => {
    if (
        typeof value !== 'string' ||
        !canonicalUnsignedDecimalPattern.test(value)
    ) {
        throw new TypeError(`${label} is not a canonical unsigned decimal.`);
    }
    const parsed = BigInt(value);
    if (parsed > maximumUnsigned64) {
        throw new TypeError(`${label} exceeds unsigned 64-bit range.`);
    }
    return parsed;
};

const parsePositiveUnsigned64 = (value: unknown, label: string): bigint => {
    const parsed = parseUnsigned64(value, label);
    if (parsed === 0n) {
        throw new TypeError(`${label} must be positive.`);
    }
    return parsed;
};

const destroyDescription = (
    description: ProofApplicationBindingDescription,
): void => {
    description.actionContextHash.fill(0);
    description.applicationSlotCanonicalBytes.fill(0);
    description.applicationSlotHash.fill(0);
    description.canonicalBindingBytes.fill(0);
    description.ceremonyContextHash.fill(0);
    description.proofHeaderHash.fill(0);
    description.proofStreamDescriptorCanonicalBytes.fill(0);
    description.suiteIdentifier.fill(0);
};

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> =>
    Object.freeze({ isValid: false, refusalReason });
