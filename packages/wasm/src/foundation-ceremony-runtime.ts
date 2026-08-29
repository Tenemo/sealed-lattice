import { isUint8Array } from './byte-array.js';
import {
    canonicalErrorCodeValues,
    configurableOptionCountRange,
    foundationProfile,
    isProtocolHash,
    refusalReasonCodes,
    type CanonicalError,
    type CanonicalErrorCode,
    type ProtocolHash,
    type RefusalReason,
    type VerificationResult,
} from './foundation-contract.js';
import type { FoundationKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import type {
    FoundationActionContextVerification,
    FoundationActionDefinitionVerification,
    FoundationBoardPolicyVerification,
    FoundationCeremonyContextVerification,
    FoundationManifestVerification,
} from './foundation-kernel/kernel-types.js';
import {
    bytesToHex,
    textDecoder,
    textEncoder,
} from './foundation-kernel/kernel-wasm-hash.js';

export type FoundationManifestInput = Readonly<{
    readonly displayTitle: string;
    readonly optionDefinitions: readonly Readonly<{
        readonly displayLabel: string;
        readonly optionIdentifier: string;
        readonly optionIndex: number;
    }>[];
}>;

export type CanonicalFoundationManifest = Readonly<{
    readonly canonicalBytes: Uint8Array;
    readonly manifestHash: ProtocolHash;
}>;

export type CanonicalFoundationActionDefinition = Readonly<{
    readonly actionDefinitionHash: ProtocolHash;
    readonly canonicalBytes: Uint8Array;
}>;

export type CanonicalFoundationBoardPolicy = Readonly<{
    readonly boardPolicyHash: ProtocolHash;
    readonly canonicalBytes: Uint8Array;
}>;

export type FoundationCeremonyRuntime = Readonly<{
    encodeActionDefinition(input: {
        readonly submissionCutoffUnixMilliseconds: bigint;
        readonly topCount: number;
    }): CanonicalFoundationActionDefinition;
    encodeBoardPolicy(input: {
        readonly boardOriginIdentifier: string;
    }): CanonicalFoundationBoardPolicy;
    encodeManifest(input: FoundationManifestInput): CanonicalFoundationManifest;
    verifyActionContext(input: {
        readonly actionIdentifier: string;
        readonly canonicalActionDefinitionBytes: Uint8Array;
        readonly canonicalBoardPolicyBytes: Uint8Array;
        readonly canonicalManifestBytes: Uint8Array;
        readonly canonicalRosterBytes: Uint8Array;
        readonly ceremonyIdentifier: string;
        readonly expectedCeremonyContextHash: ProtocolHash;
        readonly expectedSuiteId: ProtocolHash;
    }): FoundationActionContextVerification;
    verifyActionDefinition(
        canonicalBytes: Uint8Array,
    ): FoundationActionDefinitionVerification;
    verifyBoardPolicy(
        canonicalBytes: Uint8Array,
    ): FoundationBoardPolicyVerification;
    verifyCeremonyContext(input: {
        readonly canonicalManifestBytes: Uint8Array;
        readonly canonicalRosterBytes: Uint8Array;
        readonly ceremonyIdentifier: string;
        readonly expectedSuiteId: ProtocolHash;
    }): FoundationCeremonyContextVerification;
    verifyManifest(canonicalBytes: Uint8Array): FoundationManifestVerification;
}>;

const encodeManifestCommand = 1;
const verifyManifestCommand = 2;
const encodeActionDefinitionCommand = 3;
const verifyActionDefinitionCommand = 4;
const encodeBoardPolicyCommand = 5;
const verifyBoardPolicyCommand = 6;
const verifyCeremonyContextCommand = 7;
const verifyActionContextCommand = 8;
const maximumUnsigned64 = (1n << 64n) - 1n;
const hashByteLength = 64;
const maximumCopiedBufferByteLength =
    foundationProfile.maximumCopiedBufferByteLength;
const canonicalErrorCodes = new Set<CanonicalErrorCode>(
    canonicalErrorCodeValues,
);

export class FoundationKernelCommandError extends Error {
    readonly code: CanonicalErrorCode;

    constructor(error: CanonicalError) {
        super(`${error.code}: ${error.message}`);
        this.name = 'FoundationKernelCommandError';
        this.code = error.code;
    }
}

class BinaryWriter {
    readonly #chunks: Uint8Array[] = [];
    #length = 0;

    #writeFixed(bytes: Uint8Array): void {
        const requiredLength = this.#length + bytes.byteLength;
        if (
            !Number.isSafeInteger(requiredLength) ||
            requiredLength > maximumCopiedBufferByteLength
        ) {
            throw new RangeError(
                'The foundation command exceeds the copied-buffer limit.',
            );
        }
        this.#chunks.push(bytes);
        this.#length = requiredLength;
    }

    writeU8(value: number): void {
        if (!Number.isInteger(value) || value < 0 || value > 0xff) {
            throw new RangeError('The foundation command byte is invalid.');
        }
        this.#writeFixed(Uint8Array.of(value));
    }

    writeU16(value: number, fieldName: string): void {
        if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
            throw new RangeError(
                `${fieldName} must fit an unsigned 16-bit integer.`,
            );
        }
        const bytes = new Uint8Array(2);
        new DataView(bytes.buffer).setUint16(0, value, true);
        this.#writeFixed(bytes);
    }

    writeU64(value: bigint): void {
        const bytes = new Uint8Array(8);
        new DataView(bytes.buffer).setBigUint64(0, value, true);
        this.#writeFixed(bytes);
    }

    writeBytes(bytes: Uint8Array): void {
        const length = new Uint8Array(4);
        new DataView(length.buffer).setUint32(0, bytes.byteLength, true);
        this.#writeFixed(length);
        this.#writeFixed(bytes);
    }

    writeString(value: string): void {
        this.writeBytes(textEncoder.encode(value));
    }

    writeProtocolHash(value: ProtocolHash): void {
        const bytes = new Uint8Array(hashByteLength);
        for (let index = 0; index < hashByteLength; index += 1) {
            bytes[index] = Number.parseInt(
                value.slice(index * 2, index * 2 + 2),
                16,
            );
        }
        this.#writeFixed(bytes);
    }

    finish(): Uint8Array {
        const output = new Uint8Array(this.#length);
        let offset = 0;
        for (const chunk of this.#chunks) {
            output.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return output;
    }
}

class BinaryReader {
    #offset = 0;

    constructor(private readonly bytes: Uint8Array) {}

    readFixed(length: number): Uint8Array {
        const end = this.#offset + length;
        if (
            !Number.isSafeInteger(length) ||
            length < 0 ||
            end > this.bytes.byteLength
        ) {
            throw new Error(
                'The foundation kernel returned a truncated binary response.',
            );
        }
        const value = this.bytes.subarray(this.#offset, end);
        this.#offset = end;
        return value;
    }

    readU8(): number {
        return this.readFixed(1)[0] ?? 0;
    }

    readBytes(): Uint8Array {
        const lengthBytes = this.readFixed(4);
        const length = new DataView(
            lengthBytes.buffer,
            lengthBytes.byteOffset,
            lengthBytes.byteLength,
        ).getUint32(0, true);
        return this.readFixed(length);
    }

    readString(): string {
        try {
            return textDecoder.decode(this.readBytes());
        } catch {
            throw new Error(
                'The foundation kernel returned invalid UTF-8 in its binary response.',
            );
        }
    }

    finish(): void {
        if (this.#offset !== this.bytes.byteLength) {
            throw new Error(
                'The foundation kernel returned trailing binary response bytes.',
            );
        }
    }
}

const snapshotDataProperty = (
    container: unknown,
    propertyName: string,
    containerName: string,
): unknown => {
    if (
        container === null ||
        (typeof container !== 'object' && typeof container !== 'function')
    ) {
        throw new TypeError(`${containerName} must be an object.`);
    }
    let descriptor: PropertyDescriptor | undefined;
    try {
        descriptor = Object.getOwnPropertyDescriptor(container, propertyName);
    } catch {
        throw new TypeError(
            `${containerName}.${propertyName} must be an ordinary data property.`,
        );
    }
    if (descriptor === undefined || !('value' in descriptor)) {
        throw new TypeError(
            `${containerName}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const snapshotSafeInteger = (value: unknown, fieldName: string): number => {
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
        throw new TypeError(`${fieldName} must be a safe integer.`);
    }
    return value;
};

const copyCanonicalBytes = (value: unknown, fieldName: string): Uint8Array => {
    if (!isUint8Array(value)) {
        throw new TypeError(`${fieldName} must be a Uint8Array.`);
    }
    try {
        return Uint8Array.from(value);
    } catch {
        throw new TypeError(
            `${fieldName} must reference an attached Uint8Array.`,
        );
    }
};

const isWellFormedString = (value: string): boolean => {
    for (
        let codeUnitIndex = 0;
        codeUnitIndex < value.length;
        codeUnitIndex += 1
    ) {
        const codeUnit = value.charCodeAt(codeUnitIndex);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const followingCodeUnit = value.charCodeAt(codeUnitIndex + 1);
            if (
                codeUnitIndex + 1 >= value.length ||
                followingCodeUnit < 0xdc00 ||
                followingCodeUnit > 0xdfff
            ) {
                return false;
            }
            codeUnitIndex += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            return false;
        }
    }
    return true;
};

const requireWellFormedString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !isWellFormedString(value)) {
        throw new TypeError(`${fieldName} must be a well-formed string.`);
    }
    return value;
};

const requireProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (!isProtocolHash(value)) {
        throw new TypeError(`${fieldName} must be a lowercase 512-bit hash.`);
    }
    return value;
};

const snapshotManifestInput = (input: unknown): FoundationManifestInput => {
    const displayTitle = requireWellFormedString(
        snapshotDataProperty(input, 'displayTitle', 'input'),
        'displayTitle',
    );
    const optionDefinitionsValue = snapshotDataProperty(
        input,
        'optionDefinitions',
        'input',
    );
    if (!Array.isArray(optionDefinitionsValue)) {
        throw new TypeError('optionDefinitions must be an array.');
    }
    const optionDefinitionCount = snapshotSafeInteger(
        snapshotDataProperty(
            optionDefinitionsValue,
            'length',
            'optionDefinitions',
        ),
        'optionDefinitions.length',
    );
    if (
        optionDefinitionCount < configurableOptionCountRange.minimum ||
        optionDefinitionCount > configurableOptionCountRange.maximum
    ) {
        throw new RangeError(
            `optionDefinitions must contain from ${String(configurableOptionCountRange.minimum)} through ${String(configurableOptionCountRange.maximum)} entries.`,
        );
    }
    const optionDefinitions = Array.from(
        { length: optionDefinitionCount },
        (_unused, optionPosition) => {
            const optionName = `optionDefinitions[${String(optionPosition)}]`;
            const optionDefinition = snapshotDataProperty(
                optionDefinitionsValue,
                String(optionPosition),
                'optionDefinitions',
            );
            return Object.freeze({
                displayLabel: requireWellFormedString(
                    snapshotDataProperty(
                        optionDefinition,
                        'displayLabel',
                        optionName,
                    ),
                    `${optionName}.displayLabel`,
                ),
                optionIdentifier: requireWellFormedString(
                    snapshotDataProperty(
                        optionDefinition,
                        'optionIdentifier',
                        optionName,
                    ),
                    `${optionName}.optionIdentifier`,
                ),
                optionIndex: snapshotSafeInteger(
                    snapshotDataProperty(
                        optionDefinition,
                        'optionIndex',
                        optionName,
                    ),
                    `${optionName}.optionIndex`,
                ),
            });
        },
    );
    return Object.freeze({ displayTitle, optionDefinitions });
};

const readHash = (reader: BinaryReader): ProtocolHash =>
    bytesToHex(reader.readFixed(hashByteLength));

const isCanonicalErrorCode = (value: string): value is CanonicalErrorCode =>
    canonicalErrorCodes.has(value as CanonicalErrorCode);

const isRefusalReason = (value: string): value is RefusalReason =>
    Object.prototype.hasOwnProperty.call(refusalReasonCodes, value);

const executeCommand = <Result>(
    runtime: FoundationKernelCommandRuntime,
    request: BinaryWriter,
    decodeResult: (reader: BinaryReader) => Result,
): Result => {
    const reader = new BinaryReader(runtime.executeCommand(request.finish()));
    const status = reader.readU8();
    if (status === 1) {
        const code = reader.readString();
        const message = reader.readString();
        reader.finish();
        if (!isCanonicalErrorCode(code)) {
            throw new Error(
                'The foundation kernel returned an unknown command error code.',
            );
        }
        throw new FoundationKernelCommandError({ code, message });
    }
    if (status !== 0) {
        throw new Error(
            'The foundation kernel returned an invalid command status.',
        );
    }
    const result = decodeResult(reader);
    reader.finish();
    return result;
};

const readVerification = <Value>(
    reader: BinaryReader,
    readValue: (reader: BinaryReader) => Value,
): VerificationResult<Value> => {
    const status = reader.readU8();
    if (status === 1) {
        return { isValid: true, value: readValue(reader) };
    }
    if (status === 0) {
        const refusalReason = reader.readString();
        if (!isRefusalReason(refusalReason)) {
            throw new Error(
                'The foundation kernel returned an unknown refusal reason.',
            );
        }
        return { isValid: false, refusalReason };
    }
    throw new Error(
        'The foundation kernel returned an invalid verification status.',
    );
};

const canonicalInputCommand = (
    command: number,
    canonicalBytes: unknown,
): BinaryWriter => {
    const request = new BinaryWriter();
    request.writeU8(command);
    request.writeBytes(copyCanonicalBytes(canonicalBytes, 'canonicalBytes'));
    return request;
};

export const openFoundationCeremonyRuntime = (
    kernel: FoundationKernelCommandRuntime,
): FoundationCeremonyRuntime => ({
    encodeActionDefinition: (input) => {
        const submissionCutoffUnixMilliseconds = snapshotDataProperty(
            input,
            'submissionCutoffUnixMilliseconds',
            'input',
        );
        const topCount = snapshotSafeInteger(
            snapshotDataProperty(input, 'topCount', 'input'),
            'topCount',
        );
        if (
            typeof submissionCutoffUnixMilliseconds !== 'bigint' ||
            submissionCutoffUnixMilliseconds < 0n ||
            submissionCutoffUnixMilliseconds > maximumUnsigned64
        ) {
            throw new RangeError(
                'submissionCutoffUnixMilliseconds must fit an unsigned 64-bit integer.',
            );
        }
        const request = new BinaryWriter();
        request.writeU8(encodeActionDefinitionCommand);
        request.writeU16(topCount, 'topCount');
        request.writeU64(submissionCutoffUnixMilliseconds);
        return executeCommand(kernel, request, (reader) =>
            Object.freeze({
                canonicalBytes: Uint8Array.from(reader.readBytes()),
                actionDefinitionHash: readHash(reader),
            }),
        );
    },
    encodeBoardPolicy: (input) => {
        const boardOriginIdentifier = requireWellFormedString(
            snapshotDataProperty(input, 'boardOriginIdentifier', 'input'),
            'boardOriginIdentifier',
        );
        const request = new BinaryWriter();
        request.writeU8(encodeBoardPolicyCommand);
        request.writeString(boardOriginIdentifier);
        return executeCommand(kernel, request, (reader) =>
            Object.freeze({
                canonicalBytes: Uint8Array.from(reader.readBytes()),
                boardPolicyHash: readHash(reader),
            }),
        );
    },
    encodeManifest: (input) => {
        const snapshot = snapshotManifestInput(input);
        const request = new BinaryWriter();
        request.writeU8(encodeManifestCommand);
        request.writeString(snapshot.displayTitle);
        request.writeU16(
            snapshot.optionDefinitions.length,
            'optionDefinitions.length',
        );
        for (const [
            optionPosition,
            optionDefinition,
        ] of snapshot.optionDefinitions.entries()) {
            request.writeU16(
                optionDefinition.optionIndex,
                `optionDefinitions[${String(optionPosition)}].optionIndex`,
            );
            request.writeString(optionDefinition.optionIdentifier);
            request.writeString(optionDefinition.displayLabel);
        }
        return executeCommand(kernel, request, (reader) =>
            Object.freeze({
                canonicalBytes: Uint8Array.from(reader.readBytes()),
                manifestHash: readHash(reader),
            }),
        );
    },
    verifyActionContext: (input) => {
        const request = new BinaryWriter();
        request.writeU8(verifyActionContextCommand);
        request.writeBytes(
            copyCanonicalBytes(
                snapshotDataProperty(input, 'canonicalManifestBytes', 'input'),
                'canonicalManifestBytes',
            ),
        );
        request.writeBytes(
            copyCanonicalBytes(
                snapshotDataProperty(input, 'canonicalRosterBytes', 'input'),
                'canonicalRosterBytes',
            ),
        );
        request.writeBytes(
            copyCanonicalBytes(
                snapshotDataProperty(
                    input,
                    'canonicalActionDefinitionBytes',
                    'input',
                ),
                'canonicalActionDefinitionBytes',
            ),
        );
        request.writeBytes(
            copyCanonicalBytes(
                snapshotDataProperty(
                    input,
                    'canonicalBoardPolicyBytes',
                    'input',
                ),
                'canonicalBoardPolicyBytes',
            ),
        );
        request.writeString(
            requireWellFormedString(
                snapshotDataProperty(input, 'ceremonyIdentifier', 'input'),
                'ceremonyIdentifier',
            ),
        );
        request.writeString(
            requireWellFormedString(
                snapshotDataProperty(input, 'actionIdentifier', 'input'),
                'actionIdentifier',
            ),
        );
        request.writeProtocolHash(
            requireProtocolHash(
                snapshotDataProperty(input, 'expectedSuiteId', 'input'),
                'expectedSuiteId',
            ),
        );
        request.writeProtocolHash(
            requireProtocolHash(
                snapshotDataProperty(
                    input,
                    'expectedCeremonyContextHash',
                    'input',
                ),
                'expectedCeremonyContextHash',
            ),
        );
        return executeCommand(kernel, request, (reader) =>
            readVerification(reader, (response) => ({
                suiteId: readHash(response),
                rosterHash: readHash(response),
                ceremonyContextHash: readHash(response),
                actionDefinitionHash: readHash(response),
                boardPolicyHash: readHash(response),
                actionContextHash: readHash(response),
                submissionCutoffHash: readHash(response),
            })),
        );
    },
    verifyActionDefinition: (canonicalBytes) =>
        executeCommand(
            kernel,
            canonicalInputCommand(
                verifyActionDefinitionCommand,
                canonicalBytes,
            ),
            (reader) =>
                readVerification(reader, (response) => ({
                    actionDefinitionHash: readHash(response),
                })),
        ),
    verifyBoardPolicy: (canonicalBytes) =>
        executeCommand(
            kernel,
            canonicalInputCommand(verifyBoardPolicyCommand, canonicalBytes),
            (reader) =>
                readVerification(reader, (response) => ({
                    boardPolicyHash: readHash(response),
                })),
        ),
    verifyCeremonyContext: (input) => {
        const request = new BinaryWriter();
        request.writeU8(verifyCeremonyContextCommand);
        request.writeBytes(
            copyCanonicalBytes(
                snapshotDataProperty(input, 'canonicalManifestBytes', 'input'),
                'canonicalManifestBytes',
            ),
        );
        request.writeBytes(
            copyCanonicalBytes(
                snapshotDataProperty(input, 'canonicalRosterBytes', 'input'),
                'canonicalRosterBytes',
            ),
        );
        request.writeString(
            requireWellFormedString(
                snapshotDataProperty(input, 'ceremonyIdentifier', 'input'),
                'ceremonyIdentifier',
            ),
        );
        request.writeProtocolHash(
            requireProtocolHash(
                snapshotDataProperty(input, 'expectedSuiteId', 'input'),
                'expectedSuiteId',
            ),
        );
        return executeCommand(kernel, request, (reader) =>
            readVerification(reader, (response) => ({
                suiteId: readHash(response),
                manifestHash: readHash(response),
                rosterHash: readHash(response),
                ceremonyContextHash: readHash(response),
            })),
        );
    },
    verifyManifest: (canonicalBytes) =>
        executeCommand(
            kernel,
            canonicalInputCommand(verifyManifestCommand, canonicalBytes),
            (reader) =>
                readVerification(reader, (response) => ({
                    manifestHash: readHash(response),
                })),
        ),
});
