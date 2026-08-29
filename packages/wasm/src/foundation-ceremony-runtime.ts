import {
    canonicalErrorCodeValues,
    configurableOptionCountRange,
    isProtocolHash,
    maximumFoundationCopiedBufferByteLength,
    refusalReasonValues,
    type CanonicalError,
    type CanonicalErrorCode,
    type ProtocolHash,
    type RefusalReason,
    type VerificationResult,
} from './foundation-contract.js';
import {
    instantiateFoundationKernelCommandRuntime,
    type FoundationKernelCommandRuntime,
    type FoundationKernelLoaderOptions,
} from './foundation-kernel/kernel-runtime.js';

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

export type FoundationManifestVerification = VerificationResult<{
    readonly manifestHash: ProtocolHash;
}>;

export type FoundationActionDefinitionVerification = VerificationResult<{
    readonly actionDefinitionHash: ProtocolHash;
}>;

export type FoundationBoardPolicyVerification = VerificationResult<{
    readonly boardPolicyHash: ProtocolHash;
}>;

export type FoundationCeremonyContextVerification = VerificationResult<{
    readonly ceremonyContextHash: ProtocolHash;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly suiteId: ProtocolHash;
}>;

export type FoundationActionContextVerification = VerificationResult<{
    readonly actionContextHash: ProtocolHash;
    readonly actionDefinitionHash: ProtocolHash;
    readonly boardPolicyHash: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly submissionCutoffHash: ProtocolHash;
    readonly suiteId: ProtocolHash;
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
const maximumCopiedBufferByteLength = maximumFoundationCopiedBufferByteLength;
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const textEncoder = new TextEncoder();
const canonicalErrorCodes = new Set<CanonicalErrorCode>(
    canonicalErrorCodeValues,
);
const refusalReasons = new Set<RefusalReason>(refusalReasonValues);
const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

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

const requireSafeInteger = (value: unknown, fieldName: string): number => {
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
        throw new TypeError(`${fieldName} must be a safe integer.`);
    }
    return value;
};

const requireCanonicalBytes = (
    value: unknown,
    fieldName: string,
): Uint8Array => {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError(`${fieldName} must be a Uint8Array.`);
    }
    return value;
};

const requireWellFormedString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !value.isWellFormed()) {
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

const validateManifestInput = (
    input: FoundationManifestInput,
): FoundationManifestInput => {
    const displayTitle = requireWellFormedString(
        input.displayTitle,
        'displayTitle',
    );
    const rawOptionDefinitions: unknown = input.optionDefinitions;
    if (!Array.isArray(rawOptionDefinitions)) {
        throw new TypeError('optionDefinitions must be an array.');
    }
    const optionDefinitionsValue: readonly unknown[] = rawOptionDefinitions;
    const optionDefinitionCount = requireSafeInteger(
        optionDefinitionsValue.length,
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
            const optionDefinition = optionDefinitionsValue[optionPosition];
            if (
                optionDefinition === null ||
                typeof optionDefinition !== 'object'
            ) {
                throw new TypeError(`${optionName} must be an object.`);
            }
            const optionDefinitionRecord = optionDefinition as Readonly<
                Record<string, unknown>
            >;
            return {
                displayLabel: requireWellFormedString(
                    optionDefinitionRecord.displayLabel,
                    `${optionName}.displayLabel`,
                ),
                optionIdentifier: requireWellFormedString(
                    optionDefinitionRecord.optionIdentifier,
                    `${optionName}.optionIdentifier`,
                ),
                optionIndex: requireSafeInteger(
                    optionDefinitionRecord.optionIndex,
                    `${optionName}.optionIndex`,
                ),
            };
        },
    );
    return { displayTitle, optionDefinitions };
};

const readHash = (reader: BinaryReader): ProtocolHash =>
    bytesToHex(reader.readFixed(hashByteLength));

const isCanonicalErrorCode = (value: string): value is CanonicalErrorCode =>
    canonicalErrorCodes.has(value as CanonicalErrorCode);

const isRefusalReason = (value: string): value is RefusalReason =>
    refusalReasons.has(value as RefusalReason);

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
    request.writeBytes(requireCanonicalBytes(canonicalBytes, 'canonicalBytes'));
    return request;
};

export const openFoundationCeremonyRuntime = (
    kernel: FoundationKernelCommandRuntime,
): FoundationCeremonyRuntime => ({
    encodeActionDefinition: (input) => {
        const { submissionCutoffUnixMilliseconds } = input;
        const topCount = requireSafeInteger(input.topCount, 'topCount');
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
        return executeCommand(kernel, request, (reader) => ({
            canonicalBytes: Uint8Array.from(reader.readBytes()),
            actionDefinitionHash: readHash(reader),
        }));
    },
    encodeBoardPolicy: (input) => {
        const boardOriginIdentifier = requireWellFormedString(
            input.boardOriginIdentifier,
            'boardOriginIdentifier',
        );
        const request = new BinaryWriter();
        request.writeU8(encodeBoardPolicyCommand);
        request.writeString(boardOriginIdentifier);
        return executeCommand(kernel, request, (reader) => ({
            canonicalBytes: Uint8Array.from(reader.readBytes()),
            boardPolicyHash: readHash(reader),
        }));
    },
    encodeManifest: (input) => {
        const manifest = validateManifestInput(input);
        const request = new BinaryWriter();
        request.writeU8(encodeManifestCommand);
        request.writeString(manifest.displayTitle);
        request.writeU16(
            manifest.optionDefinitions.length,
            'optionDefinitions.length',
        );
        for (const [
            optionPosition,
            optionDefinition,
        ] of manifest.optionDefinitions.entries()) {
            request.writeU16(
                optionDefinition.optionIndex,
                `optionDefinitions[${String(optionPosition)}].optionIndex`,
            );
            request.writeString(optionDefinition.optionIdentifier);
            request.writeString(optionDefinition.displayLabel);
        }
        return executeCommand(kernel, request, (reader) => ({
            canonicalBytes: Uint8Array.from(reader.readBytes()),
            manifestHash: readHash(reader),
        }));
    },
    verifyActionContext: (input) => {
        const request = new BinaryWriter();
        request.writeU8(verifyActionContextCommand);
        request.writeBytes(
            requireCanonicalBytes(
                input.canonicalManifestBytes,
                'canonicalManifestBytes',
            ),
        );
        request.writeBytes(
            requireCanonicalBytes(
                input.canonicalRosterBytes,
                'canonicalRosterBytes',
            ),
        );
        request.writeBytes(
            requireCanonicalBytes(
                input.canonicalActionDefinitionBytes,
                'canonicalActionDefinitionBytes',
            ),
        );
        request.writeBytes(
            requireCanonicalBytes(
                input.canonicalBoardPolicyBytes,
                'canonicalBoardPolicyBytes',
            ),
        );
        request.writeString(
            requireWellFormedString(
                input.ceremonyIdentifier,
                'ceremonyIdentifier',
            ),
        );
        request.writeString(
            requireWellFormedString(input.actionIdentifier, 'actionIdentifier'),
        );
        request.writeProtocolHash(
            requireProtocolHash(input.expectedSuiteId, 'expectedSuiteId'),
        );
        request.writeProtocolHash(
            requireProtocolHash(
                input.expectedCeremonyContextHash,
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
            requireCanonicalBytes(
                input.canonicalManifestBytes,
                'canonicalManifestBytes',
            ),
        );
        request.writeBytes(
            requireCanonicalBytes(
                input.canonicalRosterBytes,
                'canonicalRosterBytes',
            ),
        );
        request.writeString(
            requireWellFormedString(
                input.ceremonyIdentifier,
                'ceremonyIdentifier',
            ),
        );
        request.writeProtocolHash(
            requireProtocolHash(input.expectedSuiteId, 'expectedSuiteId'),
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

export const createFoundationCeremonyRuntimeLoader = (
    foundationKernelUrl: URL,
    options: FoundationKernelLoaderOptions = {},
): (() => Promise<FoundationCeremonyRuntime>) => {
    let runtimePromise: Promise<FoundationCeremonyRuntime> | undefined;
    return async () => {
        runtimePromise ??= instantiateFoundationKernelCommandRuntime(
            foundationKernelUrl,
            options,
        )
            .then(openFoundationCeremonyRuntime)
            .catch((error: unknown) => {
                runtimePromise = undefined;
                throw error;
            });
        return runtimePromise;
    };
};
