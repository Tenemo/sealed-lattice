const identityByteLength = 64;
const allocationNonceByteLength = 32;
const chunkHeaderByteLength = 250;
const manifestHeaderByteLength = 176;
const manifestDescriptorByteLength = 78;
const completionParticipantCount = 10;

class TranscriptReader {
    #offset = 0;

    constructor(private readonly bytes: Uint8Array) {}

    get offset(): number {
        return this.#offset;
    }

    readU8(): number {
        return this.readFixed(1)[0] ?? 0;
    }

    readU16(): number {
        const bytes = this.readFixed(2);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(0, true);
    }

    readU32(): number {
        const bytes = this.readFixed(4);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint32(0, true);
    }

    readFixed(byteLength: number): Uint8Array {
        const end = this.#offset + byteLength;
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            end > this.bytes.byteLength
        ) {
            throw new Error('The padded-tally transcript is truncated.');
        }
        const result = Uint8Array.from(this.bytes.subarray(this.#offset, end));
        this.#offset = end;
        return result;
    }

    finish(): void {
        if (this.#offset !== this.bytes.byteLength) {
            throw new Error('The padded-tally transcript has trailing bytes.');
        }
    }
}

const requireMagic = (actual: Uint8Array, expected: string): void => {
    if (new TextDecoder().decode(actual) !== expected) {
        throw new Error('The padded-tally transcript has the wrong magic.');
    }
};

const requireBooleanByte = (value: number): boolean => {
    if (value !== 0 && value !== 1) {
        throw new Error('The padded-tally transcript has a noncanonical flag.');
    }
    return value === 1;
};

type ParsedPaddedTallyHeader = Readonly<{
    targetIdentity: Uint8Array;
    circuitIdentity: Uint8Array;
    participantCount: number;
    participantPosition: number;
    topCount: number;
    allocationNonce: Uint8Array;
}>;

export type ParsedPaddedTallyChunk = ParsedPaddedTallyHeader &
    Readonly<{
        chunkOrdinal: number;
        firstOperation: number;
        operationEnd: number;
        includesInitial: boolean;
        includesTerminal: boolean;
        previousChunkIdentity: Uint8Array;
        payloadByteLength: number;
    }>;

type ParsedPaddedTallyManifestDescriptor = Readonly<{
    firstOperation: number;
    operationEnd: number;
    includesInitial: boolean;
    includesTerminal: boolean;
    chunkByteLength: number;
    chunkIdentity: Uint8Array;
}>;

export type ParsedPaddedTallyManifest = ParsedPaddedTallyHeader &
    Readonly<{
        descriptors: readonly ParsedPaddedTallyManifestDescriptor[];
    }>;

const readCommonHeader = (
    reader: TranscriptReader,
    expectedMagic: string,
): ParsedPaddedTallyHeader => {
    requireMagic(reader.readFixed(4), expectedMagic);
    if (reader.readU16() !== 1) {
        throw new Error('The padded-tally transcript has the wrong version.');
    }
    const targetIdentity = reader.readFixed(identityByteLength);
    const circuitIdentity = reader.readFixed(identityByteLength);
    const participantCount = reader.readU16();
    const participantPosition = reader.readU16();
    const topCount = reader.readU16();
    const allocationNonce = reader.readFixed(allocationNonceByteLength);
    if (
        participantCount !== completionParticipantCount ||
        participantPosition >= participantCount ||
        topCount < 1 ||
        topCount > completionParticipantCount
    ) {
        throw new Error('The padded-tally transcript header is out of range.');
    }
    return {
        targetIdentity,
        circuitIdentity,
        participantCount,
        participantPosition,
        topCount,
        allocationNonce,
    };
};

export const parsePaddedTallyChunk = (
    bytes: Uint8Array,
): ParsedPaddedTallyChunk => {
    if (bytes.byteLength < chunkHeaderByteLength) {
        throw new Error('The padded-tally chunk omits its header.');
    }
    const reader = new TranscriptReader(bytes);
    const common = readCommonHeader(reader, 'SLPC');
    const chunkOrdinal = reader.readU32();
    const firstOperation = reader.readU32();
    const operationEnd = reader.readU32();
    const includesInitial = requireBooleanByte(reader.readU8());
    const includesTerminal = requireBooleanByte(reader.readU8());
    const previousChunkIdentity = reader.readFixed(identityByteLength);
    if (
        firstOperation > operationEnd ||
        reader.offset !== chunkHeaderByteLength
    ) {
        throw new Error('The padded-tally chunk range is invalid.');
    }
    const payloadByteLength = bytes.byteLength - reader.offset;
    reader.readFixed(payloadByteLength);
    reader.finish();
    return {
        ...common,
        chunkOrdinal,
        firstOperation,
        operationEnd,
        includesInitial,
        includesTerminal,
        previousChunkIdentity,
        payloadByteLength,
    };
};

export const parsePaddedTallyManifest = (
    bytes: Uint8Array,
): ParsedPaddedTallyManifest => {
    if (bytes.byteLength < manifestHeaderByteLength) {
        throw new Error('The padded-tally manifest omits its header.');
    }
    const reader = new TranscriptReader(bytes);
    const common = readCommonHeader(reader, 'SLPM');
    const descriptorCount = reader.readU32();
    if (
        descriptorCount < 1 ||
        bytes.byteLength !==
            manifestHeaderByteLength +
                descriptorCount * manifestDescriptorByteLength
    ) {
        throw new Error('The padded-tally manifest length is invalid.');
    }
    const descriptors = Array.from({ length: descriptorCount }, () => {
        const firstOperation = reader.readU32();
        const operationEnd = reader.readU32();
        const includesInitial = requireBooleanByte(reader.readU8());
        const includesTerminal = requireBooleanByte(reader.readU8());
        const chunkByteLength = reader.readU32();
        const chunkIdentity = reader.readFixed(identityByteLength);
        if (
            firstOperation > operationEnd ||
            chunkByteLength < chunkHeaderByteLength
        ) {
            throw new Error('The padded-tally manifest descriptor is invalid.');
        }
        return {
            firstOperation,
            operationEnd,
            includesInitial,
            includesTerminal,
            chunkByteLength,
            chunkIdentity,
        };
    });
    reader.finish();
    return { ...common, descriptors };
};

export type ParsedPaddedTallyTerminal = Readonly<{
    targetIdentity: Uint8Array;
    outputSchemaIdentity: Uint8Array;
    topCount: number;
    kind: 'no-result' | 'result';
    acceptedBallotAuthorship: readonly boolean[];
    orderedOptionPositions: readonly number[] | undefined;
}>;

export const parsePaddedTallyTerminal = (
    bytes: Uint8Array,
): ParsedPaddedTallyTerminal => {
    const reader = new TranscriptReader(bytes);
    requireMagic(reader.readFixed(4), 'SLPR');
    if (reader.readU16() !== 1) {
        throw new Error('The padded-tally terminal has the wrong version.');
    }
    const targetIdentity = reader.readFixed(identityByteLength);
    const outputSchemaIdentity = reader.readFixed(identityByteLength);
    const topCount = reader.readU16();
    const kindByte = reader.readU8();
    const acceptedBallotAuthorship = Array.from(
        { length: completionParticipantCount },
        () => requireBooleanByte(reader.readU8()),
    );
    const resultCount = reader.readU16();
    const orderedOptionPositions = Array.from({ length: resultCount }, () =>
        reader.readU16(),
    );
    reader.finish();
    if (
        topCount < 1 ||
        topCount > completionParticipantCount ||
        (kindByte !== 1 && kindByte !== 2) ||
        (kindByte === 1 && resultCount !== topCount) ||
        (kindByte === 2 && resultCount !== 0) ||
        new Set(orderedOptionPositions).size !== resultCount ||
        orderedOptionPositions.some(
            (position) => position >= completionParticipantCount,
        )
    ) {
        throw new Error('The padded-tally terminal relation is invalid.');
    }
    return {
        targetIdentity,
        outputSchemaIdentity,
        topCount,
        kind: kindByte === 1 ? 'result' : 'no-result',
        acceptedBallotAuthorship,
        orderedOptionPositions:
            kindByte === 1 ? orderedOptionPositions : undefined,
    };
};
