import {
    concatenate,
    encodeText,
    fromHexadecimal,
    hexadecimal,
} from '../shared/bytes.js';

// Opaque transport identifiers name bytes, never a protocol identity or a
// verified capability. Fixed chunking bounds both manifest and request counts.
export const candidateChunkBytes = 1 << 20;
export const candidateIdentifierBytes = 16;
export const candidatePageEntries = 64;
export const candidateManifestBytes = 1 << 20;
const candidateMaximumFileBytes = 0xffff_fffb;
const candidateMaximumFiles = 256;
const candidateNameBytes = 160;
const candidateKeyBytes = 256;

const segment = '[a-z0-9]+(?:[.-][a-z0-9]+)*';
const filePattern = new RegExp('^' + segment + '$', 'u');
const keyPattern = new RegExp('^' + segment + '(?:/' + segment + ')*$', 'u');
export const isCandidateId = (value: string) => /^[0-9a-f]{32}$/u.test(value);
export const isCandidateFileName = (value: string) =>
    value.length <= candidateNameBytes && filePattern.test(value);
export const isCandidateKey = (value: string) =>
    value.length <= candidateKeyBytes && keyPattern.test(value);

export type CandidateFile = Readonly<{
    name: string;
    length: number;
    chunks: readonly string[];
}>;
export type CandidateManifest = Readonly<{ files: readonly CandidateFile[] }>;
export type CandidateReceipt = Readonly<{ id: string; index: number }>;
export type CandidatePage = Readonly<{ total: number; ids: readonly string[] }>;

const malformed = () => new RangeError('Malformed candidate transport record.');
const safeLength = (value: number) => Number.isSafeInteger(value) && value >= 0;
const magic = encodeText('RCM1');

export const encodeCandidateManifest = (manifest: CandidateManifest) => {
    const files = [...manifest.files].sort((left, right) =>
        left.name < right.name ? -1 : left.name === right.name ? 0 : 1,
    );
    if (files.length === 0 || files.length > candidateMaximumFiles)
        throw malformed();
    let length = 6;
    for (const [index, file] of files.entries()) {
        if (
            !isCandidateFileName(file.name) ||
            (index > 0 && files[index - 1].name === file.name) ||
            !safeLength(file.length) ||
            file.length > candidateMaximumFileBytes ||
            file.chunks.length !==
                Math.ceil(file.length / candidateChunkBytes) ||
            file.chunks.some((id) => !isCandidateId(id))
        )
            throw malformed();
        length +=
            2 +
            file.name.length +
            8 +
            candidateIdentifierBytes * file.chunks.length;
        if (length > candidateManifestBytes) throw malformed();
    }
    const bytes = new Uint8Array(length);
    const view = new DataView(bytes.buffer);
    bytes.set(magic);
    view.setUint16(4, files.length, true);
    let offset = 6;
    for (const file of files) {
        view.setUint16(offset, file.name.length, true);
        offset += 2;
        bytes.set(encodeText(file.name), offset);
        offset += file.name.length;
        view.setBigUint64(offset, BigInt(file.length), true);
        offset += 8;
        for (const id of file.chunks) {
            bytes.set(fromHexadecimal(id), offset);
            offset += candidateIdentifierBytes;
        }
    }
    return bytes;
};

export const decodeCandidateManifest = (
    bytes: Uint8Array,
): CandidateManifest => {
    if (
        bytes.length < 6 ||
        bytes.length > candidateManifestBytes ||
        magic.some((byte, index) => bytes[index] !== byte)
    )
        throw malformed();
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const count = view.getUint16(4, true);
    if (count === 0 || count > candidateMaximumFiles) throw malformed();
    const files: CandidateFile[] = [];
    let offset = 6;
    for (let index = 0; index < count; index++) {
        if (bytes.length - offset < 2) throw malformed();
        const nameLength = view.getUint16(offset, true);
        offset += 2;
        if (
            nameLength > candidateNameBytes ||
            bytes.length - offset < nameLength + 8
        )
            throw malformed();
        const name = String.fromCharCode(
            ...bytes.subarray(offset, offset + nameLength),
        );
        offset += nameLength;
        if (
            !isCandidateFileName(name) ||
            (index > 0 && files[index - 1].name >= name)
        )
            throw malformed();
        const encodedLength = view.getBigUint64(offset, true);
        offset += 8;
        if (encodedLength > BigInt(candidateMaximumFileBytes))
            throw malformed();
        const length = Number(encodedLength);
        const chunks = Math.ceil(length / candidateChunkBytes);
        if (
            chunks >
            Math.floor((bytes.length - offset) / candidateIdentifierBytes)
        )
            throw malformed();
        const identifiers = [];
        for (let chunk = 0; chunk < chunks; chunk++) {
            identifiers.push(
                hexadecimal(
                    bytes.subarray(offset, offset + candidateIdentifierBytes),
                ),
            );
            offset += candidateIdentifierBytes;
        }
        files.push(
            Object.freeze({ name, length, chunks: Object.freeze(identifiers) }),
        );
    }
    if (offset !== bytes.length) throw malformed();
    return Object.freeze({ files: Object.freeze(files) });
};

export const encodeCandidateReceipt = (receipt: CandidateReceipt) => {
    if (!isCandidateId(receipt.id) || !safeLength(receipt.index))
        throw malformed();
    const bytes = new Uint8Array(candidateIdentifierBytes + 8);
    bytes.set(fromHexadecimal(receipt.id));
    new DataView(bytes.buffer).setBigUint64(
        candidateIdentifierBytes,
        BigInt(receipt.index),
        true,
    );
    return bytes;
};

export const decodeCandidateReceipt = (bytes: Uint8Array): CandidateReceipt => {
    if (bytes.length !== candidateIdentifierBytes + 8) throw malformed();
    const index = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
    ).getBigUint64(candidateIdentifierBytes, true);
    if (index > BigInt(Number.MAX_SAFE_INTEGER)) throw malformed();
    return {
        id: hexadecimal(bytes.subarray(0, candidateIdentifierBytes)),
        index: Number(index),
    };
};

export const encodeCandidatePage = (page: CandidatePage) => {
    if (
        !safeLength(page.total) ||
        page.ids.length > candidatePageEntries ||
        page.ids.length > page.total ||
        page.ids.some((id) => !isCandidateId(id))
    )
        throw malformed();
    const header = new Uint8Array(12);
    const view = new DataView(header.buffer);
    view.setBigUint64(0, BigInt(page.total), true);
    view.setUint32(8, page.ids.length, true);
    return concatenate(header, ...page.ids.map(fromHexadecimal));
};

// A discovery page holds the list's total length and its count, then up to
// its entry limit of fixed-length entries from the requested offset.
export const decodeDiscoveryPage = (
    bytes: Uint8Array,
    entryBytes: number,
    entryLimit: number,
) => {
    if (bytes.length < 12 || bytes.length > 12 + entryLimit * entryBytes)
        throw malformed();
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const total = view.getBigUint64(0, true);
    const count = view.getUint32(8, true);
    if (
        total > BigInt(Number.MAX_SAFE_INTEGER) ||
        count > entryLimit ||
        BigInt(count) > total ||
        bytes.length !== 12 + count * entryBytes
    )
        throw malformed();
    return {
        total: Number(total),
        entries: Array.from({ length: count }, (_unused, index) =>
            bytes.subarray(
                12 + index * entryBytes,
                12 + (index + 1) * entryBytes,
            ),
        ),
    };
};

// Whether a page read from the offset holds every entry it can: its entry
// limit, or every entry that remains.
export const fillsDiscoveryPage = (
    count: number,
    total: number,
    offset: number,
    entryLimit: number,
) => count === Math.min(entryLimit, Math.max(0, total - offset));

export const decodeCandidatePage = (bytes: Uint8Array): CandidatePage => {
    const { total, entries } = decodeDiscoveryPage(
        bytes,
        candidateIdentifierBytes,
        candidatePageEntries,
    );
    return { total, ids: entries.map((entry) => hexadecimal(entry)) };
};
