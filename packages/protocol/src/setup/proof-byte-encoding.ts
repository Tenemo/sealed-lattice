const standardBase64Alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const standardBase64Values = new Map<string, number>(
    Array.from(standardBase64Alphabet, (character, index) => [
        character,
        index,
    ]),
);

const standardBase64Value = (character: string, fieldName: string): number => {
    const value = standardBase64Values.get(character);
    if (value === undefined) {
        throw new TypeError(`${fieldName} must use standard base64.`);
    }

    return value;
};

// Standard RFC 4648 base64 with padding, byte-for-byte the kernel's
// encode_standard_base64 so the canonical decoder the verifier runs accepts it
// and the proof bytes stay canonically bound.
//
// The base64 for one multi-megabyte proof is assembled into fixed-size flat
// segments and joined once, rather than appended to a single accumulator. A
// running `accumulator += character` over the millions of chunks in a large
// proof leaves V8 holding a deep, unflattened concatenated string (rope) whose
// node overhead dwarfs the ~5.7 MB result (measured ~173 MB retained per proof);
// flushing flat segments and joining keeps only the flat result live and lets
// the intermediate segments be reclaimed. The emitted string is byte-identical.
const BASE64_SEGMENT_FLUSH_LENGTH = 8192;

export const encodeStandardBase64 = (bytes: Uint8Array): string => {
    const segments: string[] = [];
    let segment = '';
    for (let chunkStart = 0; chunkStart < bytes.length; chunkStart += 3) {
        const remaining = bytes.length - chunkStart;
        const first = bytes[chunkStart] ?? 0;
        const second = remaining >= 2 ? (bytes[chunkStart + 1] ?? 0) : 0;
        const third = remaining >= 3 ? (bytes[chunkStart + 2] ?? 0) : 0;
        segment +=
            standardBase64Alphabet[first >> 2] +
            standardBase64Alphabet[((first & 0x03) << 4) | (second >> 4)] +
            (remaining >= 2
                ? standardBase64Alphabet[((second & 0x0f) << 2) | (third >> 6)]
                : '=') +
            (remaining >= 3 ? standardBase64Alphabet[third & 0x3f] : '=');
        if (segment.length >= BASE64_SEGMENT_FLUSH_LENGTH) {
            segments.push(segment);
            segment = '';
        }
    }
    if (segment.length > 0) {
        segments.push(segment);
    }

    return segments.join('');
};

export const bytesFromStandardBase64 = (
    base64Value: string,
    fieldName: string,
): Uint8Array => {
    if (base64Value.length % 4 !== 0) {
        throw new TypeError(`${fieldName} length must be a multiple of four.`);
    }

    const decoded: number[] = [];
    for (
        let characterIndex = 0;
        characterIndex < base64Value.length;
        characterIndex += 4
    ) {
        const isFinalChunk = characterIndex + 4 === base64Value.length;
        const first = standardBase64Value(
            base64Value[characterIndex] ?? '',
            fieldName,
        );
        const second = standardBase64Value(
            base64Value[characterIndex + 1] ?? '',
            fieldName,
        );
        const thirdCharacter = base64Value[characterIndex + 2] ?? '';
        const fourthCharacter = base64Value[characterIndex + 3] ?? '';

        if (thirdCharacter === '=' && fourthCharacter === '=') {
            if (!isFinalChunk) {
                throw new TypeError(
                    `${fieldName} padding must appear only in the final chunk.`,
                );
            }
            if ((second & 0x0f) !== 0) {
                throw new TypeError(
                    `${fieldName} must use canonical padding bits.`,
                );
            }
            decoded.push((first << 2) | (second >> 4));
            continue;
        }

        if (fourthCharacter === '=') {
            if (!isFinalChunk) {
                throw new TypeError(
                    `${fieldName} padding must appear only in the final chunk.`,
                );
            }
            const third = standardBase64Value(thirdCharacter, fieldName);
            if ((third & 0x03) !== 0) {
                throw new TypeError(
                    `${fieldName} must use canonical padding bits.`,
                );
            }
            decoded.push((first << 2) | (second >> 4));
            decoded.push(((second & 0x0f) << 4) | (third >> 2));
            continue;
        }

        if (thirdCharacter === '=') {
            throw new TypeError(`${fieldName} padding is malformed.`);
        }

        const third = standardBase64Value(thirdCharacter, fieldName);
        const fourth = standardBase64Value(fourthCharacter, fieldName);
        decoded.push((first << 2) | (second >> 4));
        decoded.push(((second & 0x0f) << 4) | (third >> 2));
        decoded.push(((third & 0x03) << 6) | fourth);
    }

    return new Uint8Array(decoded);
};
