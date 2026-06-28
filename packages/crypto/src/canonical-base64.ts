const base64Alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const base64EncodingChunkByteLength = 12_288;
const base64CodeByCharacterCode = (() => {
    const characterCodes = new Int16Array(128);
    characterCodes.fill(-1);
    for (
        let alphabetIndex = 0;
        alphabetIndex < base64Alphabet.length;
        alphabetIndex += 1
    ) {
        characterCodes[base64Alphabet.charCodeAt(alphabetIndex)] =
            alphabetIndex;
    }

    return characterCodes;
})();

const base64Character = (code: number): string => base64Alphabet.charAt(code);

export const bytesToBase64 = (bytes: Uint8Array): string => {
    const chunks: string[] = [];
    const completeGroupByteLength = bytes.byteLength - (bytes.byteLength % 3);
    for (
        let chunkStart = 0;
        chunkStart < completeGroupByteLength;
        chunkStart += base64EncodingChunkByteLength
    ) {
        const chunkEnd = Math.min(
            chunkStart + base64EncodingChunkByteLength,
            completeGroupByteLength,
        );
        let chunk = '';
        for (
            let byteOffset = chunkStart;
            byteOffset < chunkEnd;
            byteOffset += 3
        ) {
            const firstByte = bytes[byteOffset];
            const secondByte = bytes[byteOffset + 1];
            const thirdByte = bytes[byteOffset + 2];
            chunk +=
                base64Character(firstByte >> 2) +
                base64Character(((firstByte & 0x03) << 4) | (secondByte >> 4)) +
                base64Character(((secondByte & 0x0f) << 2) | (thirdByte >> 6)) +
                base64Character(thirdByte & 0x3f);
        }
        chunks.push(chunk);
    }

    const remainingByteLength = bytes.byteLength - completeGroupByteLength;
    if (remainingByteLength === 1) {
        const firstByte = bytes[completeGroupByteLength];
        chunks.push(
            `${base64Character(firstByte >> 2)}${base64Character(
                (firstByte & 0x03) << 4,
            )}==`,
        );
    } else if (remainingByteLength === 2) {
        const firstByte = bytes[completeGroupByteLength];
        const secondByte = bytes[completeGroupByteLength + 1];
        chunks.push(
            `${base64Character(firstByte >> 2)}${base64Character(
                ((firstByte & 0x03) << 4) | (secondByte >> 4),
            )}${base64Character((secondByte & 0x0f) << 2)}=`,
        );
    }

    return chunks.join('');
};

const base64Code = (characterCode: number, fieldName: string): number => {
    const code =
        characterCode >= 0 && characterCode < base64CodeByCharacterCode.length
            ? base64CodeByCharacterCode[characterCode]
            : -1;
    if (code < 0) {
        throw new TypeError(`${fieldName} must be canonical base64.`);
    }

    return code;
};

export const decodeCanonicalBase64 = (
    value: string,
    fieldName: string,
): Uint8Array => {
    if (value.length % 4 !== 0) {
        throw new TypeError(`${fieldName} must be canonical base64.`);
    }
    if (value.length === 0) {
        return new Uint8Array(0);
    }

    const paddingLength = value.endsWith('==')
        ? 2
        : value.endsWith('=')
          ? 1
          : 0;
    const unpaddedLength = value.length - paddingLength;
    const bytes = new Uint8Array((value.length / 4) * 3 - paddingLength);
    let outputOffset = 0;
    for (
        let characterOffset = 0;
        characterOffset < value.length;
        characterOffset += 4
    ) {
        const firstCode = base64Code(
            value.charCodeAt(characterOffset),
            fieldName,
        );
        const secondCode = base64Code(
            value.charCodeAt(characterOffset + 1),
            fieldName,
        );
        const thirdIsPadding = characterOffset + 2 >= unpaddedLength;
        const fourthIsPadding = characterOffset + 3 >= unpaddedLength;
        const thirdCode = thirdIsPadding
            ? 0
            : base64Code(value.charCodeAt(characterOffset + 2), fieldName);
        const fourthCode = fourthIsPadding
            ? 0
            : base64Code(value.charCodeAt(characterOffset + 3), fieldName);
        if (
            (thirdIsPadding && value.charCodeAt(characterOffset + 2) !== 61) ||
            (fourthIsPadding && value.charCodeAt(characterOffset + 3) !== 61)
        ) {
            throw new TypeError(`${fieldName} must be canonical base64.`);
        }
        if (
            (thirdIsPadding && !fourthIsPadding) ||
            (thirdIsPadding && (secondCode & 0x0f) !== 0) ||
            (fourthIsPadding && !thirdIsPadding && (thirdCode & 0x03) !== 0)
        ) {
            throw new TypeError(`${fieldName} must be canonical base64.`);
        }
        const triple =
            (firstCode << 18) |
            (secondCode << 12) |
            (thirdCode << 6) |
            fourthCode;
        bytes[outputOffset] = (triple >> 16) & 0xff;
        outputOffset += 1;
        if (!thirdIsPadding) {
            bytes[outputOffset] = (triple >> 8) & 0xff;
            outputOffset += 1;
        }
        if (!fourthIsPadding) {
            bytes[outputOffset] = triple & 0xff;
            outputOffset += 1;
        }
    }

    return bytes;
};
