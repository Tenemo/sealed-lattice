const generationCursorManifestMagic = Uint8Array.of(
    0x53,
    0x4c,
    0x43,
    0x47,
    0x43,
    0x4d,
    0x30,
    0x31,
);
const privateCoinCursorManifestMagic = Uint8Array.of(
    0x53,
    0x4c,
    0x43,
    0x50,
    0x43,
    0x4d,
    0x30,
    0x33,
);
const generationCursorManifestVersion = 1;
const transcriptCursorPresentFlag = 1;
const generationCursorManifestPrefixByteLength = 88;
const transcriptCursorDigestOffset = 24;
const transcriptCursorDigestByteLength = 64;
export const maximumCommonProofGenerationCursorManifestByteLength = 1_048_576;
export const maximumRowCodeWhirTranscriptCheckpointCursorByteLength =
    16 * 1_024;

export class CommonProofGenerationCursorManifestError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'CommonProofGenerationCursorManifestError';
    }
}

type DecodedCommonProofGenerationCursorManifest = Readonly<{
    privateCoinCursorManifestBytes: Uint8Array;
    transcriptCursorByteLength: number;
}>;

const fail = (message: string): never => {
    throw new CommonProofGenerationCursorManifestError(message);
};

export const decodeCommonProofGenerationCursorManifest = (
    manifestBytes: Uint8Array,
): DecodedCommonProofGenerationCursorManifest => {
    if (!(manifestBytes instanceof Uint8Array)) {
        return fail(
            'A common-proof generation cursor manifest is not a byte array.',
        );
    }
    if (
        manifestBytes.byteLength < generationCursorManifestPrefixByteLength ||
        manifestBytes.byteLength >
            maximumCommonProofGenerationCursorManifestByteLength ||
        generationCursorManifestMagic.some(
            (byte, byteIndex) => manifestBytes[byteIndex] !== byte,
        )
    ) {
        return fail(
            'A common-proof generation cursor manifest has the wrong framing.',
        );
    }
    const view = new DataView(
        manifestBytes.buffer,
        manifestBytes.byteOffset,
        manifestBytes.byteLength,
    );
    const version = view.getUint16(8, true);
    const flags = view.getUint16(10, true);
    const totalByteLength = view.getUint32(12, true);
    const privateCoinCursorManifestByteLength = view.getUint32(16, true);
    const transcriptCursorByteLength = view.getUint32(20, true);
    const privateCoinCursorManifestEnd =
        generationCursorManifestPrefixByteLength +
        privateCoinCursorManifestByteLength;
    const computedTotalByteLength =
        privateCoinCursorManifestEnd + transcriptCursorByteLength;
    const transcriptCursorIsPresent = flags === transcriptCursorPresentFlag;
    let transcriptCursorDigestIsZero = true;
    for (
        let byteIndex = transcriptCursorDigestOffset;
        byteIndex <
        transcriptCursorDigestOffset + transcriptCursorDigestByteLength;
        byteIndex += 1
    ) {
        transcriptCursorDigestIsZero =
            transcriptCursorDigestIsZero && manifestBytes[byteIndex] === 0;
    }
    if (
        version !== generationCursorManifestVersion ||
        (flags & ~transcriptCursorPresentFlag) !== 0 ||
        totalByteLength !== manifestBytes.byteLength ||
        computedTotalByteLength !== totalByteLength ||
        privateCoinCursorManifestByteLength === 0 ||
        transcriptCursorByteLength >
            maximumRowCodeWhirTranscriptCheckpointCursorByteLength ||
        transcriptCursorIsPresent !== (transcriptCursorByteLength !== 0) ||
        (!transcriptCursorIsPresent && !transcriptCursorDigestIsZero)
    ) {
        return fail(
            'A common-proof generation cursor manifest is not canonical.',
        );
    }
    if (
        privateCoinCursorManifestByteLength <
            privateCoinCursorManifestMagic.byteLength ||
        privateCoinCursorManifestMagic.some(
            (byte, byteIndex) =>
                manifestBytes[
                    generationCursorManifestPrefixByteLength + byteIndex
                ] !== byte,
        )
    ) {
        return fail(
            'A common-proof generation cursor manifest contains the wrong private-coin cursor framing.',
        );
    }
    return Object.freeze({
        privateCoinCursorManifestBytes: manifestBytes.subarray(
            generationCursorManifestPrefixByteLength,
            privateCoinCursorManifestEnd,
        ),
        transcriptCursorByteLength,
    });
};
