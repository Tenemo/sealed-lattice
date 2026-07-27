import { describe, expect, it } from 'vitest';

import {
    CommonProofGenerationCursorManifestError,
    decodeCommonProofGenerationCursorManifest,
    maximumCommonProofGenerationCursorManifestByteLength,
    maximumRowCodeWhirTranscriptCheckpointCursorByteLength,
} from '#packages/wasm/src/common-proof-generation-cursor-manifest';

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
const generationCursorManifestPrefixByteLength = 88;

const privateCoinCursorManifest = (): Uint8Array<ArrayBuffer> => {
    const manifest = new Uint8Array(19);
    manifest.set(privateCoinCursorManifestMagic);
    new DataView(manifest.buffer).setUint16(8, 3, true);
    return manifest;
};

const generationCursorManifest = (
    transcriptCursorBytes: Uint8Array = new Uint8Array(),
): Uint8Array<ArrayBuffer> => {
    const privateManifest = privateCoinCursorManifest();
    const manifest = new Uint8Array(
        generationCursorManifestPrefixByteLength +
            privateManifest.byteLength +
            transcriptCursorBytes.byteLength,
    );
    manifest.set(generationCursorManifestMagic);
    const view = new DataView(manifest.buffer);
    view.setUint16(8, 1, true);
    view.setUint16(10, transcriptCursorBytes.byteLength === 0 ? 0 : 1, true);
    view.setUint32(12, manifest.byteLength, true);
    view.setUint32(16, privateManifest.byteLength, true);
    view.setUint32(20, transcriptCursorBytes.byteLength, true);
    if (transcriptCursorBytes.byteLength !== 0) {
        manifest.fill(0xa5, 24, 88);
    }
    manifest.set(privateManifest, generationCursorManifestPrefixByteLength);
    manifest.set(
        transcriptCursorBytes,
        generationCursorManifestPrefixByteLength + privateManifest.byteLength,
    );
    privateManifest.fill(0);
    return manifest;
};

describe('common-proof generation cursor manifest', () => {
    it('decodes the exact private-only and transcript-bearing layouts from bounded views', () => {
        const privateOnlyManifest = generationCursorManifest();
        const privateOnly =
            decodeCommonProofGenerationCursorManifest(privateOnlyManifest);
        expect(privateOnly.privateCoinCursorManifestBytes).toEqual(
            privateCoinCursorManifest(),
        );
        expect(privateOnly.transcriptCursorByteLength).toBe(0);
        expect(Object.isFrozen(privateOnly)).toBe(true);

        const transcriptCursorBytes = Uint8Array.from(
            { length: 37 },
            (_, index) => (index * 29) & 0xff,
        );
        const canonicalManifest = generationCursorManifest(
            transcriptCursorBytes,
        );
        const paddedManifest = new Uint8Array(canonicalManifest.byteLength + 9);
        paddedManifest.set(canonicalManifest, 4);
        const boundedView = paddedManifest.subarray(
            4,
            4 + canonicalManifest.byteLength,
        );
        const decoded = decodeCommonProofGenerationCursorManifest(boundedView);

        expect(decoded.privateCoinCursorManifestBytes).toEqual(
            privateCoinCursorManifest(),
        );
        expect(decoded.transcriptCursorByteLength).toBe(
            transcriptCursorBytes.byteLength,
        );
    });

    it('accepts the exact transcript cursor limit and rejects the next byte', () => {
        const maximumTranscriptCursor = new Uint8Array(
            maximumRowCodeWhirTranscriptCheckpointCursorByteLength,
        ).fill(0x39);
        expect(() =>
            decodeCommonProofGenerationCursorManifest(
                generationCursorManifest(maximumTranscriptCursor),
            ),
        ).not.toThrow();

        const overlongTranscriptCursor = new Uint8Array(
            maximumRowCodeWhirTranscriptCheckpointCursorByteLength + 1,
        ).fill(0x3a);
        expect(() =>
            decodeCommonProofGenerationCursorManifest(
                generationCursorManifest(overlongTranscriptCursor),
            ),
        ).toThrow(CommonProofGenerationCursorManifestError);
    });

    it('rejects malformed framing, counts, flags, inner framing, and surplus bytes', () => {
        const canonical = generationCursorManifest();
        const wrongMagic = canonical.slice();
        wrongMagic[0] ^= 0xff;
        const wrongVersion = canonical.slice();
        new DataView(wrongVersion.buffer).setUint16(8, 2, true);
        const reservedFlag = canonical.slice();
        new DataView(reservedFlag.buffer).setUint16(10, 2, true);
        const wrongTotal = canonical.slice();
        new DataView(wrongTotal.buffer).setUint32(
            12,
            wrongTotal.byteLength - 1,
            true,
        );
        const emptyPrivateManifest = canonical.slice();
        new DataView(emptyPrivateManifest.buffer).setUint32(16, 0, true);
        const wrongPrivateMagic = canonical.slice();
        wrongPrivateMagic[generationCursorManifestPrefixByteLength] ^= 0xff;
        const absentTranscriptWithDigest = canonical.slice();
        absentTranscriptWithDigest[24] = 1;
        const presentFlagWithoutTranscript = canonical.slice();
        new DataView(presentFlagWithoutTranscript.buffer).setUint16(
            10,
            1,
            true,
        );
        const transcriptWithoutPresentFlag = generationCursorManifest(
            Uint8Array.of(7),
        );
        new DataView(transcriptWithoutPresentFlag.buffer).setUint16(
            10,
            0,
            true,
        );
        const trailing = new Uint8Array(canonical.byteLength + 1);
        trailing.set(canonical);

        for (const malformedManifest of [
            new Uint8Array(),
            canonical.subarray(0, generationCursorManifestPrefixByteLength - 1),
            wrongMagic,
            wrongVersion,
            reservedFlag,
            wrongTotal,
            emptyPrivateManifest,
            wrongPrivateMagic,
            absentTranscriptWithDigest,
            presentFlagWithoutTranscript,
            transcriptWithoutPresentFlag,
            trailing,
            new Uint8Array(
                maximumCommonProofGenerationCursorManifestByteLength + 1,
            ),
        ]) {
            expect(() =>
                decodeCommonProofGenerationCursorManifest(malformedManifest),
            ).toThrow(CommonProofGenerationCursorManifestError);
        }
        expect(() =>
            decodeCommonProofGenerationCursorManifest(null as never),
        ).toThrow(CommonProofGenerationCursorManifestError);
    });
});
