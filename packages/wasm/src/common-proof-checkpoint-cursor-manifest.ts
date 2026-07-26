import {
    isAssignedRuntimeCheckpointRandomUse,
    isAssignedRuntimeCheckpointRandomUseFamily,
    isPublicOnlyCommonProofCheckpointFamily,
} from './runtime-build-canonical.js';

const checkpointCursorManifestMagic = Uint8Array.of(
    0x53,
    0x4c,
    0x43,
    0x50,
    0x43,
    0x4d,
    0x30,
    0x33,
);
const checkpointCursorManifestVersion = 3;
const checkpointCursorManifestPrefixByteLength = 19;
const checkpointCursorManifestIdentityByteLength = 98;
const checkpointCursorManifestRunByteLength = 24;
const checkpointCursorManifestOverrideByteLength = 14;
const checkpointCursorManifestFamilyOffset =
    checkpointCursorManifestPrefixByteLength;
const checkpointCursorManifestDerivationBindingHashOffset =
    checkpointCursorManifestFamilyOffset + 2;
const derivationBindingHashByteLength = 64;
const checkpointCursorManifestAttemptIdentifierOffset =
    checkpointCursorManifestDerivationBindingHashOffset +
    derivationBindingHashByteLength;
const checkpointCursorManifestRunsOffset =
    checkpointCursorManifestPrefixByteLength +
    checkpointCursorManifestIdentityByteLength;
const privateRandomnessStreamAttemptIdentifierByteLength = 32;
const maximumCheckpointCursorManifestByteLength = 1_048_576;
const maximumCheckpointCursorManifestRunCount = 4_096;
const maximumEncodedBufferedBlockBitOffset = 512;
const maximumUnsigned32 = 0xffff_ffff;

export class CommonProofCheckpointCursorManifestError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'CommonProofCheckpointCursorManifestError';
    }
}

export type DecodedCommonProofCheckpointCursorManifest =
    | Readonly<{
          hasPrivateRandomnessIdentity: false;
          orderedPurposeClasses: readonly number[];
      }>
    | Readonly<{
          derivationBindingHash: Uint8Array<ArrayBuffer>;
          familySchemaIdentifier: number;
          hasPrivateRandomnessIdentity: true;
          orderedPurposeClasses: readonly number[];
          privateRandomnessStreamAttemptIdentifier: Uint8Array<ArrayBuffer>;
      }>;

const fail = (message: string): never => {
    throw new CommonProofCheckpointCursorManifestError(message);
};

export const decodeCommonProofCheckpointCursorManifest = (
    manifestBytes: Uint8Array,
): DecodedCommonProofCheckpointCursorManifest => {
    if (!(manifestBytes instanceof Uint8Array)) {
        return fail(
            'A common-proof checkpoint cursor manifest is not a byte array.',
        );
    }
    if (
        manifestBytes.byteLength < checkpointCursorManifestPrefixByteLength ||
        manifestBytes.byteLength > maximumCheckpointCursorManifestByteLength ||
        checkpointCursorManifestMagic.some(
            (byte, byteIndex) => manifestBytes[byteIndex] !== byte,
        )
    ) {
        return fail(
            'A common-proof checkpoint cursor manifest has the wrong magic.',
        );
    }
    const view = new DataView(
        manifestBytes.buffer,
        manifestBytes.byteOffset,
        manifestBytes.byteLength,
    );
    const version = view.getUint16(8, true);
    const hasIdentity = manifestBytes[10];
    const runCount = view.getUint32(11, true);
    const logicalCursorCount = view.getUint32(15, true);
    if (version !== checkpointCursorManifestVersion) {
        return fail(
            'A common-proof checkpoint cursor manifest has the wrong version.',
        );
    }
    if (hasIdentity === 0) {
        if (
            runCount !== 0 ||
            logicalCursorCount !== 0 ||
            manifestBytes.byteLength !==
                checkpointCursorManifestPrefixByteLength
        ) {
            return fail(
                'An identity-free common-proof checkpoint cursor manifest is not canonical.',
            );
        }
        return Object.freeze({
            hasPrivateRandomnessIdentity: false,
            orderedPurposeClasses: Object.freeze([]),
        });
    }
    if (
        hasIdentity !== 1 ||
        runCount > maximumCheckpointCursorManifestRunCount ||
        (runCount === 0) !== (logicalCursorCount === 0) ||
        runCount > logicalCursorCount ||
        manifestBytes.byteLength < checkpointCursorManifestRunsOffset
    ) {
        return fail(
            'A common-proof checkpoint cursor manifest has an inconsistent identity.',
        );
    }
    const familySchemaIdentifier = view.getUint16(
        checkpointCursorManifestFamilyOffset,
        true,
    );
    const isPublicOnlyCommonProofFamily =
        isPublicOnlyCommonProofCheckpointFamily(familySchemaIdentifier);
    if (
        !isPublicOnlyCommonProofFamily &&
        !isAssignedRuntimeCheckpointRandomUseFamily(familySchemaIdentifier)
    ) {
        return fail(
            'A common-proof checkpoint cursor manifest has an unassigned family.',
        );
    }
    if (
        isPublicOnlyCommonProofFamily &&
        (runCount !== 0 || logicalCursorCount !== 0)
    ) {
        return fail(
            'A public-only common-proof checkpoint cursor manifest contains a private-randomness purpose.',
        );
    }
    const derivationBindingHash = manifestBytes.slice(
        checkpointCursorManifestDerivationBindingHashOffset,
        checkpointCursorManifestDerivationBindingHashOffset +
            derivationBindingHashByteLength,
    );
    const privateRandomnessStreamAttemptIdentifier = manifestBytes.slice(
        checkpointCursorManifestAttemptIdentifierOffset,
        checkpointCursorManifestAttemptIdentifierOffset +
            privateRandomnessStreamAttemptIdentifierByteLength,
    );
    const orderedPurposeClasses: number[] = [];
    let offset = checkpointCursorManifestRunsOffset;
    let parsedLogicalCursorCount = 0;
    for (let runIndex = 0; runIndex < runCount; runIndex += 1) {
        if (
            offset + checkpointCursorManifestRunByteLength >
            manifestBytes.byteLength
        ) {
            return fail(
                'A common-proof checkpoint cursor manifest has a truncated run.',
            );
        }
        const purposeClass = view.getUint16(offset, true);
        const firstCoordinateOrdinal = view.getUint32(offset + 2, true);
        const followingCoordinateCount = view.getUint32(offset + 6, true);
        const commonNextCounter = view.getBigUint64(offset + 10, true);
        const commonEncodedBufferedBlockBitOffset = view.getUint16(
            offset + 18,
            true,
        );
        const overrideCount = view.getUint32(offset + 20, true);
        const previousPurposeClass =
            orderedPurposeClasses[orderedPurposeClasses.length - 1];
        if (
            purposeClass === 0 ||
            !isAssignedRuntimeCheckpointRandomUse(
                familySchemaIdentifier,
                purposeClass,
            ) ||
            firstCoordinateOrdinal !== 0 ||
            followingCoordinateCount === maximumUnsigned32 ||
            commonEncodedBufferedBlockBitOffset >
                maximumEncodedBufferedBlockBitOffset ||
            (commonEncodedBufferedBlockBitOffset !== 0 &&
                commonNextCounter === 0n) ||
            overrideCount > followingCoordinateCount ||
            (previousPurposeClass !== undefined &&
                purposeClass <= previousPurposeClass)
        ) {
            return fail(
                'Common-proof checkpoint cursor runs are malformed, duplicated, or unsorted.',
            );
        }
        parsedLogicalCursorCount += followingCoordinateCount + 1;
        if (parsedLogicalCursorCount > maximumUnsigned32) {
            return fail(
                'A common-proof checkpoint cursor manifest count overflows.',
            );
        }
        offset += checkpointCursorManifestRunByteLength;
        let previousOverrideCoordinateOffset = 0;
        for (
            let overrideIndex = 0;
            overrideIndex < overrideCount;
            overrideIndex += 1
        ) {
            if (
                offset + checkpointCursorManifestOverrideByteLength >
                manifestBytes.byteLength
            ) {
                return fail(
                    'A common-proof checkpoint cursor manifest has a truncated override.',
                );
            }
            const overrideCoordinateOffset = view.getUint32(offset, true);
            const overrideNextCounter = view.getBigUint64(offset + 4, true);
            const overrideEncodedBufferedBlockBitOffset = view.getUint16(
                offset + 12,
                true,
            );
            if (
                overrideCoordinateOffset === 0 ||
                overrideCoordinateOffset > followingCoordinateCount ||
                overrideCoordinateOffset <= previousOverrideCoordinateOffset ||
                overrideEncodedBufferedBlockBitOffset >
                    maximumEncodedBufferedBlockBitOffset ||
                (overrideEncodedBufferedBlockBitOffset !== 0 &&
                    overrideNextCounter === 0n) ||
                (overrideNextCounter === commonNextCounter &&
                    overrideEncodedBufferedBlockBitOffset ===
                        commonEncodedBufferedBlockBitOffset)
            ) {
                return fail(
                    'Common-proof checkpoint cursor overrides are duplicated or unsorted.',
                );
            }
            previousOverrideCoordinateOffset = overrideCoordinateOffset;
            offset += checkpointCursorManifestOverrideByteLength;
        }
        orderedPurposeClasses.push(purposeClass);
    }
    if (
        offset !== manifestBytes.byteLength ||
        parsedLogicalCursorCount !== logicalCursorCount
    ) {
        return fail(
            'A common-proof checkpoint cursor manifest has trailing bytes or a wrong count.',
        );
    }
    return Object.freeze({
        derivationBindingHash,
        familySchemaIdentifier,
        hasPrivateRandomnessIdentity: true,
        orderedPurposeClasses: Object.freeze(orderedPurposeClasses),
        privateRandomnessStreamAttemptIdentifier,
    });
};
