import {
    createPrivateVssMailboxKeyPair,
    hash512Hex,
} from '#packages/crypto/src/index';
import { createMlDsaKeyPairFixture } from '#packages/crypto/tests/support/protocol-signature-fixtures';
import { publicKeyShareCoefficientVectorHashDomain } from '#packages/protocol/src/setup/public-key-share-records';
import { binaryVssCoefficientCommitmentMaterialByteLength } from '#packages/protocol/src/setup/vss-coefficient-commitments';
import { type VssOpeningRandomByteSource } from '#packages/protocol/src/setup/vss-coefficient-commitments';

export type JsonRecord = Record<string, unknown>;

export const jsonRecord = (value: unknown, label: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${label} must be a JSON object.`);
    }

    return value as JsonRecord;
};

export const cloneJsonRecord = (value: JsonRecord): JsonRecord =>
    JSON.parse(JSON.stringify(value)) as JsonRecord;

export const textEncoder = new TextEncoder();
// Reduced collective setup coverage still runs below the parameters ring, but it
// must use a ring degree accepted by the succinct proof relation.
export const minimumSuccinctProofFixtureRingDegree = 128;
export const firstRosterParticipantCount = 10;
export const firstRosterDecryptionThreshold = 4;
export const protocolHashPattern = /^[0-9a-f]{128}$/u;
export const setupTransportChunkSizeBytes = 1_048_576;
// The accepted transport certificate must bind the exact binary VSS coefficient
// commitment material byte length the kernel recomputes for the reduced-ring
// fixture material.
export const setupTransportTotalByteLength =
    binaryVssCoefficientCommitmentMaterialByteLength({
        participantCount: firstRosterParticipantCount,
        thresholdDegree: firstRosterDecryptionThreshold,
        rnsLimbCount: 17,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
    });
export const setupTransportChunkCount = Math.ceil(
    setupTransportTotalByteLength / setupTransportChunkSizeBytes,
);
export const setupTrusteeSignatureSeedLabel = (
    trusteeIdentity: string,
): string => `${trusteeIdentity}-setup-signing`;

type CanonicalObjectHashDeriver = (input: {
    readonly value: unknown;
}) => string;

export const collectiveSetupRosterHash = (
    deriveCanonicalObjectHashForValue: CanonicalObjectHashDeriver,
    participantCount = firstRosterParticipantCount,
): string =>
    deriveCanonicalObjectHashForValue({
        value: {
            objectType: 'CollectiveBgvSetupRoster',
            rosterEntries: Array.from(
                { length: participantCount },
                (_unusedSlot, rosterPosition) => {
                    const trusteeIdentity = `trustee-${String(rosterPosition)}`;
                    const signingPublicKeyHash = createMlDsaKeyPairFixture(
                        setupTrusteeSignatureSeedLabel(trusteeIdentity),
                    ).publicKeyHash;

                    return {
                        objectType: 'CollectiveBgvSetupRosterEntry',
                        objectVersion: 1,
                        rosterPosition,
                        trusteeIdentity,
                        signingPublicKeyHash,
                    };
                },
            ),
        },
    });

export const hexToBytes = (hexValue: string): Uint8Array =>
    Uint8Array.from(
        Array.from({ length: hexValue.length / 2 }, (_unused, byteIndex) =>
            Number.parseInt(
                hexValue.slice(byteIndex * 2, byteIndex * 2 + 2),
                16,
            ),
        ),
    );

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    const view = new DataView(bytes.buffer);
    coefficients.forEach((coefficient, coefficientIndex) => {
        view.setBigUint64(coefficientIndex * 8, BigInt(coefficient), true);
    });

    return bytes;
};

export const coefficientVectorLittleEndianHex = (
    coefficients: readonly number[],
): string => bytesToHex(coefficientVectorBytes(coefficients));

export const publicKeyShareCoefficientVectorHash = (
    coefficients: readonly number[],
): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

export const privateVssMailboxKeyPairForRosterPosition = (
    rosterPosition: number,
): ReturnType<typeof createPrivateVssMailboxKeyPair> =>
    createPrivateVssMailboxKeyPair(
        hash512Hex('sealed-lattice-test/private-vss-mailbox-key', [
            textEncoder.encode(String(rosterPosition)),
        ]),
    );

export const privateVssMailboxPublicKeyBytesHash = (
    publicKeyBytesHex: string,
): string =>
    hash512Hex('sealed-lattice-private-vss-mailbox/ml-kem-768-public-key-v1', [
        hexToBytes(publicKeyBytesHex),
    ]);

export const deterministicRandomBytes = (
    seedLabel: string,
): VssOpeningRandomByteSource => {
    let blockIndex = 0;
    let bufferedBytes = new Uint8Array(0);
    let bufferedOffset = 0;

    return (byteLength) => {
        const outputBytes = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < byteLength) {
            if (bufferedOffset >= bufferedBytes.byteLength) {
                const blockHex = hash512Hex(
                    'sealed-lattice-test/vss-opening-randomness',
                    [
                        textEncoder.encode(seedLabel),
                        textEncoder.encode(String(blockIndex)),
                    ],
                );
                bufferedBytes = Uint8Array.from(
                    blockHex
                        .match(/../gu)
                        ?.map((byteHex) => Number.parseInt(byteHex, 16)) ?? [],
                );
                bufferedOffset = 0;
                blockIndex += 1;
            }
            const copyLength = Math.min(
                byteLength - outputOffset,
                bufferedBytes.byteLength - bufferedOffset,
            );
            outputBytes.set(
                bufferedBytes.subarray(
                    bufferedOffset,
                    bufferedOffset + copyLength,
                ),
                outputOffset,
            );
            bufferedOffset += copyLength;
            outputOffset += copyLength;
        }

        return outputBytes;
    };
};
