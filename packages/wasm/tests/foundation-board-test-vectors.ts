import { foundationProfile } from '@sealed-lattice/types';

import {
    createFoundationBoardSigningKeyPairFixtures,
    hashFoundationBoardFixtureFrame,
    signFoundationBoardFixtureMessage,
} from '#packages/crypto/tests/support/foundation-board-cryptographic-fixtures';

const mlDsa65VerificationKeyByteLength = 1_952;
const mlKem768EncapsulationKeyByteLength = 1_184;

export const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

export const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

export const unsigned64LittleEndian = (value: bigint): Uint8Array => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

export const concatenateBytes = (
    ...chunks: readonly Uint8Array[]
): Uint8Array => {
    const byteLength = chunks.reduce(
        (total, chunk) => total + chunk.byteLength,
        0,
    );
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return bytes;
};

export const canonicalItem = (
    itemType: number,
    canonicalBytes: Uint8Array,
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(itemType),
        unsigned32LittleEndian(canonicalBytes.byteLength),
        canonicalBytes,
    );

export const canonicalTuple = (
    schemaIdentifier: number,
    ...items: readonly Uint8Array[]
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(schemaIdentifier),
        unsigned16LittleEndian(1),
        unsigned32LittleEndian(items.length),
        ...items,
    );

export const unsigned16Item = (value: number): Uint8Array =>
    canonicalItem(0x03, unsigned16LittleEndian(value));

export const rawBytesItem = (bytes: Uint8Array): Uint8Array =>
    canonicalItem(0x01, bytes);

export const variableValue = (bytes: Uint8Array): Uint8Array =>
    concatenateBytes(unsigned32LittleEndian(bytes.byteLength), bytes);

export const variableBytesItem = (bytes: Uint8Array): Uint8Array =>
    rawBytesItem(variableValue(bytes));

export const asciiItem = (value: string): Uint8Array =>
    canonicalItem(0x02, variableValue(new TextEncoder().encode(value)));

export const unsigned64Item = (value: bigint): Uint8Array =>
    canonicalItem(0x05, unsigned64LittleEndian(value));

export const hashItem = (hash: Uint8Array): Uint8Array =>
    canonicalItem(0x06, hash);

export const emptyOptionalItem = (containedItemType: number): Uint8Array =>
    canonicalItem(
        0x0d,
        concatenateBytes(
            unsigned16LittleEndian(containedItemType),
            Uint8Array.of(0),
        ),
    );

export const presentOptionalItem = (
    containedItemType: number,
    canonicalValue: Uint8Array,
): Uint8Array =>
    canonicalItem(
        0x0d,
        concatenateBytes(
            unsigned16LittleEndian(containedItemType),
            Uint8Array.of(1),
            canonicalValue,
        ),
    );

export const emptyHomogeneousListItem = (elementItemType: number): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(elementItemType),
            unsigned32LittleEndian(0),
        ),
    );

export const foundationHash512 = (
    domain: string,
    ...items: readonly Uint8Array[]
): Uint8Array =>
    hashFoundationBoardFixtureFrame(
        canonicalTuple(0x0001, asciiItem(domain), ...items),
    );

const testMailboxEncapsulationKey = (rosterPosition: number): Uint8Array => {
    const bytes = new Uint8Array(mlKem768EncapsulationKeyByteLength);
    bytes[1_152] = rosterPosition + 1;
    return bytes;
};

const defaultSigningVerificationKey = (rosterPosition: number): Uint8Array => {
    const bytes = new Uint8Array(mlDsa65VerificationKeyByteLength);
    bytes.fill(rosterPosition + 1);
    return bytes;
};

export const createCanonicalTestRosterBytes = (
    signingVerificationKeys: readonly Uint8Array[] = Array.from(
        { length: foundationProfile.participantCount },
        (_, rosterPosition) => defaultSigningVerificationKey(rosterPosition),
    ),
): Uint8Array => {
    if (
        signingVerificationKeys.length !== foundationProfile.participantCount ||
        signingVerificationKeys.some(
            (key) => key.byteLength !== mlDsa65VerificationKeyByteLength,
        )
    ) {
        throw new Error('The test roster signing keys have the wrong shape.');
    }
    const entryTuples = signingVerificationKeys.map(
        (signingVerificationKey, rosterPosition) =>
            canonicalTuple(
                0x0114,
                unsigned16Item(rosterPosition),
                unsigned16Item(1),
                rawBytesItem(signingVerificationKey),
                rawBytesItem(testMailboxEncapsulationKey(rosterPosition)),
            ),
    );
    const nestedTupleList = concatenateBytes(
        unsigned16LittleEndian(0x09),
        unsigned32LittleEndian(entryTuples.length),
        ...entryTuples,
    );
    return canonicalTuple(
        0x0115,
        unsigned16Item(1),
        canonicalItem(0x0e, nestedTupleList),
    );
};

export type AuthenticatedComplaintTestVector = Readonly<{
    canonicalCarrierBytes: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    objectHash: Uint8Array;
}>;

let cachedAuthenticatedComplaintTestVector:
    | AuthenticatedComplaintTestVector
    | undefined;

const copyAuthenticatedComplaintTestVector = (
    vector: AuthenticatedComplaintTestVector,
): AuthenticatedComplaintTestVector => ({
    canonicalCarrierBytes: Uint8Array.from(vector.canonicalCarrierBytes),
    canonicalRosterBytes: Uint8Array.from(vector.canonicalRosterBytes),
    objectHash: Uint8Array.from(vector.objectHash),
});

export const createAuthenticatedComplaintTestVector =
    (): AuthenticatedComplaintTestVector => {
        if (cachedAuthenticatedComplaintTestVector !== undefined) {
            return copyAuthenticatedComplaintTestVector(
                cachedAuthenticatedComplaintTestVector,
            );
        }

        const signingKeyPairs = createFoundationBoardSigningKeyPairFixtures(
            foundationProfile.participantCount,
        );
        try {
            const canonicalRosterBytes = createCanonicalTestRosterBytes(
                signingKeyPairs.map(({ publicKey }) => publicKey),
            );
            const rosterHash = foundationHash512(
                'sealed-lattice/foundation/roster/v1',
                variableBytesItem(canonicalRosterBytes),
            );
            const producerIdentity = foundationHash512(
                'sealed-lattice/foundation/participant-id/v1',
                rawBytesItem(signingKeyPairs[0].publicKey),
            );
            const accusedParticipantIdentity = foundationHash512(
                'sealed-lattice/foundation/participant-id/v1',
                rawBytesItem(signingKeyPairs[1].publicKey),
            );
            const payloadBytes = canonicalTuple(
                0x1204,
                canonicalItem(0x07, accusedParticipantIdentity),
                hashItem(new Uint8Array(64).fill(0x44)),
                unsigned16Item(0x0007),
            );
            const canonicalEnvelopeBytes = canonicalTuple(
                0x0100,
                asciiItem('sealed-lattice'),
                unsigned16Item(1),
                hashItem(new Uint8Array(64).fill(0x11)),
                unsigned16Item(0x0012),
                hashItem(new Uint8Array(64).fill(0x22)),
                hashItem(new Uint8Array(64).fill(0x33)),
                unsigned64Item(0n),
                emptyOptionalItem(0x06),
                presentOptionalItem(0x07, producerIdentity),
                unsigned64Item(0n),
                emptyHomogeneousListItem(0x06),
                variableBytesItem(payloadBytes),
            );
            const objectHash = foundationHash512(
                'sealed-lattice/foundation/object/v1',
                variableBytesItem(canonicalEnvelopeBytes),
            );
            const signatureMessage = foundationHash512(
                'sealed-lattice/foundation/signature-message/v1',
                hashItem(objectHash),
                hashItem(rosterHash),
                asciiItem('setup-complaint'),
            );
            const signature = signFoundationBoardFixtureMessage(
                signatureMessage,
                signingKeyPairs[0].secretKey,
            );
            const canonicalCarrierBytes = canonicalTuple(
                0x0101,
                variableBytesItem(canonicalEnvelopeBytes),
                rawBytesItem(signature),
            );
            cachedAuthenticatedComplaintTestVector = {
                canonicalCarrierBytes,
                canonicalRosterBytes,
                objectHash,
            };
            return copyAuthenticatedComplaintTestVector(
                cachedAuthenticatedComplaintTestVector,
            );
        } finally {
            for (const { secretKey } of signingKeyPairs) {
                secretKey.fill(0);
            }
        }
    };
