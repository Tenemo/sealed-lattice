import { shake256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
    configurableParticipantCountRange,
    deriveFoundationRosterParameters,
    type ProtocolHash,
} from '@sealed-lattice/types';

const canonicalTupleVersion = 1;
const canonicalBytesItemType = 0x01;
const canonicalAsciiItemType = 0x02;
const canonicalUnsigned16ItemType = 0x03;
const canonicalNestedTupleItemType = 0x09;
const canonicalHomogeneousListItemType = 0x0e;
const canonicalHashFrameSchemaIdentifier = 0x0001;
const rosterEntrySchemaIdentifier = 0x0114;
const rosterSchemaIdentifier = 0x0115;
const canonicalTupleHeaderByteLength = 8;
const canonicalItemHeaderByteLength = 6;
const canonicalListHeaderByteLength = 6;
const mlDsa65VerificationKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlKem768EncapsulationKeyByteLength = ml_kem768.lengths.publicKey!;
const mlKem768EncapsulationCoinByteLength = ml_kem768.lengths.msg!;
const canonicalRosterEntryByteLength =
    canonicalTupleHeaderByteLength +
    canonicalItemHeaderByteLength +
    2 +
    canonicalItemHeaderByteLength +
    mlDsa65VerificationKeyByteLength +
    canonicalItemHeaderByteLength +
    mlKem768EncapsulationKeyByteLength;
const canonicalRosterFixedByteLength =
    canonicalTupleHeaderByteLength +
    canonicalItemHeaderByteLength +
    canonicalListHeaderByteLength;
const canonicalRosterByteLength = (participantCount: number): number =>
    canonicalRosterFixedByteLength +
    participantCount * canonicalRosterEntryByteLength;
const minimumCanonicalRosterByteLength = canonicalRosterByteLength(
    configurableParticipantCountRange.minimum,
);
const maximumCanonicalRosterByteLength = canonicalRosterByteLength(
    configurableParticipantCountRange.maximum,
);
const textEncoder = new TextEncoder();

declare const authenticatedMailboxFrozenRosterBrand: unique symbol;

/**
 * Opaque authority for selecting setup-mailbox source verification keys from
 * one canonical, validated foundation roster.
 */
export type AuthenticatedMailboxFrozenRoster = Readonly<{
    readonly [authenticatedMailboxFrozenRosterBrand]: true;
}>;

type FrozenRosterState = Readonly<{
    readonly orderedParticipantIdentities: readonly Uint8Array[];
    readonly rosterHash: ProtocolHash;
    readonly sourceVerificationKeys: ReadonlyMap<string, Uint8Array>;
}>;

type ParsedRosterEntry = Readonly<{
    readonly mailboxEncapsulationKey: Uint8Array;
    readonly signingVerificationKey: Uint8Array;
}>;

const frozenRosterStates = new WeakMap<
    AuthenticatedMailboxFrozenRoster,
    FrozenRosterState
>();

class CanonicalRosterReader {
    private byteOffset = 0;

    public constructor(private readonly bytes: Uint8Array) {}

    public readUnsigned16(fieldName: string): number {
        this.requireRemainingBytes(2, fieldName);
        const value = new DataView(
            this.bytes.buffer,
            this.bytes.byteOffset + this.byteOffset,
            2,
        ).getUint16(0, true);
        this.byteOffset += 2;
        return value;
    }

    public readUnsigned32(fieldName: string): number {
        this.requireRemainingBytes(4, fieldName);
        const value = new DataView(
            this.bytes.buffer,
            this.bytes.byteOffset + this.byteOffset,
            4,
        ).getUint32(0, true);
        this.byteOffset += 4;
        return value;
    }

    public readBytes(byteLength: number, fieldName: string): Uint8Array {
        this.requireRemainingBytes(byteLength, fieldName);
        const value = this.bytes.slice(
            this.byteOffset,
            this.byteOffset + byteLength,
        );
        this.byteOffset += byteLength;
        return value;
    }

    public requireEnd(fieldName: string): void {
        if (this.byteOffset !== this.bytes.byteLength) {
            throw new TypeError(`${fieldName} contains trailing bytes.`);
        }
    }

    private requireRemainingBytes(byteLength: number, fieldName: string): void {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            this.byteOffset + byteLength > this.bytes.byteLength
        ) {
            throw new TypeError(`${fieldName} is truncated.`);
        }
    }
}

const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const concatenateBytes = (...byteArrays: readonly Uint8Array[]): Uint8Array => {
    const byteLength = byteArrays.reduce(
        (totalByteLength, bytes) => totalByteLength + bytes.byteLength,
        0,
    );
    const result = new Uint8Array(byteLength);
    let byteOffset = 0;
    for (const bytes of byteArrays) {
        result.set(bytes, byteOffset);
        byteOffset += bytes.byteLength;
    }
    return result;
};

const canonicalItem = (
    itemType: number,
    canonicalValue: Uint8Array,
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(itemType),
        unsigned32LittleEndian(canonicalValue.byteLength),
        canonicalValue,
    );

const variableValue = (value: Uint8Array): Uint8Array =>
    concatenateBytes(unsigned32LittleEndian(value.byteLength), value);

const foundationHash512 = (domain: string, item: Uint8Array): Uint8Array => {
    const domainItem = canonicalItem(
        canonicalAsciiItemType,
        variableValue(textEncoder.encode(domain)),
    );
    const canonicalHashFrame = concatenateBytes(
        unsigned16LittleEndian(canonicalHashFrameSchemaIdentifier),
        unsigned16LittleEndian(canonicalTupleVersion),
        unsigned32LittleEndian(2),
        domainItem,
        item,
    );
    const hash = shake256.create({ dkLen: 64 });
    hash.update(canonicalHashFrame);
    const digest = hash.digest();
    domainItem.fill(0);
    canonicalHashFrame.fill(0);
    return digest;
};

const requireValue = (
    actualValue: number,
    expectedValue: number,
    fieldName: string,
): void => {
    if (actualValue !== expectedValue) {
        throw new TypeError(`${fieldName} is not canonical.`);
    }
};

const readCanonicalTupleHeader = (
    reader: CanonicalRosterReader,
    schemaIdentifier: number,
    itemCount: number,
    fieldName: string,
): void => {
    requireValue(
        reader.readUnsigned16(`${fieldName}.schemaIdentifier`),
        schemaIdentifier,
        `${fieldName}.schemaIdentifier`,
    );
    requireValue(
        reader.readUnsigned16(`${fieldName}.version`),
        canonicalTupleVersion,
        `${fieldName}.version`,
    );
    requireValue(
        reader.readUnsigned32(`${fieldName}.itemCount`),
        itemCount,
        `${fieldName}.itemCount`,
    );
};

const readFixedBytesItem = (
    reader: CanonicalRosterReader,
    byteLength: number,
    fieldName: string,
): Uint8Array => {
    requireValue(
        reader.readUnsigned16(`${fieldName}.itemType`),
        canonicalBytesItemType,
        `${fieldName}.itemType`,
    );
    requireValue(
        reader.readUnsigned32(`${fieldName}.byteLength`),
        byteLength,
        `${fieldName}.byteLength`,
    );
    return reader.readBytes(byteLength, fieldName);
};

const readUnsigned16Item = (
    reader: CanonicalRosterReader,
    fieldName: string,
): number => {
    requireValue(
        reader.readUnsigned16(`${fieldName}.itemType`),
        canonicalUnsigned16ItemType,
        `${fieldName}.itemType`,
    );
    requireValue(
        reader.readUnsigned32(`${fieldName}.byteLength`),
        2,
        `${fieldName}.byteLength`,
    );
    return reader.readUnsigned16(fieldName);
};

const parseCanonicalRoster = (
    canonicalRosterBytes: Uint8Array,
): readonly ParsedRosterEntry[] => {
    const rosterReader = new CanonicalRosterReader(canonicalRosterBytes);
    readCanonicalTupleHeader(
        rosterReader,
        rosterSchemaIdentifier,
        1,
        'canonicalRosterBytes',
    );
    requireValue(
        rosterReader.readUnsigned16('canonicalRosterBytes.entries.itemType'),
        canonicalHomogeneousListItemType,
        'canonicalRosterBytes.entries.itemType',
    );
    const listByteLength = rosterReader.readUnsigned32(
        'canonicalRosterBytes.entries.byteLength',
    );
    const listBytes = rosterReader.readBytes(
        listByteLength,
        'canonicalRosterBytes.entries',
    );
    rosterReader.requireEnd('canonicalRosterBytes');

    try {
        const listReader = new CanonicalRosterReader(listBytes);
        requireValue(
            listReader.readUnsigned16(
                'canonicalRosterBytes.entries.elementItemType',
            ),
            canonicalNestedTupleItemType,
            'canonicalRosterBytes.entries.elementItemType',
        );
        const participantCount = listReader.readUnsigned32(
            'canonicalRosterBytes.entries.count',
        );
        if (
            participantCount < configurableParticipantCountRange.minimum ||
            participantCount > configurableParticipantCountRange.maximum
        ) {
            throw new TypeError(
                'canonicalRosterBytes.entries.count is outside the configurable participant-count range.',
            );
        }
        deriveFoundationRosterParameters(participantCount);
        requireValue(
            canonicalRosterBytes.byteLength,
            canonicalRosterByteLength(participantCount),
            'canonicalRosterBytes.byteLength',
        );

        const entries: ParsedRosterEntry[] = [];
        for (
            let rosterPosition = 0;
            rosterPosition < participantCount;
            rosterPosition += 1
        ) {
            const entryName = `canonicalRosterBytes.entries[${rosterPosition}]`;
            readCanonicalTupleHeader(
                listReader,
                rosterEntrySchemaIdentifier,
                3,
                entryName,
            );
            requireValue(
                readUnsigned16Item(listReader, `${entryName}.rosterPosition`),
                rosterPosition,
                `${entryName}.rosterPosition`,
            );
            entries.push({
                signingVerificationKey: readFixedBytesItem(
                    listReader,
                    mlDsa65VerificationKeyByteLength,
                    `${entryName}.signingVerificationKey`,
                ),
                mailboxEncapsulationKey: readFixedBytesItem(
                    listReader,
                    mlKem768EncapsulationKeyByteLength,
                    `${entryName}.mailboxEncapsulationKey`,
                ),
            });
        }
        listReader.requireEnd('canonicalRosterBytes.entries');
        return entries;
    } finally {
        listBytes.fill(0);
    }
};

const deriveParticipantIdentity = (
    signingVerificationKey: Uint8Array,
): string => {
    const fixedSigningKeyItem = canonicalItem(
        canonicalBytesItemType,
        signingVerificationKey,
    );
    try {
        const identity = foundationHash512(
            'sealed-lattice/foundation/participant-id/v1',
            fixedSigningKeyItem,
        );
        try {
            return bytesToHex(identity);
        } finally {
            identity.fill(0);
        }
    } finally {
        fixedSigningKeyItem.fill(0);
    }
};

const deriveRosterHash = (canonicalRosterBytes: Uint8Array): ProtocolHash => {
    const variableRosterItem = canonicalItem(
        canonicalBytesItemType,
        variableValue(canonicalRosterBytes),
    );
    try {
        const rosterHash = foundationHash512(
            'sealed-lattice/foundation/roster/v1',
            variableRosterItem,
        );
        try {
            return bytesToHex(rosterHash);
        } finally {
            rosterHash.fill(0);
        }
    } finally {
        variableRosterItem.fill(0);
    }
};

const validateMailboxEncapsulationKey = (
    mailboxEncapsulationKey: Uint8Array,
): void => {
    const encapsulationCoins = new Uint8Array(
        mlKem768EncapsulationCoinByteLength,
    );
    let encapsulation: ReturnType<typeof ml_kem768.encapsulate> | undefined;
    try {
        try {
            encapsulation = ml_kem768.encapsulate(
                mailboxEncapsulationKey,
                encapsulationCoins,
            );
        } catch {
            throw new TypeError(
                'canonicalRosterBytes contains a noncanonical ML-KEM-768 encapsulation key.',
            );
        }
    } finally {
        encapsulationCoins.fill(0);
        encapsulation?.cipherText.fill(0);
        encapsulation?.sharedSecret.fill(0);
    }
};

/**
 * Validates and freezes the exact canonical roster used to authenticate
 * setup-mailbox sources. Raw source keys cannot be supplied after this point.
 */
export const openAuthenticatedMailboxFrozenRoster = (
    canonicalRosterBytes: Uint8Array,
): AuthenticatedMailboxFrozenRoster => {
    if (
        !(canonicalRosterBytes instanceof Uint8Array) ||
        canonicalRosterBytes.byteLength < minimumCanonicalRosterByteLength ||
        canonicalRosterBytes.byteLength > maximumCanonicalRosterByteLength
    ) {
        throw new TypeError(
            `canonicalRosterBytes must encode between ${String(configurableParticipantCountRange.minimum)} and ${String(configurableParticipantCountRange.maximum)} participants.`,
        );
    }

    const ownedRosterBytes = canonicalRosterBytes.slice();
    let parsedEntries: readonly ParsedRosterEntry[] = [];
    try {
        parsedEntries = parseCanonicalRoster(ownedRosterBytes);
        const signingVerificationKeys = new Set<string>();
        const mailboxEncapsulationKeys = new Set<string>();
        const sourceVerificationKeys = new Map<string, Uint8Array>();
        const orderedParticipantIdentities: Uint8Array[] = [];
        for (const entry of parsedEntries) {
            validateMailboxEncapsulationKey(entry.mailboxEncapsulationKey);
            const participantIdentity = deriveParticipantIdentity(
                entry.signingVerificationKey,
            );
            if (
                signingVerificationKeys.has(
                    bytesToHex(entry.signingVerificationKey),
                ) ||
                mailboxEncapsulationKeys.has(
                    bytesToHex(entry.mailboxEncapsulationKey),
                ) ||
                sourceVerificationKeys.has(participantIdentity)
            ) {
                throw new TypeError(
                    'canonicalRosterBytes contains a duplicate identity, signing key, or mailbox key.',
                );
            }
            signingVerificationKeys.add(
                bytesToHex(entry.signingVerificationKey),
            );
            mailboxEncapsulationKeys.add(
                bytesToHex(entry.mailboxEncapsulationKey),
            );
            sourceVerificationKeys.set(
                participantIdentity,
                entry.signingVerificationKey.slice(),
            );
            orderedParticipantIdentities.push(hexToBytes(participantIdentity));
        }

        const frozenRoster = Object.freeze(
            {},
        ) as AuthenticatedMailboxFrozenRoster;
        frozenRosterStates.set(frozenRoster, {
            orderedParticipantIdentities: Object.freeze(
                orderedParticipantIdentities,
            ),
            rosterHash: deriveRosterHash(ownedRosterBytes),
            sourceVerificationKeys,
        });
        return frozenRoster;
    } finally {
        ownedRosterBytes.fill(0);
        for (const entry of parsedEntries) {
            entry.signingVerificationKey.fill(0);
            entry.mailboxEncapsulationKey.fill(0);
        }
    }
};

/**
 * Copies the canonical roster's participant identities in roster order. Only
 * an opaque roster returned by `openAuthenticatedMailboxFrozenRoster` can be
 * inspected through this function.
 */
export const copyAuthenticatedMailboxFrozenRosterParticipantIdentities = (
    frozenRoster: AuthenticatedMailboxFrozenRoster,
): readonly Uint8Array[] => {
    const state = frozenRosterStates.get(frozenRoster);
    if (state === undefined) {
        throw new TypeError(
            'The authenticated mailbox frozen roster capability is forged or owned by another runtime.',
        );
    }
    return Object.freeze(
        state.orderedParticipantIdentities.map((identity) => identity.slice()),
    );
};

export const resolveAuthenticatedMailboxFrozenRosterSourceVerificationKey = (
    frozenRoster: AuthenticatedMailboxFrozenRoster,
    rosterHash: ProtocolHash,
    sourceParticipantId: string,
): Uint8Array | undefined => {
    const state = frozenRosterStates.get(frozenRoster);
    if (state?.rosterHash !== rosterHash) {
        return undefined;
    }
    return state.sourceVerificationKeys.get(sourceParticipantId)?.slice();
};
