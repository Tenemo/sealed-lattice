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

const unsigned64LittleEndian = (value: bigint): Uint8Array => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const concatenateBytes = (...chunks: readonly Uint8Array[]): Uint8Array => {
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

const canonicalItem = (
    itemType: number,
    canonicalBytes: Uint8Array,
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(itemType),
        unsigned32LittleEndian(canonicalBytes.byteLength),
        canonicalBytes,
    );

const canonicalTupleWithVersion = (
    schemaIdentifier: number,
    schemaVersion: number,
    ...items: readonly Uint8Array[]
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(schemaIdentifier),
        unsigned16LittleEndian(schemaVersion),
        unsigned32LittleEndian(items.length),
        ...items,
    );

const canonicalTuple = (
    schemaIdentifier: number,
    ...items: readonly Uint8Array[]
): Uint8Array => canonicalTupleWithVersion(schemaIdentifier, 1, ...items);

const variableBytes = (bytes: Uint8Array): Uint8Array =>
    concatenateBytes(unsigned32LittleEndian(bytes.byteLength), bytes);

const textEncoder = new TextEncoder();

const rawBytes = (bytes: Uint8Array): Uint8Array => canonicalItem(0x01, bytes);
const variableRawBytes = (bytes: Uint8Array): Uint8Array =>
    rawBytes(variableBytes(bytes));
const ascii = (value: string): Uint8Array =>
    canonicalItem(0x02, variableBytes(textEncoder.encode(value)));
const unsigned16 = (value: number): Uint8Array =>
    canonicalItem(0x03, unsigned16LittleEndian(value));
const unsigned32 = (value: number): Uint8Array =>
    canonicalItem(0x04, unsigned32LittleEndian(value));
const unsigned64 = (value: bigint): Uint8Array =>
    canonicalItem(0x05, unsigned64LittleEndian(value));
const hash = (byte: number): Uint8Array =>
    canonicalItem(0x06, new Uint8Array(64).fill(byte));
const hashBytes = (bytes: Uint8Array): Uint8Array => canonicalItem(0x06, bytes);
const participantIdentity = (byte: number): Uint8Array =>
    canonicalItem(0x07, new Uint8Array(64).fill(byte));
const displayText = (value: string): Uint8Array =>
    canonicalItem(0x0c, variableBytes(textEncoder.encode(value)));
const nestedTuple = (tuple: Uint8Array): Uint8Array =>
    canonicalItem(0x09, tuple);
const optional = (
    containedItemType: number,
    canonicalValue?: Uint8Array,
): Uint8Array =>
    canonicalItem(
        0x0d,
        concatenateBytes(
            unsigned16LittleEndian(containedItemType),
            Uint8Array.of(canonicalValue === undefined ? 0 : 1),
            canonicalValue ?? new Uint8Array(),
        ),
    );
const homogeneousList = (
    elementItemType: number,
    canonicalValues: readonly Uint8Array[],
): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(elementItemType),
            unsigned32LittleEndian(canonicalValues.length),
            ...canonicalValues,
        ),
    );
const hashList = (bytes: readonly number[]): Uint8Array =>
    homogeneousList(
        0x06,
        bytes.map((byte) => new Uint8Array(64).fill(byte)),
    );
const nestedTupleList = (tuples: readonly Uint8Array[]): Uint8Array =>
    homogeneousList(0x09, tuples);
const variableRawBytesList = (values: readonly Uint8Array[]): Uint8Array =>
    homogeneousList(0x01, values.map(variableBytes));
const asciiList = (values: readonly string[]): Uint8Array =>
    homogeneousList(
        0x02,
        values.map((value) => variableBytes(textEncoder.encode(value))),
    );

const hexadecimalBytes = (hexadecimal: string): Uint8Array => {
    const matches = hexadecimal.match(/../gu);
    if (matches === null || matches.length * 2 !== hexadecimal.length) {
        throw new Error('The hexadecimal test vector is malformed.');
    }
    return Uint8Array.from(matches, (pair) => Number.parseInt(pair, 16));
};

const repeatedBytes = (byteLength: number, byte: number): Uint8Array =>
    new Uint8Array(byteLength).fill(byte);

const ballotOptionDefinition = (
    optionIndex: number,
    optionIdentifier: string,
    displayTextBytes: Uint8Array,
): Uint8Array =>
    canonicalTuple(
        0x0111,
        unsigned16(optionIndex),
        ascii(optionIdentifier),
        canonicalItem(0x0c, variableBytes(displayTextBytes)),
    );

const manifestOptions = Array.from({ length: 20 }, (_, optionIndex) =>
    ballotOptionDefinition(
        optionIndex,
        `option-${String(optionIndex + 1)}`,
        textEncoder.encode(`Option ${String(optionIndex + 1)}`),
    ),
);
const manifest = canonicalTuple(
    0x0110,
    unsigned16(1),
    displayText('Canonical poll'),
    nestedTupleList(manifestOptions),
);

const mailboxEncapsulationKey = (rosterPosition: number): Uint8Array => {
    const bytes = new Uint8Array(1_184);
    bytes[1_152] = rosterPosition + 1;
    return bytes;
};
const rosterEntry = (rosterPosition: number): Uint8Array =>
    canonicalTuple(
        0x0114,
        unsigned16(rosterPosition),
        unsigned16(1),
        rawBytes(repeatedBytes(1_952, rosterPosition + 1)),
        rawBytes(mailboxEncapsulationKey(rosterPosition)),
    );
const rosterEntries = Array.from({ length: 10 }, (_, rosterPosition) =>
    rosterEntry(rosterPosition),
);
const roster = canonicalTuple(
    0x0115,
    unsigned16(1),
    nestedTupleList(rosterEntries),
);

const distributionRecord = (purpose: number): Uint8Array => {
    const isTernary = [1, 3, 8, 11].includes(purpose);
    return canonicalTuple(
        0x0116,
        unsigned16(purpose),
        unsigned16(isTernary ? 1 : 2),
        unsigned64(BigInt(isTernary ? 0 : 2)),
    );
};
const artifactReference = (artifactKind: number): Uint8Array =>
    canonicalTuple(
        0x0117,
        unsigned16(artifactKind),
        unsigned64(BigInt(100 + artifactKind)),
        hash(artifactKind),
    );
const suiteRecord = canonicalTuple(
    0x0118,
    unsigned16(1),
    unsigned16(10),
    unsigned16(3),
    unsigned16(4),
    unsigned16(7),
    unsigned32(2),
    unsigned64(5n),
    homogeneousList(0x05, [41n, 61n, 13n].map(unsigned64LittleEndian)),
    homogeneousList(0x05, [17n, 29n].map(unsigned64LittleEndian)),
    homogeneousList(0x03, [0, 1].map(unsigned16LittleEndian)),
    homogeneousList(0x03, [0, 1, 2].map(unsigned16LittleEndian)),
    unsigned16(1),
    unsigned16(2),
    unsigned16(1),
    unsigned16(3),
    unsigned16(4),
    unsigned16(10),
    unsigned32(20),
    unsigned32(100),
    unsigned64(3_000n),
    unsigned64(20_000n),
    unsigned64(4_000n),
    unsigned64(25_000n),
    unsigned64(50_000n),
    unsigned64(5_000n),
    unsigned64(100_000n),
    nestedTupleList(
        Array.from({ length: 12 }, (_, index) => distributionRecord(index + 1)),
    ),
    nestedTupleList(
        Array.from({ length: 6 }, (_, index) => artifactReference(index + 1)),
    ),
);

const streamDescriptor = canonicalTuple(
    0x1800,
    unsigned64(1n),
    hashList([0x41]),
    hash(0x42),
);
const objectEnvelope = canonicalTuple(
    0x0100,
    ascii('sealed-lattice'),
    unsigned16(1),
    hash(0x11),
    unsigned16(0x0010),
    unsigned16(1),
    hash(0x12),
    hash(0x13),
    unsigned64(0n),
    optional(0x06),
    optional(0x07),
    unsigned64(0n),
    hashList([]),
    variableRawBytes(new Uint8Array()),
);

const proofAuthenticationNode = canonicalTuple(
    0x0106,
    unsigned32(1),
    unsigned64(0n),
    hash(0x27),
);
const proofFieldSchedule = canonicalTuple(
    0x2203,
    unsigned16(0),
    unsigned32(4),
    unsigned64(3n),
    unsigned16(2),
    unsigned32(8),
    unsigned32(4),
    unsigned16(2),
);
const proofFamilyStatementIdentifiers = [
    0x1211, 0x1212, 0x1213, 0x1214, 0x1215, 0x1216, 0x1217, 0x1218, 0x1302,
    0x1621, 0x2110, 0x2111,
] as const;
const proofFamilyProfile = (statementSchemaIdentifier: number): Uint8Array =>
    canonicalTuple(
        0x2202,
        unsigned16(statementSchemaIdentifier),
        nestedTuple(proofFieldSchedule),
    );
const proofFieldProfile = canonicalTuple(
    0x2201,
    unsigned64(97n),
    unsigned64(28n),
    homogeneousList(0x05, [5n, 0n].map(unsigned64LittleEndian)),
);
const proofProfileSet = canonicalTuple(
    0x2200,
    nestedTupleList([proofFieldProfile]),
    nestedTupleList(proofFamilyStatementIdentifiers.map(proofFamilyProfile)),
);

const mailboxKemCiphertext = new Uint8Array(1_088);
const mailboxKemCiphertextHash = hexadecimalBytes(
    'a480de7138c4d29863af677e1a60df8799b951779440d4cdd05f8d95ba6e2aef' +
        '38dc2f316f702eaac80eda7f3f19d5c50defa17bb5fee40e00210c65d7424a24',
);
const mailboxKeyScheduleItems = [
    ascii('sealed-lattice/mailbox/key-schedule/v1'),
    unsigned16(1),
    hash(1),
    hash(2),
    hash(3),
    hash(4),
    participantIdentity(5),
    participantIdentity(6),
    unsigned64(7n),
    rawBytes(repeatedBytes(32, 8)),
    ascii('source-to-recipient'),
    unsigned16(1),
    unsigned16(1),
    hash(9),
    hashList([]),
    hashBytes(mailboxKemCiphertextHash),
] as const;
const mailboxKeyScheduleInput = canonicalTuple(
    0x0200,
    ...mailboxKeyScheduleItems,
);
const mailboxAssociatedData = canonicalTuple(
    0x0201,
    ...mailboxKeyScheduleItems,
    unsigned64(1n),
    unsigned16(1),
);
const signedMailboxEnvelope = canonicalTuple(
    0x0202,
    variableRawBytes(mailboxAssociatedData),
    rawBytes(mailboxKemCiphertext),
    nestedTuple(streamDescriptor),
    rawBytes(repeatedBytes(16, 0x52)),
    rawBytes(repeatedBytes(3_309, 0x53)),
);

const deviceWrappingAssociatedData = canonicalTuple(
    0x0300,
    unsigned16(1),
    hash(0x31),
    hash(0x32),
    hash(0x33),
    participantIdentity(0x34),
    hash(0x35),
    unsigned64(48n),
);
const localRecordAssociatedData = canonicalTuple(
    0x0301,
    unsigned16(1),
    hash(0x31),
    hash(0x32),
    hash(0x33),
    participantIdentity(0x34),
    unsigned16(1),
    hash(0x36),
    unsigned64(0n),
    unsigned64(0n),
    optional(0x06),
    unsigned64(3n),
);

const checkpointRandomUseProfile = canonicalTuple(
    0x1806,
    unsigned16(0x0116),
    unsigned16(1),
);
const checkpointBoundaryProfile = canonicalTuple(
    0x1807,
    unsigned32(0),
    unsigned16(0x1901),
    nestedTupleList([checkpointRandomUseProfile]),
);
const runtimeOperationProfile = canonicalTuple(
    0x1808,
    unsigned16(0x1205),
    nestedTupleList([checkpointBoundaryProfile]),
);
const runtimeAssetReference = (
    role: number,
    path: string,
    hashByte: number,
): Uint8Array =>
    canonicalTuple(
        0x1801,
        unsigned16(role),
        ascii(path),
        unsigned64(1_024n),
        hash(hashByte),
    );
const runtimeAssets = [
    runtimeAssetReference(1, '/application.js', 0x61),
    runtimeAssetReference(2, '/worker.js', 0x62),
    runtimeAssetReference(3, '/kernel.wasm', 0x63),
] as const;
const runtimeBuildManifest = canonicalTuple(
    0x1802,
    unsigned16(1),
    ascii('release-1'),
    hash(0x60),
    ascii('/suite.bin'),
    asciiList(
        Array.from(
            { length: 6 },
            (_, index) => `/artifact-${String(index + 1)}.bin`,
        ),
    ),
    nestedTupleList(runtimeAssets),
    nestedTupleList([]),
);
const randomCursor = canonicalTuple(
    0x1804,
    unsigned16(0x0116),
    unsigned16(1),
    hash(0x71),
    unsigned64(2n),
);

export type FoundationSchemaObjectVector = Readonly<{
    name: string;
    schemaIdentifier: number;
    canonicalBytes: Uint8Array;
}>;

const schemaObject = (
    name: string,
    schemaIdentifier: number,
    canonicalBytes: Uint8Array,
): FoundationSchemaObjectVector => ({
    name,
    schemaIdentifier,
    canonicalBytes,
});

/**
 * Independently encoded canonical bytes for every schema accepted by the
 * public foundation schema-object validator. These values deliberately do not
 * call production encoders.
 */
export const validFoundationSchemaObjectVectors = [
    schemaObject('object envelope', 0x0100, objectEnvelope),
    schemaObject(
        'signed carrier',
        0x0101,
        canonicalTuple(
            0x0101,
            variableRawBytes(objectEnvelope),
            rawBytes(repeatedBytes(3_309, 0x21)),
        ),
    ),
    schemaObject(
        'proof object header',
        0x0102,
        canonicalTuple(0x0102, variableRawBytes(canonicalTuple(0x1211))),
    ),
    schemaObject(
        'proof Merkle tree context',
        0x0103,
        canonicalTuple(
            0x0103,
            hash(0x22),
            hash(0x23),
            unsigned16(0x1211),
            unsigned16(0),
            unsigned16(1),
            unsigned16(0),
            unsigned64(2n),
            unsigned32(1),
            unsigned16(1),
        ),
    ),
    schemaObject(
        'proof oracle phase-pair leaf',
        0x0104,
        canonicalTuple(
            0x0104,
            hash(0x24),
            unsigned64(0n),
            unsigned16(1),
            homogeneousList(0x08, [Uint8Array.of(7)]),
            homogeneousList(0x08, [Uint8Array.of(8)]),
        ),
    ),
    schemaObject(
        'proof Merkle node',
        0x0105,
        canonicalTuple(
            0x0105,
            hash(0x24),
            unsigned32(1),
            unsigned64(0n),
            hash(0x25),
            hash(0x26),
        ),
    ),
    schemaObject('proof authentication node', 0x0106, proofAuthenticationNode),
    schemaObject(
        'proof query opening record',
        0x0107,
        canonicalTuple(
            0x0107,
            unsigned16(0),
            variableRawBytesList([Uint8Array.of(1, 2)]),
        ),
    ),
    schemaObject(
        'proof authentication frontier',
        0x0108,
        canonicalTuple(
            0x0108,
            unsigned16(0),
            nestedTupleList([proofAuthenticationNode]),
        ),
    ),
    schemaObject('manifest', 0x0110, manifest),
    schemaObject('option definition', 0x0111, manifestOptions[0]),
    schemaObject(
        'action definition',
        0x0112,
        canonicalTuple(
            0x0112,
            unsigned16(1),
            unsigned16(1),
            unsigned16(20),
            unsigned16(1),
            unsigned16(10),
            unsigned16(5),
            unsigned64(1_900_000_000_000n),
        ),
    ),
    schemaObject(
        'board policy',
        0x0113,
        canonicalTuple(
            0x0113,
            unsigned16(1),
            ascii('board.example'),
            unsigned16(1),
        ),
    ),
    schemaObject('roster entry', 0x0114, rosterEntries[0]),
    schemaObject('roster', 0x0115, roster),
    schemaObject('distribution record', 0x0116, distributionRecord(1)),
    schemaObject('artifact reference', 0x0117, artifactReference(1)),
    schemaObject('suite record', 0x0118, suiteRecord),
    schemaObject('mailbox key-schedule input', 0x0200, mailboxKeyScheduleInput),
    schemaObject('mailbox associated data', 0x0201, mailboxAssociatedData),
    schemaObject('signed mailbox envelope', 0x0202, signedMailboxEnvelope),
    schemaObject(
        'device-wrapping associated data',
        0x0300,
        deviceWrappingAssociatedData,
    ),
    schemaObject(
        'local-record associated data',
        0x0301,
        localRecordAssociatedData,
    ),
    schemaObject(
        'storage-root commitment payload',
        0x0303,
        canonicalTuple(0x0303, hash(0x35)),
    ),
    schemaObject(
        'local-record key input',
        0x0304,
        canonicalTuple(
            0x0304,
            unsigned16(1),
            hash(0x31),
            hash(0x32),
            hash(0x33),
            participantIdentity(0x34),
            unsigned16(1),
            hash(0x36),
            unsigned64(0n),
        ),
    ),
    schemaObject(
        'device-wrapped storage root',
        0x0305,
        canonicalTuple(
            0x0305,
            variableRawBytes(deviceWrappingAssociatedData),
            rawBytes(repeatedBytes(12, 0x37)),
            rawBytes(repeatedBytes(48, 0x38)),
            rawBytes(repeatedBytes(16, 0x39)),
        ),
    ),
    schemaObject(
        'local-record envelope',
        0x0306,
        canonicalTuple(
            0x0306,
            variableRawBytes(localRecordAssociatedData),
            rawBytes(repeatedBytes(12, 0x3a)),
            variableRawBytes(Uint8Array.of(1, 2, 3)),
            rawBytes(repeatedBytes(16, 0x3b)),
            rawBytes(repeatedBytes(32, 0x3c)),
        ),
    ),
    schemaObject(
        'state reservation intent',
        0x1610,
        canonicalTuple(0x1610, unsigned16(1), hash(0x81)),
    ),
    schemaObject(
        'state output intent',
        0x1611,
        canonicalTuple(0x1611, hash(0x82), hash(0x83)),
    ),
    schemaObject(
        'state witness vote',
        0x1612,
        canonicalTuple(0x1612, hash(0x84)),
    ),
    schemaObject(
        'state certificate',
        0x1613,
        canonicalTuple(
            0x1613,
            variableRawBytesList(
                Array.from({ length: 7 }, (_, index) =>
                    Uint8Array.of(index + 1),
                ),
            ),
        ),
    ),
    schemaObject(
        'state recovery transition',
        0x1614,
        canonicalTuple(0x1614, unsigned16(1), optional(0x06)),
    ),
    schemaObject('stream descriptor', 0x1800, streamDescriptor),
    schemaObject('runtime asset reference', 0x1801, runtimeAssets[0]),
    schemaObject('runtime build manifest', 0x1802, runtimeBuildManifest),
    schemaObject('random cursor', 0x1804, randomCursor),
    schemaObject(
        'checkpoint manifest',
        0x1805,
        canonicalTuple(
            0x1805,
            hash(0x72),
            hash(0x73),
            hash(0x74),
            hash(0x75),
            participantIdentity(0x76),
            rawBytes(repeatedBytes(32, 0x77)),
            unsigned16(0x1205),
            unsigned32(0),
            hashList([]),
            nestedTupleList([randomCursor]),
            nestedTuple(streamDescriptor),
        ),
    ),
    schemaObject(
        'checkpoint random-use profile',
        0x1806,
        checkpointRandomUseProfile,
    ),
    schemaObject(
        'checkpoint boundary profile',
        0x1807,
        checkpointBoundaryProfile,
    ),
    schemaObject('runtime operation profile', 0x1808, runtimeOperationProfile),
    schemaObject(
        'mobile runtime profile',
        0x1809,
        canonicalTuple(
            0x1809,
            displayText('Phone model'),
            displayText('Revision 2'),
            unsigned64(8_589_934_592n),
            unsigned64(2_147_483_648n),
            displayText('Operating system 17.5'),
            displayText('Browser engine 126'),
            displayText('Browser 126.0.1'),
            hash(0x78),
            hash(0x79),
            unsigned16(1),
        ),
    ),
    schemaObject('proof profile set', 0x2200, proofProfileSet),
    schemaObject('proof field profile', 0x2201, proofFieldProfile),
    schemaObject('proof family profile', 0x2202, proofFamilyProfile(0x1302)),
    schemaObject('proof field schedule', 0x2203, proofFieldSchedule),
] as const satisfies readonly FoundationSchemaObjectVector[];

export type InvalidFoundationSchemaObjectVector = Readonly<{
    name: string;
    expectedCode: string;
    canonicalBytes: Uint8Array;
}>;

export const invalidFoundationSchemaObjectVectors = [
    {
        name: 'unassigned schema identifier',
        expectedCode: 'UnsupportedObjectType',
        canonicalBytes: canonicalTuple(0xffff),
    },
    {
        name: 'unsupported schema version',
        expectedCode: 'UnsupportedObjectVersion',
        canonicalBytes: canonicalTupleWithVersion(0x0303, 2, hash(1)),
    },
    {
        name: 'trailing canonical bytes',
        expectedCode: 'InvalidProtocolObject',
        canonicalBytes: concatenateBytes(
            canonicalTuple(0x0303, hash(1)),
            Uint8Array.of(0),
        ),
    },
    {
        name: 'wrong canonical item type',
        expectedCode: 'InvalidProtocolObject',
        canonicalBytes: canonicalTuple(0x0303, unsigned16(1)),
    },
] as const satisfies readonly InvalidFoundationSchemaObjectVector[];

export type FoundationDisplayTextVector = Readonly<{
    name: string;
    canonicalBytes: Uint8Array;
}>;

const validDisplayText = (
    name: string,
    value: string,
): FoundationDisplayTextVector => ({
    name,
    canonicalBytes: ballotOptionDefinition(
        0,
        'canonical-option',
        textEncoder.encode(value),
    ),
});

const invalidDisplayText = (
    name: string,
    bytes: Uint8Array,
): FoundationDisplayTextVector => ({
    name,
    canonicalBytes: ballotOptionDefinition(0, 'canonical-option', bytes),
});

/**
 * Canonical Unicode 17 vectors shared verbatim by the real-WASM Node and
 * browser suites. Canonical-object verification validates stabilized NFC; it
 * never normalizes producer bytes.
 */
export const validFoundationDisplayTextVectors = [
    validDisplayText('ASCII', 'Canonical label'),
    validDisplayText('precomposed Latin', 'Caf\u00e9'),
    validDisplayText('precomposed Hangul', '\uac00'),
    validDisplayText('ordered combining marks', '\u1ea1\u0301'),
    validDisplayText('assigned supplementary scalar', '\u{10000}'),
    validDisplayText('assigned supplementary letter', '\u{10400}'),
    validDisplayText('basic private use', 'label-\ue000'),
    validDisplayText('supplementary private use', 'label-\u{10fffd}'),
] as const satisfies readonly FoundationDisplayTextVector[];

export const invalidFoundationDisplayTextVectors = [
    invalidDisplayText(
        'decomposed Latin is not NFC',
        textEncoder.encode('Cafe\u0301'),
    ),
    invalidDisplayText(
        'decomposed Hangul is not NFC',
        textEncoder.encode('\u1100\u1161'),
    ),
    invalidDisplayText(
        'canonically decomposable Angstrom sign is not NFC',
        textEncoder.encode('\u212b'),
    ),
    invalidDisplayText(
        'Unicode 17 unassigned scalar',
        textEncoder.encode('\u0378'),
    ),
    invalidDisplayText(
        'basic multilingual plane noncharacter',
        textEncoder.encode('\ufdd0'),
    ),
    invalidDisplayText(
        'supplementary noncharacter',
        textEncoder.encode('\u{10ffff}'),
    ),
    invalidDisplayText(
        'UTF-8 surrogate encoding',
        Uint8Array.from([0xed, 0xa0, 0x80]),
    ),
    invalidDisplayText(
        'overlong UTF-8 encoding',
        Uint8Array.from([0xc0, 0xaf]),
    ),
    invalidDisplayText(
        'truncated UTF-8 encoding',
        Uint8Array.from([0xe2, 0x82]),
    ),
] as const satisfies readonly FoundationDisplayTextVector[];

export const foundationHashContractVector = Object.freeze({
    domain: 'sealed-lattice/test/hash/v1',
    canonicalItemsTupleBytes: canonicalTuple(
        0x0001,
        unsigned16(0x0201),
        variableRawBytes(Uint8Array.of(7, 8, 9)),
    ),
    expectedHash:
        '8707213bf91c004dfbe283f1283f0c27aab2882b59d5555a5d65c4bd247bea15' +
        'f5536990fbc115f9ab3a557fe497e53fef5f22d4ff1ad24d5ccb1cf2ec387281',
});

export const participantIdentityContractVector = Object.freeze({
    signingVerificationKey: new Uint8Array(1_952),
    expectedParticipantIdentity:
        '69cf925b3abbe015ec3a7f083eaa55b03d82aa82f3f8754d34adc6059557f954' +
        '517b4ada80f724304f9ceee84fd5e3021c5524fef252a449e34d40c5e380178d',
});
