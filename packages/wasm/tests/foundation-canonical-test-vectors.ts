import { createCanonicalCarrierMailboxKeyPairFixtures } from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    displayTextItem,
    emptyOptionalItem,
    fixedBytesItem,
    foundationHash512,
    hashItem,
    homogeneousListItem,
    participantIdentityItem,
    presentOptionalItem,
    unsigned16Item,
    unsigned16LittleEndian,
    unsigned32Item,
    unsigned64Item,
    unsigned64LittleEndian,
    variableBytesItem,
    variableValue,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';

export type FoundationCanonicalTestVector = Readonly<{
    canonicalBytes: Uint8Array;
    name: string;
    schemaIdentifier: number;
}>;

const textEncoder = new TextEncoder();

const repeatedBytes = (byteLength: number, value: number): Uint8Array =>
    new Uint8Array(byteLength).fill(value);

const bytesFromHex = (value: string): Uint8Array => {
    if (value.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(value)) {
        throw new Error('The canonical test fixture hex is malformed.');
    }
    return Uint8Array.from({ length: value.length / 2 }, (_unused, byteIndex) =>
        Number.parseInt(value.slice(byteIndex * 2, byteIndex * 2 + 2), 16),
    );
};

const nestedTupleItem = (tuple: Uint8Array): Uint8Array =>
    canonicalItem(0x09, tuple);

const nestedTupleListItem = (tuples: readonly Uint8Array[]): Uint8Array =>
    homogeneousListItem(0x09, tuples);

const hashListItem = (hashes: readonly Uint8Array[]): Uint8Array =>
    homogeneousListItem(0x06, hashes);

const unsigned16ListItem = (values: readonly number[]): Uint8Array =>
    homogeneousListItem(0x03, values.map(unsigned16LittleEndian));

const unsigned64ListItem = (values: readonly bigint[]): Uint8Array =>
    homogeneousListItem(0x05, values.map(unsigned64LittleEndian));

const asciiListItem = (values: readonly string[]): Uint8Array =>
    homogeneousListItem(
        0x02,
        values.map((value) => variableValue(textEncoder.encode(value))),
    );

const vector = (
    name: string,
    schemaIdentifier: number,
    canonicalBytes: Uint8Array,
): FoundationCanonicalTestVector => ({
    canonicalBytes,
    name,
    schemaIdentifier,
});

const createRosterVectors = (): Readonly<{
    entry: Uint8Array;
    roster: Uint8Array;
}> => {
    const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(10);
    try {
        const entries = mailboxKeyPairs.map(({ publicKey }, rosterPosition) =>
            canonicalTuple(
                0x0114,
                unsigned16Item(rosterPosition),
                fixedBytesItem(repeatedBytes(1_952, rosterPosition + 1)),
                fixedBytesItem(publicKey),
            ),
        );
        return {
            entry: entries[0],
            roster: canonicalTuple(0x0115, nestedTupleListItem(entries)),
        };
    } finally {
        for (const { secretKey } of mailboxKeyPairs) {
            secretKey.fill(0);
        }
    }
};

const createManifestVectors = (): Readonly<{
    actionDefinition: Uint8Array;
    boardPolicy: Uint8Array;
    manifest: Uint8Array;
    optionDefinition: Uint8Array;
}> => {
    const options = Array.from({ length: 20 }, (_unused, optionIndex) =>
        canonicalTuple(
            0x0111,
            unsigned16Item(optionIndex),
            asciiItem(`option-${String(optionIndex).padStart(2, '0')}`),
            displayTextItem(`Option ${String(optionIndex + 1)}`),
        ),
    );
    return {
        actionDefinition: canonicalTuple(
            0x0112,
            unsigned16Item(5),
            unsigned64Item(1_900_000_000_000n),
        ),
        boardPolicy: canonicalTuple(0x0113, asciiItem('primary-board')),
        manifest: canonicalTuple(
            0x0110,
            displayTextItem('Canonical foundation test'),
            nestedTupleListItem(options),
        ),
        optionDefinition: options[0],
    };
};

const distributionRecord = (purpose: number): Uint8Array => {
    const ternaryPurpose = [1, 3, 8, 11].includes(purpose);
    return canonicalTuple(
        0x0116,
        unsigned16Item(purpose),
        unsigned16Item(ternaryPurpose ? 1 : 2),
        unsigned64Item(ternaryPurpose ? 0n : 2n),
    );
};

const artifactReference = (artifactKind: number): Uint8Array =>
    canonicalTuple(
        0x0117,
        unsigned16Item(artifactKind),
        unsigned64Item(3n),
        hashItem(repeatedBytes(64, 0x40 + artifactKind)),
    );

const createSuiteRecord = (): Uint8Array =>
    canonicalTuple(
        0x0118,
        unsigned16Item(10),
        unsigned16Item(3),
        unsigned16Item(4),
        unsigned16Item(7),
        unsigned32Item(8),
        unsigned64Item(17n),
        unsigned64ListItem([97n, 113n, 193n]),
        unsigned64ListItem([241n]),
        unsigned16ListItem([0, 1]),
        unsigned16ListItem([0, 1, 2]),
        unsigned16Item(2),
        unsigned16Item(2),
        unsigned16Item(3),
        unsigned16Item(10),
        unsigned32Item(64),
        unsigned32Item(128),
        unsigned32Item(15),
        unsigned32Item(400),
        unsigned64Item(2_000n),
        unsigned64Item(15_000n),
        unsigned64Item(3_000n),
        unsigned64Item(9_000n),
        unsigned64Item(30_000n),
        unsigned64Item(5_000n),
        unsigned64Item(40_000n),
        nestedTupleListItem(
            Array.from({ length: 12 }, (_unused, index) =>
                distributionRecord(index + 1),
            ),
        ),
        nestedTupleListItem(
            Array.from({ length: 6 }, (_unused, index) =>
                artifactReference(index + 1),
            ),
        ),
    );

const createObjectEnvelope = (): Uint8Array =>
    canonicalTuple(
        0x0100,
        asciiItem('sealed-lattice'),
        unsigned16Item(1),
        hashItem(repeatedBytes(64, 0x11)),
        unsigned16Item(0x0051),
        hashItem(repeatedBytes(64, 0x22)),
        hashItem(repeatedBytes(64, 0x33)),
        unsigned64Item(0n),
        emptyOptionalItem(0x06),
        emptyOptionalItem(0x07),
        unsigned64Item(0n),
        hashListItem([repeatedBytes(64, 0x44)]),
        variableBytesItem(Uint8Array.of(0x51, 0x01)),
    );

const createMailboxVectors = (): Readonly<{
    associatedData: Uint8Array;
    keyScheduleInput: Uint8Array;
    signedEnvelope: Uint8Array;
}> => {
    const kemCiphertext = repeatedBytes(1_088, 0x5a);
    const kemCiphertextHash = foundationHash512(
        'sealed-lattice/mailbox/kem-ciphertext/v1',
        fixedBytesItem(kemCiphertext),
    );
    const keyScheduleItems = [
        hashItem(repeatedBytes(64, 0x11)),
        hashItem(repeatedBytes(64, 0x22)),
        hashItem(repeatedBytes(64, 0x33)),
        hashItem(repeatedBytes(64, 0x44)),
        participantIdentityItem(repeatedBytes(64, 0x55)),
        participantIdentityItem(repeatedBytes(64, 0x66)),
        unsigned64Item(9n),
        fixedBytesItem(repeatedBytes(32, 0x77)),
        unsigned16Item(2),
        hashItem(repeatedBytes(64, 0x88)),
        hashListItem([repeatedBytes(64, 0x99)]),
        hashItem(kemCiphertextHash),
    ] as const;
    const plaintextByteLength = 19n;
    const associatedData = canonicalTuple(
        0x0201,
        ...keyScheduleItems,
        unsigned64Item(plaintextByteLength),
    );
    const streamDescriptor = canonicalTuple(
        0x1800,
        unsigned64Item(plaintextByteLength),
        hashListItem([repeatedBytes(64, 0xaa)]),
    );
    return {
        associatedData,
        keyScheduleInput: canonicalTuple(0x0200, ...keyScheduleItems),
        signedEnvelope: canonicalTuple(
            0x0202,
            variableBytesItem(associatedData),
            fixedBytesItem(kemCiphertext),
            nestedTupleItem(streamDescriptor),
            fixedBytesItem(repeatedBytes(16, 0xcc)),
            fixedBytesItem(repeatedBytes(3_309, 0xdd)),
        ),
    };
};

const createLocalStorageVectors =
    (): readonly FoundationCanonicalTestVector[] => {
        const bindingItems = [
            hashItem(repeatedBytes(64, 0x11)),
            hashItem(repeatedBytes(64, 0x22)),
            hashItem(repeatedBytes(64, 0x33)),
            participantIdentityItem(repeatedBytes(64, 0x44)),
        ] as const;
        const actionStorageDerivationInput = canonicalTuple(
            0x0308,
            unsigned16Item(1),
            ...bindingItems,
        );
        const actionStorageRoot = repeatedBytes(48, 0x45);
        const storageRootCommitment = bytesFromHex(
            '0028917659afe506058cb3b4d15da98c7a351c74771a7e2b2cbbb31a364b2d246db9c89b6d2d08d7402a5f25c283ea4846d27e2df276a9738d5b89e44d08849a',
        );
        const recoveryChecksum = bytesFromHex(
            '3c703c11a543968b8e5ecfc26c197096',
        );
        const recoveryValue = canonicalTuple(
            0x0302,
            unsigned16Item(1),
            ...bindingItems,
            hashItem(storageRootCommitment),
            fixedBytesItem(actionStorageRoot),
            fixedBytesItem(recoveryChecksum),
        );
        const deviceAssociatedData = canonicalTuple(
            0x0300,
            unsigned16Item(1),
            ...bindingItems,
            hashItem(storageRootCommitment),
            unsigned64Item(48n),
        );
        const deviceWrappedRoot = canonicalTuple(
            0x0305,
            variableBytesItem(deviceAssociatedData),
            fixedBytesItem(repeatedBytes(12, 0x56)),
            fixedBytesItem(repeatedBytes(48, 0x67)),
            fixedBytesItem(repeatedBytes(16, 0x78)),
        );
        const actionRandomnessCommitment = repeatedBytes(64, 0x55);
        const recordIdentifier = repeatedBytes(64, 0x66);
        const ciphertext = textEncoder.encode('authenticated local record');
        const localRecordAssociatedData = canonicalTuple(
            0x0301,
            unsigned16Item(1),
            ...bindingItems,
            hashItem(actionRandomnessCommitment),
            unsigned16Item(5),
            hashItem(recordIdentifier),
            unsigned64Item(0n),
            unsigned64Item(3n),
            emptyOptionalItem(0x06),
            unsigned64Item(BigInt(ciphertext.byteLength)),
        );
        const nonce = repeatedBytes(12, 0x77);
        const tag = repeatedBytes(16, 0x88);
        const localRecordKeyInput = canonicalTuple(
            0x0304,
            unsigned16Item(1),
            ...bindingItems,
            hashItem(actionRandomnessCommitment),
            unsigned16Item(5),
            hashItem(recordIdentifier),
            unsigned64Item(0n),
        );
        const localRecordAuthenticatorInput = canonicalTuple(
            0x0307,
            variableBytesItem(localRecordAssociatedData),
            fixedBytesItem(nonce),
            variableBytesItem(ciphertext),
            fixedBytesItem(tag),
        );
        const localRecordEnvelope = canonicalTuple(
            0x0306,
            variableBytesItem(localRecordAssociatedData),
            fixedBytesItem(nonce),
            variableBytesItem(ciphertext),
            fixedBytesItem(tag),
            fixedBytesItem(repeatedBytes(32, 0x99)),
        );

        return [
            vector(
                'device wrapping associated data',
                0x0300,
                deviceAssociatedData,
            ),
            vector(
                'local record associated data',
                0x0301,
                localRecordAssociatedData,
            ),
            vector('storage root recovery value', 0x0302, recoveryValue),
            vector(
                'storage root commitment payload',
                0x0303,
                canonicalTuple(0x0303, hashItem(storageRootCommitment)),
            ),
            vector('local record key input', 0x0304, localRecordKeyInput),
            vector('device wrapped storage root', 0x0305, deviceWrappedRoot),
            vector('local record envelope', 0x0306, localRecordEnvelope),
            vector(
                'local record authenticator input',
                0x0307,
                localRecordAuthenticatorInput,
            ),
            vector(
                'action storage derivation input',
                0x0308,
                actionStorageDerivationInput,
            ),
        ];
    };

const createStateVectors = (): readonly FoundationCanonicalTestVector[] => [
    vector(
        'state reservation intent',
        0x1610,
        canonicalTuple(
            0x1610,
            unsigned16Item(1),
            hashItem(repeatedBytes(64, 0x11)),
        ),
    ),
    vector(
        'state output intent',
        0x1611,
        canonicalTuple(
            0x1611,
            hashItem(repeatedBytes(64, 0x22)),
            hashItem(repeatedBytes(64, 0x33)),
        ),
    ),
    vector(
        'state witness vote',
        0x1612,
        canonicalTuple(0x1612, hashItem(repeatedBytes(64, 0x44))),
    ),
    vector(
        'state certificate',
        0x1613,
        canonicalTuple(
            0x1613,
            homogeneousListItem(
                0x01,
                Array.from({ length: 7 }, (_unused, index) =>
                    variableValue(Uint8Array.of(index + 1)),
                ),
            ),
        ),
    ),
    vector(
        'state recovery transition',
        0x1614,
        canonicalTuple(
            0x1614,
            unsigned16Item(1),
            presentOptionalItem(0x06, repeatedBytes(64, 0x55)),
        ),
    ),
];

const createRuntimeVectors = (): readonly FoundationCanonicalTestVector[] => {
    const randomUse = canonicalTuple(
        0x1806,
        unsigned16Item(0x0116),
        unsigned16Item(1),
    );
    const boundary = canonicalTuple(
        0x1807,
        unsigned32Item(0),
        unsigned16Item(0x1610),
        nestedTupleListItem([randomUse]),
    );
    const operation = canonicalTuple(
        0x1808,
        unsigned16Item(1),
        nestedTupleListItem([boundary]),
    );
    const assets = [
        canonicalTuple(
            0x1801,
            unsigned16Item(1),
            asciiItem('/app.js'),
            unsigned64Item(101n),
            hashItem(repeatedBytes(64, 0x31)),
        ),
        canonicalTuple(
            0x1801,
            unsigned16Item(2),
            asciiItem('/worker.js'),
            unsigned64Item(102n),
            hashItem(repeatedBytes(64, 0x32)),
        ),
        canonicalTuple(
            0x1801,
            unsigned16Item(3),
            asciiItem('/kernel.wasm'),
            unsigned64Item(103n),
            hashItem(repeatedBytes(64, 0x33)),
        ),
    ];
    const buildManifest = canonicalTuple(
        0x1802,
        unsigned16Item(1),
        asciiItem('test-release'),
        hashItem(repeatedBytes(64, 0x11)),
        asciiItem('/suite.cbor'),
        asciiListItem(
            Array.from(
                { length: 6 },
                (_unused, index) => `/suite-artifact-${String(index + 1)}.cbor`,
            ),
        ),
        nestedTupleListItem(assets),
        nestedTupleListItem([operation]),
    );
    const privateRandomCursor = canonicalTuple(
        0x1804,
        unsigned16Item(0x0116),
        unsigned16Item(1),
        hashItem(repeatedBytes(64, 0x44)),
        fixedBytesItem(repeatedBytes(32, 0x55)),
        unsigned64Item(1n),
        presentOptionalItem(0x03, unsigned16LittleEndian(7)),
    );
    return [
        vector(
            'stream descriptor',
            0x1800,
            canonicalTuple(
                0x1800,
                unsigned64Item(19n),
                hashListItem([repeatedBytes(64, 0x21)]),
            ),
        ),
        vector('runtime asset reference', 0x1801, assets[0]),
        vector('runtime build manifest', 0x1802, buildManifest),
        vector('private random cursor', 0x1804, privateRandomCursor),
        vector('checkpoint random use profile', 0x1806, randomUse),
        vector('checkpoint boundary profile', 0x1807, boundary),
        vector('runtime operation profile', 0x1808, operation),
    ];
};

export const createFoundationCanonicalTestVectors =
    (): readonly FoundationCanonicalTestVector[] => {
        const roster = createRosterVectors();
        const manifest = createManifestVectors();
        const objectEnvelope = createObjectEnvelope();
        const mailbox = createMailboxVectors();
        const vectors = [
            vector('object envelope', 0x0100, objectEnvelope),
            vector(
                'signed carrier',
                0x0101,
                canonicalTuple(
                    0x0101,
                    variableBytesItem(objectEnvelope),
                    fixedBytesItem(repeatedBytes(3_309, 0x5a)),
                ),
            ),
            vector('manifest', 0x0110, manifest.manifest),
            vector('option definition', 0x0111, manifest.optionDefinition),
            vector('action definition', 0x0112, manifest.actionDefinition),
            vector('board policy', 0x0113, manifest.boardPolicy),
            vector('roster entry', 0x0114, roster.entry),
            vector('roster', 0x0115, roster.roster),
            vector('distribution record', 0x0116, distributionRecord(1)),
            vector('artifact reference', 0x0117, artifactReference(1)),
            vector('suite record', 0x0118, createSuiteRecord()),
            vector(
                'mailbox key schedule input',
                0x0200,
                mailbox.keyScheduleInput,
            ),
            vector('mailbox associated data', 0x0201, mailbox.associatedData),
            vector('signed mailbox envelope', 0x0202, mailbox.signedEnvelope),
            ...createLocalStorageVectors(),
            ...createStateVectors(),
            ...createRuntimeVectors(),
        ];
        if (vectors.length !== 35) {
            throw new Error(
                `Expected 35 foundation schema vectors, received ${String(vectors.length)}.`,
            );
        }
        return vectors;
    };

export const foundationCanonicalSchemaIdentifiers = [
    0x0100, 0x0101, 0x0110, 0x0111, 0x0112, 0x0113, 0x0114, 0x0115, 0x0116,
    0x0117, 0x0118, 0x0200, 0x0201, 0x0202, 0x0300, 0x0301, 0x0302, 0x0303,
    0x0304, 0x0305, 0x0306, 0x0307, 0x0308, 0x1610, 0x1611, 0x1612, 0x1613,
    0x1614, 0x1800, 0x1801, 0x1802, 0x1804, 0x1806, 0x1807, 0x1808,
] as const;

export const createDeterministicCanonicalByteFragments = (
    canonicalBytes: Uint8Array,
): readonly Uint8Array[] => {
    const fragments: Uint8Array[] = [];
    const widths = [1, 2, 3, 5, 8, 13, 21] as const;
    let offset = 0;
    let widthIndex = 0;
    while (offset < canonicalBytes.byteLength) {
        const end = Math.min(
            canonicalBytes.byteLength,
            offset + widths[widthIndex % widths.length],
        );
        fragments.push(canonicalBytes.slice(offset, end));
        offset = end;
        widthIndex += 1;
    }
    return fragments;
};
