import type { ParticipantProfile } from './bounds.js';
import {
    concatenate,
    encodeText,
    equalBytes,
    readUnsigned16,
    readUnsigned32,
    tupleFields,
    unsigned16,
    unsigned32,
} from './bytes.js';
import {
    isSetupContributor,
    PublicInputFailure,
    sessionInput,
} from './context.js';
import type { ProfileContext } from './context.js';
import { custodyIdentity, custodyPurpose } from './identity.js';
import {
    readKernel,
    writeContributionSeed,
    writeProofInput,
} from './kernel.js';
import type { ParticipantStoredRecord } from './predecessor.js';
import { publishChunk, publishRecord, readPublic } from './public.js';
import type { PublicRelay } from './public.js';
import {
    chunkBytes,
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
    StoragePending,
} from './root.js';
import type { AuthenticatedRoot } from './root.js';
import {
    proposalRecordIds,
    registrationFile,
    registrationPath,
} from './roster.js';
import type { VerifiedProposal } from './roster.js';
import {
    addParticipantRecords,
    discardStagedRecords,
    readParticipantValue,
    snapshotParticipant,
} from './storage.js';

// A setup contributor's contribution; only the first roster positions
// contribute. Generation four locks the generation
// intent with the seed of all its randomness before the prover draws any;
// generation five retains the sealed first-oracle checkpoint and the retained
// body polynomials; generation six locks the continuation with the seed of
// its randomness; generation seven retains the complete body. An interrupted
// generation or continuation draws the same bytes from its seed again, so it
// reproduces the same outputs. Generations eight to eleven sign the
// confirmation and, after every confirmation is known, the opening, each with
// coins locked beforehand. The root's contribution suffix lists every record
// key and ciphertext hash.
//
// Every other participant confirms the roster without a contribution: its
// confirmation names its own registration body. Generation eight locks the
// confirmation body with its signing coins and generation nine retains the
// signature, under the same record names.

type RecordLocation = Readonly<{
    object: number;
    offset: number;
    length: number;
}>;

type SealedRecord = RecordLocation &
    Readonly<{ key: Uint8Array; hash: Uint8Array }>;

type CheckpointRecord = Readonly<{ key: Uint8Array; hash: Uint8Array }>;

type ContributionState = Readonly<{
    position: number;
    salt: Uint8Array;
    header: Uint8Array;
    publicRecords: readonly SealedRecord[];
    privateRecords: readonly CheckpointRecord[];
    signingRecords: readonly SealedRecord[];
    // The randomness seed of a generation or continuation intent.
    seed: Uint8Array;
    coins: Uint8Array;
}>;

// What a sealed record is bound to besides its location.
type RecordContext = Readonly<{
    poll: Uint8Array;
    runtime: Uint8Array;
    proposal: Uint8Array;
    position: number;
}>;

// What every operation from the accepted roster on shares. A setup
// contributor's session retains its contribution from generation four, and
// any other participant's its roster confirmation from generation eight.
export type ParticipantSession = {
    readonly context: ProfileContext;
    readonly records: RecordContext;
    root: AuthenticatedRoot;
    state?: ContributionState;
};

export type ContributionSession = ParticipantSession & {
    state: ContributionState;
};

export const isContributionSession = (
    session: ParticipantSession,
): session is ContributionSession => session.state !== undefined;

export type SignedPacket = Readonly<{
    body: Uint8Array;
    signature: Uint8Array;
}>;

const publicEntryBytes = 2 + 4 + 4 + 32 + 64;
const privateEntryBytes = 32 + 64;
const signingEntryBytes = 2 + 4 + 32 + 64;
const keyBytes = 32;
const coinBytes = 32;
const seedBytes = 64;
const identityBytes = 64;

// Prover phases: generation below one hundred, then one hundred plus the
// proof phase.
const proverPhase = {
    firstInitialize: 103,
    firstColumn: 104,
    polynomials: 107,
    output: 110,
    done: 111,
} as const;

const proverCommand = {
    generate: 2,
    step: 7,
    beginPolynomial: 8,
    pushPolynomial: 9,
    finishPolynomial: 10,
    nextOutput: 11,
    consumePredecessor: 14,
} as const;

const checkpointCommand = {
    exportHeader: 1,
    seal: 2,
    complete: 3,
    import: 4,
    open: 5,
    finish: 6,
} as const;

const signingCommand = {
    beginBody: 1,
    polynomial: 2,
    proof: 3,
    finishBody: 4,
    signConfirmation: 5,
    restoreConfirmation: 6,
    acceptConfirmation: 7,
    finishInventory: 8,
    signOpening: 9,
    consumeOpening: 10,
    validatePosition: 11,
    confirmationBody: 12,
    openingBody: 13,
    rosterConfirmationBody: 14,
    signRosterConfirmation: 15,
} as const;

// Signing records follow the proof in this order, one generation after
// another.
const signingKinds = [
    'confirmationBody',
    'confirmationSignature',
    'inventory',
    'openingBody',
    'openingSignature',
] as const;
type SigningKind = (typeof signingKinds)[number];

// Setup polynomial i is object i + 1, as the prover emits it; the proof and
// the signing records follow the last setup polynomial.
const proofObject = (profile: ParticipantProfile) =>
    profile.contribution.expandedPolynomials + 1;

const signingObject = (profile: ParticipantProfile, kind: SigningKind) =>
    proofObject(profile) + 1 + signingKinds.indexOf(kind);

// The confirmation inventory is the participant count and every
// participant's packet.
const inventoryBytes = (profile: ParticipantProfile) =>
    profile.root.setupInventoryBytes;

const signingLength = (profile: ParticipantProfile, kind: SigningKind) =>
    kind === 'confirmationBody'
        ? profile.contribution.confirmationBodyBytes
        : kind === 'openingBody'
          ? profile.contribution.openingBodyBytes
          : kind === 'inventory'
            ? inventoryBytes(profile)
            : profile.registration.signatureBytes;

// The records, seed and coins each generation retains; later generations
// keep the opened state.
const retainedShape = (generation: number) => {
    const stage = Math.min(generation, 11);
    return {
        stage,
        signingRecords:
            stage <= 7
                ? 0
                : stage === 8
                  ? 1
                  : stage === 9
                    ? 2
                    : stage === 10
                      ? 4
                      : 5,
        seedBytes: stage === 4 || stage === 6 ? seedBytes : 0,
        coinBytes: stage === 8 || stage === 10 ? coinBytes : 0,
    };
};

const prefixBytes = (profile: ParticipantProfile) =>
    4 + 2 + profile.contribution.saltBytes + 4 * 4;

const proofLength = (state: ContributionState, profile: ParticipantProfile) =>
    state.publicRecords
        .filter((record) => record.object === proofObject(profile))
        .reduce((total, record) => total + record.length, 0);

const encodeSigningRecord = (record: SealedRecord) =>
    concatenate(
        unsigned16(record.object),
        unsigned32(record.length),
        record.key,
        record.hash,
    );

// A setup contributor's state lists its whole contribution; any other
// participant's only its roster confirmation records and coins.
const encodeContributionState = (
    state: ContributionState,
    profile: ParticipantProfile,
) =>
    state.position >= profile.setupContributorCount
        ? concatenate(
              encodeText('PRC1'),
              unsigned16(state.position),
              unsigned32(state.signingRecords.length),
              ...state.signingRecords.map(encodeSigningRecord),
              state.coins,
          )
        : concatenate(
              encodeText('PCS2'),
              unsigned16(state.position),
              state.salt,
              unsigned32(state.header.length),
              unsigned32(state.publicRecords.length),
              unsigned32(state.privateRecords.length),
              unsigned32(state.signingRecords.length),
              state.header,
              ...state.publicRecords.map((record) =>
                  concatenate(
                      unsigned16(record.object),
                      unsigned32(record.offset),
                      unsigned32(record.length),
                      record.key,
                      record.hash,
                  ),
              ),
              ...state.privateRecords.map((record) =>
                  concatenate(record.key, record.hash),
              ),
              ...state.signingRecords.map(encodeSigningRecord),
              state.seed,
              state.coins,
          );

// Decodes the first signing records in their order from the offset.
const decodeSigningRecords = (
    bytes: Uint8Array,
    offset: number,
    count: number,
    profile: ParticipantProfile,
) =>
    signingKinds.slice(0, count).map((kind, index) => {
        const start = offset + index * signingEntryBytes;
        const record = {
            object: readUnsigned16(bytes, start),
            offset: 0,
            length: readUnsigned32(bytes, start + 2),
            key: bytes.slice(start + 6, start + 6 + keyBytes),
            hash: bytes.slice(start + 6 + keyBytes, start + signingEntryBytes),
        };
        if (
            record.object !== signingObject(profile, kind) ||
            record.length !== signingLength(profile, kind)
        )
            throw new Error('Noncanonical contribution signing record.');
        return record;
    });

// Decodes the roster confirmation of a participant outside the setup
// contributors: the locked body with coins at generation eight, and the
// signed confirmation from generation nine on. Such a participant never
// holds the contributor-only generations.
const decodeConfirmationState = (
    bytes: Uint8Array,
    generation: number,
    profile: ParticipantProfile,
): ContributionState => {
    const locked = generation === 8;
    const signingCount = locked ? 1 : 2;
    const coins = locked ? coinBytes : 0;
    const prefix = 4 + 2 + 4;
    if (
        (generation !== 8 && generation !== 9 && generation < 12) ||
        bytes.length !== prefix + signingEntryBytes * signingCount + coins ||
        !equalBytes(bytes.subarray(0, 4), encodeText('PRC1')) ||
        readUnsigned32(bytes, 6) !== signingCount
    )
        throw new Error(
            'The roster confirmation does not match its generation.',
        );
    const position = readUnsigned16(bytes, 4);
    if (
        position < profile.setupContributorCount ||
        position >= profile.participantCount
    )
        throw new Error('The roster confirmation names another position.');
    return {
        position,
        salt: new Uint8Array(),
        header: new Uint8Array(),
        publicRecords: [],
        privateRecords: [],
        signingRecords: decodeSigningRecords(
            bytes,
            prefix,
            signingCount,
            profile,
        ),
        seed: new Uint8Array(),
        coins: bytes.slice(prefix + signingEntryBytes * signingCount),
    };
};

// Decodes the contribution suffix of an authenticated root. The retained
// body records must be exactly the profile's, the proof records contiguous
// chunks of a proof of valid length, and the signing records those of the
// generation.
const decodeContributionState = (
    bytes: Uint8Array,
    generation: number,
    profile: ParticipantProfile,
): ContributionState => {
    const bounds = profile.contribution;
    const prefix = prefixBytes(profile);
    if (
        generation < 4 ||
        bytes.length < prefix ||
        bytes.length > bounds.maximumStateBytes ||
        !equalBytes(bytes.subarray(0, 4), encodeText('PCS2'))
    )
        throw new Error('Invalid contribution state.');
    const position = readUnsigned16(bytes, 4);
    const counts = 6 + bounds.saltBytes;
    const headerLength = readUnsigned32(bytes, counts);
    const publicCount = readUnsigned32(bytes, counts + 4);
    const privateCount = readUnsigned32(bytes, counts + 8);
    const signingCount = readUnsigned32(bytes, counts + 12);
    const shape = retainedShape(generation);
    const bodyRecords = bounds.publicRecords.length;
    const maximumProofRecords = Math.ceil(
        bounds.maximumProofBytes / chunkBytes,
    );
    const shaped =
        shape.stage === 4
            ? headerLength === 0 && publicCount === 0 && privateCount === 0
            : shape.stage <= 6
              ? headerLength >= 1 &&
                headerLength <= bounds.maximumCheckpointHeaderBytes &&
                publicCount === bodyRecords &&
                privateCount === bounds.checkpointLengths.length
              : headerLength === 0 &&
                privateCount === 0 &&
                publicCount > bodyRecords &&
                publicCount <= bodyRecords + maximumProofRecords;
    if (
        position >= profile.setupContributorCount ||
        !shaped ||
        signingCount !== shape.signingRecords ||
        bytes.length !==
            prefix +
                headerLength +
                publicEntryBytes * publicCount +
                privateEntryBytes * privateCount +
                signingEntryBytes * signingCount +
                shape.seedBytes +
                shape.coinBytes
    )
        throw new Error(
            'The contribution state does not match its generation.',
        );
    let offset = prefix + headerLength;
    const publicRecords: SealedRecord[] = [];
    let proofBytes = 0;
    for (let index = 0; index < publicCount; index++) {
        const record = {
            object: readUnsigned16(bytes, offset),
            offset: readUnsigned32(bytes, offset + 2),
            length: readUnsigned32(bytes, offset + 6),
            key: bytes.slice(offset + 10, offset + 10 + keyBytes),
            hash: bytes.slice(
                offset + 10 + keyBytes,
                offset + publicEntryBytes,
            ),
        };
        let canonical: boolean;
        if (index < bodyRecords) {
            const expected = bounds.publicRecords[index];
            canonical =
                record.object === expected.object &&
                record.offset === expected.offset &&
                record.length === expected.length;
        } else {
            canonical =
                record.object === proofObject(profile) &&
                record.offset === proofBytes &&
                record.length >= 1 &&
                record.length <= chunkBytes &&
                (index === publicCount - 1 || record.length === chunkBytes);
            proofBytes += record.length;
        }
        if (!canonical) throw new Error('Noncanonical contribution record.');
        publicRecords.push(record);
        offset += publicEntryBytes;
    }
    if (
        shape.stage >= 7 &&
        (proofBytes < bounds.minimumProofBytes ||
            proofBytes > bounds.maximumProofBytes)
    )
        throw new Error('The retained proof has an invalid length.');
    const privateRecords: CheckpointRecord[] = [];
    for (let index = 0; index < privateCount; index++) {
        privateRecords.push({
            key: bytes.slice(offset, offset + keyBytes),
            hash: bytes.slice(offset + keyBytes, offset + privateEntryBytes),
        });
        offset += privateEntryBytes;
    }
    const signingRecords = decodeSigningRecords(
        bytes,
        offset,
        signingCount,
        profile,
    );
    offset += signingEntryBytes * signingCount;
    return {
        position,
        salt: bytes.slice(6, counts),
        header: bytes.slice(prefix, prefix + headerLength),
        publicRecords,
        privateRecords,
        signingRecords,
        seed: bytes.slice(offset, offset + shape.seedBytes),
        coins: bytes.slice(offset + shape.seedBytes),
    };
};

// Each record has its own key, so the fixed zero nonce is used once per key.
const recordAssociatedData = (context: RecordContext, record: RecordLocation) =>
    concatenate(
        encodeText('participant-contribution-record/1'),
        context.poll,
        context.runtime,
        context.proposal,
        unsigned16(context.position),
        unsigned16(record.object),
        unsigned32(record.offset),
        unsigned32(record.length),
    );

const recordCipher = (key: Uint8Array, usage: 'encrypt' | 'decrypt') =>
    crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-GCM', false, [
        usage,
    ]);

type SealedOutput = Readonly<{
    record: SealedRecord;
    ciphertext: Uint8Array;
}>;

const sealRecord = async (
    session: ParticipantSession,
    object: number,
    offset: number,
    bytes: Uint8Array,
): Promise<SealedOutput> => {
    const key = crypto.getRandomValues(new Uint8Array(keyBytes));
    const location = { object, offset, length: bytes.length };
    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(12),
                additionalData: new Uint8Array(
                    recordAssociatedData(session.records, location),
                ),
            },
            await recordCipher(key, 'encrypt'),
            new Uint8Array(bytes),
        ),
    );
    return {
        record: {
            ...location,
            key,
            hash: custodyIdentity(
                session.context.kernel,
                custodyPurpose.record,
                ciphertext,
            ),
        },
        ciphertext,
    };
};

const openRecord = async (
    session: ParticipantSession,
    record: SealedRecord,
) => {
    const blob = await readParticipantValue(
        session.context.database,
        'contribution',
        [record.object, record.offset],
    );
    if (!(blob instanceof Blob) || blob.size !== record.length + 16)
        throw new Error('A contribution record is missing.');
    const ciphertext = new Uint8Array(await blob.arrayBuffer());
    if (
        !equalBytes(
            custodyIdentity(
                session.context.kernel,
                custodyPurpose.record,
                ciphertext,
            ),
            record.hash,
        )
    )
        throw new Error('A contribution record changed.');
    const bytes = new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(12),
                additionalData: new Uint8Array(
                    recordAssociatedData(session.records, record),
                ),
            },
            await recordCipher(record.key, 'decrypt'),
            ciphertext,
        ),
    );
    if (bytes.length !== record.length)
        throw new Error('A contribution record has another length.');
    return bytes;
};

const openSigning = (session: ContributionSession, kind: SigningKind) => {
    const object = signingObject(session.context.profile, kind);
    const record = session.state.signingRecords.find(
        (value) => value.object === object,
    );
    if (record === undefined)
        throw new Error('A contribution signing record is missing.');
    return openRecord(session, record);
};

// The stored records a contribution state lists. With a record context each
// sealed record must also open under its own key.
const contributionInventory = (
    profile: ParticipantProfile,
    state: ContributionState,
    context?: RecordContext,
): ParticipantStoredRecord[] => [
    ...[...state.publicRecords, ...state.signingRecords].map((record) => ({
        store: 'contribution',
        key: [record.object, record.offset],
        byteLength: record.length + 16,
        identity: record.hash,
        ...(context === undefined
            ? {}
            : {
                  encryption: {
                      key: record.key,
                      additionalData: recordAssociatedData(context, record),
                  },
              }),
    })),
    ...state.privateRecords.map((record, index) => ({
        store: 'checkpoint',
        key: index,
        byteLength: profile.contribution.checkpointLengths[index],
        identity: record.hash,
    })),
];

type ContributionTransition = Readonly<{
    generation: number;
    state: ContributionState;
    // Generated records stored ahead of this root; its transition checks
    // that each one opens before it commits.
    staged?: boolean;
    // Signing records written with the root.
    signing?: readonly SealedOutput[];
    clearCheckpoint?: boolean;
}>;

const commitContribution = async (
    session: ParticipantSession,
    transition: ContributionTransition,
) => {
    const { context, root } = session;
    const profile = context.profile;
    const predecessor =
        root.head.generation >= 4 && session.state !== undefined
            ? contributionInventory(profile, session.state)
            : [];
    const listed = new Set(
        predecessor.map(
            (record) => record.store + ':' + JSON.stringify(record.key),
        ),
    );
    const staged =
        transition.staged === true
            ? contributionInventory(
                  profile,
                  transition.state,
                  session.records,
              ).filter(
                  (record) =>
                      !listed.has(
                          record.store + ':' + JSON.stringify(record.key),
                      ),
              )
            : [];
    session.root = await commitRoot(context, root, {
        generation: transition.generation,
        manifest: {
            ...root.manifest,
            suffixes: {
                ...root.manifest.suffixes,
                contribution: encodeContributionState(
                    transition.state,
                    profile,
                ),
            },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...predecessor,
            ...staged,
        ],
        write: (transaction) => {
            for (const output of transition.signing ?? [])
                transaction
                    .objectStore('contribution')
                    .add(new Blob([new Uint8Array(output.ciphertext)]), [
                        output.record.object,
                        output.record.offset,
                    ]);
            if (transition.clearCheckpoint === true)
                transaction.objectStore('checkpoint').clear();
        },
    });
    session.state = transition.state;
    for (const output of transition.signing ?? [])
        (await openRecord(session, output.record)).fill(0);
};

const proverOutput = (context: ProfileContext) =>
    readKernel(
        context.kernel,
        context.kernel.contribution_proof_output_pointer(),
        context.kernel.contribution_proof_output_length(),
    );

const checkpoint = (
    context: ProfileContext,
    operation: number,
    position = 0,
    bytes: Uint8Array = new Uint8Array(),
) => {
    writeProofInput(context.kernel, bytes);
    return context.kernel.contribution_checkpoint_command(
        operation,
        position,
        bytes.length,
    );
};

const signing = (
    context: ProfileContext,
    operation: number,
    bytes: Uint8Array = new Uint8Array(),
    argument = 0,
) => {
    sessionInput(context, bytes);
    if (
        context.kernel.contribution_signing(
            operation,
            argument,
            bytes.length,
        ) !== 0
    )
        throw new Error('The contribution signer refused an operation.');
    return readKernel(
        context.kernel,
        context.kernel.contribution_output_pointer(),
        context.kernel.contribution_output_length(),
    );
};

const packet = (body: Uint8Array, signature: Uint8Array) =>
    concatenate(unsigned32(body.length), body, signature);

const splitPacket = (
    bytes: Uint8Array,
    profile: ParticipantProfile,
): SignedPacket => {
    const signatureBytes = profile.registration.signatureBytes;
    if (
        bytes.length < 4 ||
        bytes.length !== 4 + readUnsigned32(bytes, 0) + signatureBytes
    )
        throw new Error('Malformed signed contribution packet.');
    return {
        body: bytes.slice(4, bytes.length - signatureBytes),
        signature: bytes.slice(bytes.length - signatureBytes),
    };
};

// Runs prover commands with the randomness of one generation or
// continuation, which the module expands from its retained seed. Only
// generation emits statement output; its retained body output is sealed and
// stored as it arrives.
const proverRun = (session: ContributionSession, statement: boolean) => {
    const { context } = session;
    const { kernel, handlers, profile } = context;
    const bounds = profile.contribution;
    const bodyObjects = new Set(
        bounds.publicRecords.map((record) => record.object),
    );
    const lengths = new Map<number, number>();
    const pending: { object: number; offset: number; bytes: Uint8Array }[] = [];
    const stored: SealedRecord[] = [];
    let current = 0;
    let emitted = 0;
    let randomBytes = 0;
    if (session.state.seed.length !== seedBytes)
        throw new Error('No contribution randomness seed is retained.');
    writeContributionSeed(kernel, session.state.seed);
    if (kernel.contribution_random_command(0, seedBytes) !== 0)
        throw new Error('The contribution randomness refused its seed.');
    handlers.random = (source, target) => {
        if (source !== 'witness' && source !== 'proof')
            throw new Error('Unexpected contribution randomness request.');
        if (
            kernel.contribution_random_command(
                source === 'witness' ? 1 : 2,
                target.length,
            ) !== 0
        )
            throw new Error('The contribution randomness refused a request.');
        const output = new Uint8Array(
            kernel.memory.buffer,
            kernel.contribution_random_output_pointer() >>> 0,
            target.length,
        );
        target.set(output);
        output.fill(0);
        randomBytes += target.length;
    };
    handlers.contribution = (object, offset, bytes) => {
        if (
            !statement ||
            (object !== current && object !== current + 1) ||
            object > bounds.expandedPolynomials ||
            bytes.length < 1 ||
            bytes.length > chunkBytes ||
            offset !== (lengths.get(object) ?? 0) ||
            bytes.length > bounds.statementBytes - emitted
        )
            throw new Error('Invalid generated contribution output.');
        current = object;
        if (bodyObjects.has(object)) pending.push({ object, offset, bytes });
        lengths.set(object, offset + bytes.length);
        emitted += bytes.length;
    };
    // Seals pending body output in the profile's record order.
    const store = async () => {
        const records = pending.splice(0);
        const outputs: SealedOutput[] = [];
        try {
            for (const record of records) {
                const expected =
                    bounds.publicRecords[stored.length + outputs.length];
                if (
                    stored.length + outputs.length >=
                        bounds.publicRecords.length ||
                    record.object !== expected.object ||
                    record.offset !== expected.offset ||
                    record.bytes.length !== expected.length
                )
                    throw new Error('Generated body output is noncanonical.');
                outputs.push(
                    await sealRecord(
                        session,
                        record.object,
                        record.offset,
                        record.bytes,
                    ),
                );
            }
        } finally {
            for (const record of records) record.bytes.fill(0);
        }
        if (outputs.length === 0) return;
        await addParticipantRecords(
            context.database,
            'contribution',
            outputs.map((output) => ({
                key: [output.record.object, output.record.offset],
                bytes: output.ciphertext,
            })),
        );
        stored.push(...outputs.map((output) => output.record));
    };
    const advance = async (
        operation: number,
        argument = 0,
        bytes: Uint8Array = new Uint8Array(),
    ) => {
        writeProofInput(kernel, bytes);
        if (
            kernel.contribution_proof_command(
                operation,
                argument,
                bytes.length,
            ) !== 0
        )
            throw new Error('The contribution prover refused an operation.');
        await store();
    };
    return {
        advance,
        store,
        stored,
        phase: () => kernel.contribution_proof_phase(),
        objects: () => lengths.size,
        emitted: () => emitted,
        randomBytes: () => randomBytes,
        close: () => {
            handlers.random = undefined;
            handlers.contribution = undefined;
            kernel.contribution_random_command(3, 0);
            for (const record of pending) record.bytes.fill(0);
            pending.length = 0;
        },
    };
};

// Discards what an interrupted generation or continuation stored before its
// root committed: at generation four every contribution and checkpoint
// record, and at generation six every proof record. Their keys existed only
// in the interrupted operation, which runs again from its retained seed.
export const discardInterruptedRecords = (
    context: ProfileContext,
    root: AuthenticatedRoot,
) => {
    const proof = proofObject(context.profile);
    if (root.head.generation === 4)
        return discardStagedRecords(context.database, [
            { store: 'contribution' },
            { store: 'checkpoint' },
        ]);
    if (root.head.generation === 6)
        return discardStagedRecords(context.database, [
            {
                store: 'contribution',
                keys: IDBKeyRange.bound([proof], [proof + 1], false, true),
            },
        ]);
    throw new Error('No interrupted contribution work is retained.');
};

// Locks the contribution intent with a fresh randomness seed for the
// verified signed proposal after the credential accepts its position and the
// origin has room for the retained contribution.
export const beginContribution = async (
    context: ProfileContext,
    root: AuthenticatedRoot,
    proposal: VerifiedProposal,
): Promise<ContributionSession> => {
    if (root.head.generation !== 3)
        throw new Error('No agreed roster awaits a contribution.');
    signing(
        context,
        signingCommand.validatePosition,
        unsigned16(proposal.position),
    );
    const estimate = await navigator.storage.estimate();
    if (
        estimate.quota === undefined ||
        estimate.usage === undefined ||
        estimate.quota - estimate.usage <
            context.profile.contribution.requiredStorageBytes
    )
        throw new StoragePending('The origin lacks room for a contribution.');
    const session: ContributionSession = {
        context,
        records: {
            poll: root.manifest.poll,
            runtime: context.runtime,
            proposal: proposal.identity,
            position: proposal.position,
        },
        root,
        state: {
            position: proposal.position,
            salt: crypto.getRandomValues(
                new Uint8Array(context.profile.contribution.saltBytes),
            ),
            header: new Uint8Array(),
            publicRecords: [],
            privateRecords: [],
            signingRecords: [],
            seed: crypto.getRandomValues(new Uint8Array(seedBytes)),
            coins: new Uint8Array(),
        },
    };
    await commitContribution(session, { generation: 4, state: session.state });
    return session;
};

// Generates the contribution from the intent's seed, advances the proof to
// the last first-oracle column, and retains the sealed checkpoint with the
// body polynomials. The checkpoint retires the seed. An interrupted
// generation runs again from the same seed once its stored records are
// discarded.
export const generateContribution = async (session: ContributionSession) => {
    const { context } = session;
    const { kernel, profile } = context;
    const bounds = profile.contribution;
    if (session.root.head.generation !== 4)
        throw new Error('No contribution intent is locked.');
    const run = proverRun(session, true);
    const privateRecords: CheckpointRecord[] = [];
    let header: Uint8Array;
    try {
        if (kernel.begin_contribution(session.state.position) !== 0)
            throw new Error('The credential refused contribution generation.');
        await run.store();
        while (run.phase() < 100) await run.advance(proverCommand.generate);
        if (
            run.phase() !== proverPhase.firstInitialize ||
            run.objects() !== bounds.expandedPolynomials + 1 ||
            run.emitted() !== bounds.statementBytes ||
            run.stored.length !== bounds.publicRecords.length
        )
            throw new Error('The generated contribution is incomplete.');
        // The checkpoint follows every first-oracle column but the last.
        for (let step = 0; step < bounds.firstOracleColumns + 2; step++)
            await run.advance(proverCommand.step);
        if (
            run.phase() !== proverPhase.firstColumn ||
            kernel.contribution_checkpoint_records() !==
                bounds.checkpointLengths.length ||
            checkpoint(context, checkpointCommand.exportHeader) !== 0
        )
            throw new Error('The first-oracle checkpoint is unavailable.');
        header = proverOutput(context);
        if (
            header.length < 1 ||
            header.length > bounds.maximumCheckpointHeaderBytes
        )
            throw new Error('The checkpoint header has an invalid length.');
        const batch: { key: number; bytes: Uint8Array }[] = [];
        for (const [index, length] of bounds.checkpointLengths.entries()) {
            const key = crypto.getRandomValues(new Uint8Array(keyBytes));
            if (checkpoint(context, checkpointCommand.seal, 0, key) !== 0)
                throw new Error('A checkpoint record was refused.');
            const sealed = proverOutput(context);
            if (sealed.length !== length)
                throw new Error('A checkpoint record has another length.');
            privateRecords.push({
                key,
                hash: custodyIdentity(kernel, custodyPurpose.record, sealed),
            });
            batch.push({ key: index, bytes: sealed });
            if (
                batch.length === 64 ||
                index === bounds.checkpointLengths.length - 1
            )
                await addParticipantRecords(
                    context.database,
                    'checkpoint',
                    batch.splice(0),
                );
        }
        if (checkpoint(context, checkpointCommand.complete) !== 0)
            throw new Error('The checkpoint is incomplete.');
    } finally {
        run.close();
    }
    await commitContribution(session, {
        generation: 5,
        state: {
            ...session.state,
            header,
            publicRecords: run.stored,
            privateRecords,
            seed: new Uint8Array(),
        },
        staged: true,
    });
    return run.randomBytes();
};

// Resumes the checkpointed prover in a new instance. Each recipient key comes
// from its public registration and must match the checkpoint's key hash.
export const restoreCheckpoint = async (
    session: ContributionSession,
    relay: PublicRelay,
) => {
    const { context, state } = session;
    const { kernel, profile } = context;
    const { generation } = session.root.head;
    if (generation !== 5 && generation !== 6)
        throw new Error('No contribution checkpoint is retained.');
    if (
        checkpoint(
            context,
            checkpointCommand.import,
            state.position,
            concatenate(
                session.records.poll,
                session.records.runtime,
                session.records.proposal,
                state.header,
            ),
        ) !== 0
    )
        throw new Error('The retained proof context was refused.');
    for (const [index, record] of state.privateRecords.entries()) {
        const blob = await readParticipantValue(
            context.database,
            'checkpoint',
            index,
        );
        const length = profile.contribution.checkpointLengths[index];
        if (!(blob instanceof Blob) || blob.size !== length)
            throw new Error('A checkpoint record is missing.');
        const sealed = new Uint8Array(await blob.arrayBuffer());
        if (
            !equalBytes(
                custodyIdentity(context.kernel, custodyPurpose.record, sealed),
                record.hash,
            )
        )
            throw new Error('A checkpoint record changed.');
        const input = concatenate(record.key, sealed);
        try {
            if (checkpoint(context, checkpointCommand.open, 0, input) !== 0)
                throw new Error('A checkpoint record was refused.');
        } finally {
            input.fill(0);
        }
    }
    const recordIds = proposalRecordIds(
        await readDataKind(context, session.root.manifest, dataKind.proposal),
    );
    for (const [position, id] of recordIds.entries()) {
        const key = await readPublic(
            relay,
            registrationPath(id, registrationFile.publicKey),
            profile.registration.publicKeyBytes,
        );
        writeProofInput(kernel, key);
        if (kernel.contribution_checkpoint_key(position, key.length) !== 0)
            throw new PublicInputFailure(
                'A recipient key does not match the checkpoint.',
            );
    }
    if (
        checkpoint(context, checkpointCommand.finish) !== 0 ||
        kernel.contribution_proof_phase() !== proverPhase.firstColumn
    )
        throw new Error('The contribution did not resume exactly.');
};

// Locks the continuation with a fresh randomness seed, completes the proof
// over the retained body, and retains the complete body, which retires the
// seed. An interrupted continuation runs again from the same seed once its
// stored proof records are discarded.
export const continueContribution = async (session: ContributionSession) => {
    const { context } = session;
    const { profile } = context;
    const bounds = profile.contribution;
    const { generation } = session.root.head;
    if (generation !== 5 && generation !== 6)
        throw new Error('No contribution checkpoint is retained.');
    if (generation === 5)
        await commitContribution(session, {
            generation: 6,
            state: {
                ...session.state,
                seed: crypto.getRandomValues(new Uint8Array(seedBytes)),
            },
        });
    const { state } = session;
    const run = proverRun(session, false);
    const proof: SealedRecord[] = [];
    const buffer = new Uint8Array(chunkBytes);
    let used = 0;
    let proofBytes = 0;
    const sealProof = async () => {
        const output = await sealRecord(
            session,
            proofObject(profile),
            proofBytes,
            buffer.subarray(0, used),
        );
        await addParticipantRecords(context.database, 'contribution', [
            {
                key: [output.record.object, output.record.offset],
                bytes: output.ciphertext,
            },
        ]);
        proof.push(output.record);
        proofBytes += used;
        used = 0;
    };
    try {
        while (run.phase() !== proverPhase.polynomials)
            await run.advance(proverCommand.step);
        for (let index = 0; index < bounds.expandedPolynomials; index++) {
            const records = state.publicRecords.filter(
                (record) => record.object === index + 1,
            );
            if (records.length === 0) {
                await run.advance(proverCommand.consumePredecessor, index);
                continue;
            }
            await run.advance(proverCommand.beginPolynomial, index);
            for (const record of records) {
                const bytes = await openRecord(session, record);
                try {
                    await run.advance(proverCommand.pushPolynomial, 0, bytes);
                } finally {
                    bytes.fill(0);
                }
            }
            await run.advance(proverCommand.finishPolynomial);
        }
        // The linear oracle, then the folded combination.
        await run.advance(proverCommand.step);
        await run.advance(proverCommand.step);
        while (run.phase() === proverPhase.output) {
            await run.advance(proverCommand.nextOutput);
            const bytes = proverOutput(context);
            if (bytes.length > bounds.maximumProofBytes - proofBytes - used)
                throw new Error('The proof exceeds its bound.');
            for (let offset = 0; offset < bytes.length;) {
                const count = Math.min(
                    bytes.length - offset,
                    chunkBytes - used,
                );
                buffer.set(bytes.subarray(offset, offset + count), used);
                offset += count;
                used += count;
                if (used === chunkBytes) await sealProof();
            }
        }
        if (used > 0) await sealProof();
        if (
            run.phase() !== proverPhase.done ||
            proofBytes < bounds.minimumProofBytes ||
            proofBytes > bounds.maximumProofBytes
        )
            throw new Error('The continued proof is incomplete.');
    } finally {
        buffer.fill(0);
        run.close();
    }
    await commitContribution(session, {
        generation: 7,
        state: {
            ...state,
            header: new Uint8Array(),
            publicRecords: [...state.publicRecords, ...proof],
            privateRecords: [],
            seed: new Uint8Array(),
        },
        staged: true,
        clearCheckpoint: true,
    });
    return run.randomBytes();
};

// The body header: its marker and the proof length.
const bodyHeader = (proofBytes: number) => {
    const header = new Uint8Array(12);
    header.set(encodeText('SCB1'));
    new DataView(header.buffer).setBigUint64(4, BigInt(proofBytes), true);
    return header;
};

// Recomputes the commitment to the retained body in the module's signer.
const bodyCommitment = async (session: ContributionSession) => {
    const { context, state } = session;
    const { profile } = context;
    const control = concatenate(
        unsigned16(state.position),
        state.salt,
        bodyHeader(proofLength(state, profile)),
    );
    try {
        signing(context, signingCommand.beginBody, control);
    } finally {
        control.fill(0);
    }
    for (const polynomial of profile.contribution.polynomials)
        for (const record of state.publicRecords.filter(
            (value) => value.object === polynomial.expandedIndex + 1,
        )) {
            const bytes = await openRecord(session, record);
            const input = concatenate(unsigned32(record.offset), bytes);
            try {
                signing(
                    context,
                    signingCommand.polynomial,
                    input,
                    polynomial.expandedIndex,
                );
            } finally {
                bytes.fill(0);
                input.fill(0);
            }
        }
    for (const record of state.publicRecords.filter(
        (value) => value.object === proofObject(profile),
    )) {
        const bytes = await openRecord(session, record);
        try {
            signing(context, signingCommand.proof, bytes, record.offset);
        } finally {
            bytes.fill(0);
        }
    }
    return signing(context, signingCommand.finishBody);
};

// Signs the confirmation of the retained body with coins locked beforehand,
// or restores a completed confirmation into the module's signer.
// A signed confirmation is delivered again from its authenticated records;
// delivery needs no signer state.
export const storedConfirmation = async (
    session: ContributionSession,
): Promise<SignedPacket> => ({
    body: await openSigning(session, 'confirmationBody'),
    signature: await openSigning(session, 'confirmationSignature'),
});

// Signs the confirmation of the retained body once, or after it is signed
// restores it into the signer. Restoration authenticates the rebuilt
// commitment against the signed proposal, so its session must be bound to
// the proposal verified again in this invocation.
export const confirmContribution = async (
    session: ContributionSession,
): Promise<SignedPacket> => {
    const { context } = session;
    const { profile } = context;
    if (session.root.head.generation < 7)
        throw new Error('No contribution body is retained.');
    const commitment = await bodyCommitment(session);
    if (session.root.head.generation === 7) {
        const output = await sealRecord(
            session,
            signingObject(profile, 'confirmationBody'),
            0,
            signing(context, signingCommand.confirmationBody),
        );
        await commitContribution(session, {
            generation: 8,
            state: {
                ...session.state,
                signingRecords: [
                    ...session.state.signingRecords,
                    output.record,
                ],
                coins: crypto.getRandomValues(new Uint8Array(coinBytes)),
            },
            signing: [output],
        });
    }
    const body = await openSigning(session, 'confirmationBody');
    if (session.root.head.generation === 8) {
        if (
            !equalBytes(signing(context, signingCommand.confirmationBody), body)
        )
            throw new Error('The locked confirmation changed.');
        const control = concatenate(commitment, session.state.coins);
        let signed: SignedPacket;
        try {
            signed = splitPacket(
                signing(context, signingCommand.signConfirmation, control),
                profile,
            );
        } finally {
            control.fill(0);
        }
        if (!equalBytes(signed.body, body))
            throw new Error('The signer changed the confirmation.');
        const output = await sealRecord(
            session,
            signingObject(profile, 'confirmationSignature'),
            0,
            signed.signature,
        );
        await commitContribution(session, {
            generation: 9,
            state: {
                ...session.state,
                signingRecords: [
                    ...session.state.signingRecords,
                    output.record,
                ],
                coins: new Uint8Array(),
            },
            signing: [output],
        });
    } else
        signing(
            context,
            signingCommand.restoreConfirmation,
            packet(body, await openSigning(session, 'confirmationSignature')),
        );
    return storedConfirmation(session);
};

export const contributionDirectory = (position: number) =>
    'contribution-' + String(position) + '/';

export const polynomialFile = (expandedIndex: number) =>
    'polynomial-' + String(expandedIndex).padStart(2, '0') + '.bin';

// Reads every participant's published confirmation into one inventory.
export const readConfirmations = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    const { profile } = session.context;
    const packets: Uint8Array[] = [];
    for (let position = 0; position < profile.participantCount; position++) {
        const directory = contributionDirectory(position);
        const confirmation = packet(
            await readPublic(
                relay,
                directory + 'confirmation.bin',
                profile.contribution.confirmationBodyBytes,
            ),
            await readPublic(
                relay,
                directory + 'confirmation-signature.bin',
                profile.registration.signatureBytes,
            ),
        );
        if (
            confirmation.length !== profile.contribution.confirmationPacketBytes
        )
            throw new PublicInputFailure('A confirmation is incomplete.');
        packets.push(confirmation);
    }
    return concatenate(unsigned32(profile.participantCount), ...packets);
};

// Every confirmation must pass the module's verifier before the inventory
// identity exists.
const loadInventory = (session: ContributionSession, inventory: Uint8Array) => {
    const { context } = session;
    const { profile } = context;
    const packetBytes = profile.contribution.confirmationPacketBytes;
    if (
        inventory.length !== inventoryBytes(profile) ||
        readUnsigned32(inventory, 0) !== profile.participantCount
    )
        throw new PublicInputFailure(
            'The confirmation inventory is incomplete.',
        );
    for (let position = 0; position < profile.participantCount; position++) {
        const confirmation = inventory.subarray(
            4 + position * packetBytes,
            4 + (position + 1) * packetBytes,
        );
        sessionInput(context, confirmation);
        if (
            context.kernel.contribution_signing(
                signingCommand.acceptConfirmation,
                0,
                confirmation.length,
            ) !== 0
        )
            throw new PublicInputFailure('A confirmation was refused.');
    }
    const identity = signing(context, signingCommand.finishInventory);
    if (identity.length !== identityBytes)
        throw new Error('The inventory identity has another length.');
    return identity;
};

// Signs the opening over the complete confirmation inventory with coins
// locked beforehand, or consumes a completed opening. The module's signer
// must hold the restored confirmation.
export const openContribution = async (
    session: ContributionSession,
    relay: PublicRelay,
): Promise<SignedPacket> => {
    const { context } = session;
    const { profile } = context;
    if (session.root.head.generation < 9)
        throw new Error('No signed confirmation is retained.');
    const inventory =
        session.root.head.generation === 9
            ? await readConfirmations(session, relay)
            : await openSigning(session, 'inventory');
    const identity = loadInventory(session, inventory);
    if (session.root.head.generation === 9) {
        const outputs = [
            await sealRecord(
                session,
                signingObject(profile, 'inventory'),
                0,
                inventory,
            ),
            await sealRecord(
                session,
                signingObject(profile, 'openingBody'),
                0,
                signing(context, signingCommand.openingBody),
            ),
        ];
        await commitContribution(session, {
            generation: 10,
            state: {
                ...session.state,
                signingRecords: [
                    ...session.state.signingRecords,
                    ...outputs.map((output) => output.record),
                ],
                coins: crypto.getRandomValues(new Uint8Array(coinBytes)),
            },
            signing: outputs,
        });
    }
    const body = await openSigning(session, 'openingBody');
    if (session.root.head.generation === 10) {
        if (!equalBytes(signing(context, signingCommand.openingBody), body))
            throw new Error('The locked opening changed.');
        const control = concatenate(identity, session.state.coins);
        let signed: SignedPacket;
        try {
            signed = splitPacket(
                signing(context, signingCommand.signOpening, control),
                profile,
            );
        } finally {
            control.fill(0);
        }
        if (!equalBytes(signed.body, body))
            throw new Error('The signer changed the opening.');
        const output = await sealRecord(
            session,
            signingObject(profile, 'openingSignature'),
            0,
            signed.signature,
        );
        await commitContribution(session, {
            generation: 11,
            state: {
                ...session.state,
                signingRecords: [
                    ...session.state.signingRecords,
                    output.record,
                ],
                coins: new Uint8Array(),
            },
            signing: [output],
        });
    } else
        signing(
            context,
            signingCommand.consumeOpening,
            packet(body, await openSigning(session, 'openingSignature')),
        );
    return { body, signature: await openSigning(session, 'openingSignature') };
};

// Has the module retain the stored proposal's context at this participant's
// position and returns the proposal's identity.
const retainProposal = async (
    context: ProfileContext,
    root: AuthenticatedRoot,
) => {
    const { kernel } = context;
    const proposal = await readDataKind(
        context,
        root.manifest,
        dataKind.proposal,
    );
    const control = concatenate(
        root.manifest.poll,
        context.runtime,
        unsigned16(context.position),
        unsigned32(proposal.length),
        proposal,
    );
    sessionInput(context, control);
    if (kernel.retain_proposal(control.length) !== 0)
        throw new Error('The retained proposal context was refused.');
    return readKernel(
        kernel,
        kernel.retained_proposal_identity_pointer(),
        identityBytes,
    );
};

// Decodes the retained contribution of a root after its intent. Every listed
// record must be stored and nothing else, so interrupted one-shot work cannot
// continue. The records bind to the verified signed proposal when the caller
// verified it again: accepting confirmations and restoring a signed
// confirmation need it. Otherwise the module retains the stored proposal's
// context, which suffices for the checkpoint and the confirmation signature.
export const resumeContribution = async (
    context: ProfileContext,
    root: AuthenticatedRoot,
    verified?: VerifiedProposal,
): Promise<ContributionSession> => {
    const { profile } = context;
    const suffix = root.manifest.suffixes.contribution;
    if (root.head.generation < 4 || suffix === undefined)
        throw new Error('No contribution is retained.');
    const state = decodeContributionState(
        suffix,
        root.head.generation,
        profile,
    );
    if (state.position !== context.position)
        throw new Error('The retained contribution names another position.');
    const snapshot = await snapshotParticipant(context.database);
    if (
        snapshot.counts.contribution !==
            state.publicRecords.length + state.signingRecords.length ||
        snapshot.counts.checkpoint !== state.privateRecords.length
    )
        throw new Error('The contribution records changed.');
    let identity: Uint8Array;
    if (verified === undefined) identity = await retainProposal(context, root);
    else {
        if (verified.position !== state.position)
            throw new Error('The verified proposal moved this participant.');
        identity = verified.identity;
    }
    return {
        context,
        records: {
            poll: root.manifest.poll,
            runtime: context.runtime,
            proposal: identity,
            position: state.position,
        },
        root,
        state,
    };
};

// Resumes a setup contributor from its retained contribution, and any other
// participant from its accepted roster on, with its roster confirmation once
// that is locked. Every listed record must be stored and nothing else.
export const resumeParticipant = async (
    context: ProfileContext,
    root: AuthenticatedRoot,
): Promise<ParticipantSession> => {
    if (isSetupContributor(context)) return resumeContribution(context, root);
    const { generation } = root.head;
    const suffix = root.manifest.suffixes.contribution;
    if (generation < 3 || (generation === 3) !== (suffix === undefined))
        throw new Error('No accepted roster is retained.');
    const state =
        suffix === undefined
            ? undefined
            : decodeConfirmationState(suffix, generation, context.profile);
    if (state !== undefined && state.position !== context.position)
        throw new Error('The roster confirmation names another position.');
    const snapshot = await snapshotParticipant(context.database);
    if (
        snapshot.counts.contribution !== (state?.signingRecords.length ?? 0) ||
        snapshot.counts.checkpoint !== 0
    )
        throw new Error('The roster confirmation records changed.');
    return {
        context,
        records: {
            poll: root.manifest.poll,
            runtime: context.runtime,
            proposal: await retainProposal(context, root),
            position: context.position,
        },
        root,
        ...(state === undefined ? {} : { state }),
    };
};

// Signs the roster confirmation of a participant outside the setup
// contributors once, with coins locked beforehand, and delivers it again
// from its authenticated records afterwards. The module rebuilds the body
// from the retained roster, which names this participant's own registration
// body.
export const confirmRoster = async (
    session: ParticipantSession,
): Promise<SignedPacket> => {
    const { context } = session;
    const { profile } = context;
    if (isSetupContributor(context))
        throw new Error('A setup contributor confirms its contribution.');
    const retained = () => {
        if (!isContributionSession(session))
            throw new Error('No roster confirmation is retained.');
        return session;
    };
    if (session.root.head.generation === 3) {
        const output = await sealRecord(
            session,
            signingObject(profile, 'confirmationBody'),
            0,
            signing(context, signingCommand.rosterConfirmationBody),
        );
        await commitContribution(session, {
            generation: 8,
            state: {
                position: context.position,
                salt: new Uint8Array(),
                header: new Uint8Array(),
                publicRecords: [],
                privateRecords: [],
                signingRecords: [output.record],
                seed: new Uint8Array(),
                coins: crypto.getRandomValues(new Uint8Array(coinBytes)),
            },
            signing: [output],
        });
    }
    if (session.root.head.generation === 8) {
        const locked = retained();
        const body = await openSigning(locked, 'confirmationBody');
        if (
            !equalBytes(
                signing(context, signingCommand.rosterConfirmationBody),
                body,
            )
        )
            throw new Error('The locked confirmation changed.');
        const signed = splitPacket(
            signing(
                context,
                signingCommand.signRosterConfirmation,
                locked.state.coins,
            ),
            profile,
        );
        if (!equalBytes(signed.body, body))
            throw new Error('The signer changed the confirmation.');
        const output = await sealRecord(
            locked,
            signingObject(profile, 'confirmationSignature'),
            0,
            signed.signature,
        );
        await commitContribution(locked, {
            generation: 9,
            state: {
                ...locked.state,
                signingRecords: [...locked.state.signingRecords, output.record],
                coins: new Uint8Array(),
            },
            signing: [output],
        });
    }
    return storedConfirmation(retained());
};

// The stored records the retained contribution or roster confirmation
// lists, if any.
export const contributionRecords = (session: ParticipantSession) =>
    isContributionSession(session)
        ? contributionInventory(session.context.profile, session.state)
        : [];

// The signed opening, as retained.
export const storedOpening = async (
    session: ContributionSession,
): Promise<SignedPacket> => {
    if (session.root.head.generation < 11)
        throw new Error('No opening is retained.');
    return {
        body: await openSigning(session, 'openingBody'),
        signature: await openSigning(session, 'openingSignature'),
    };
};

// The confirmation inventory this participant opened and its identity, as
// the retained opening body names it.
export const openedInventory = async (session: ContributionSession) => {
    if (session.root.head.generation < 11)
        throw new Error('No opening is retained.');
    const inventory = await openSigning(session, 'inventory');
    const fields = tupleFields(await openSigning(session, 'openingBody'));
    if (fields.length !== 4 || fields[1].length !== identityBytes)
        throw new Error('The retained opening is malformed.');
    return { inventory, identity: fields[1].slice() };
};

export const publishConfirmation = async (
    session: ParticipantSession,
    relay: PublicRelay,
    confirmation: SignedPacket,
) => {
    const directory = contributionDirectory(session.records.position);
    await publishRecord(
        relay,
        directory + 'confirmation.bin',
        confirmation.body,
    );
    await publishRecord(
        relay,
        directory + 'confirmation-signature.bin',
        confirmation.signature,
    );
};

// Publishes the opening and then the body it opens, under the names the
// native records use.
export const publishOpening = async (
    session: ContributionSession,
    relay: PublicRelay,
    opening: SignedPacket,
) => {
    const { profile } = session.context;
    const directory = contributionDirectory(session.state.position);
    await publishRecord(relay, directory + 'opening.bin', opening.body);
    await publishRecord(
        relay,
        directory + 'opening-signature.bin',
        opening.signature,
    );
    await publishRecord(
        relay,
        directory + 'body-header.bin',
        bodyHeader(proofLength(session.state, profile)),
    );
    for (const record of session.state.publicRecords) {
        const bytes = await openRecord(session, record);
        try {
            await publishChunk(
                relay,
                directory +
                    (record.object === proofObject(profile)
                        ? 'proof.bin'
                        : polynomialFile(record.object - 1)),
                record.offset,
                bytes,
            );
        } finally {
            bytes.fill(0);
        }
    }
};
