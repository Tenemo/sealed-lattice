import { validateParticipantPredecessor } from '../protocol-participant-predecessor.js';
import { commitParticipantState } from '../protocol-participant-state-transaction.js';

import {
    concatenate,
    encodeText,
    equalBytes,
    hexadecimal,
    sha512,
    tupleFields,
    unsigned16,
    unsigned32,
} from './bytes.js';
import { ownRegistrationInput, sessionInput } from './context.js';
import type { ParticipantContext } from './context.js';
import { readKernel } from './kernel.js';
import {
    authenticateRoot,
    chunkBytes,
    createRootKey,
    dataKind,
    dataKindMaximums,
    encodeManifest,
    readDataKind,
    readDataRecord,
    rootAssociatedData,
    sealRoot,
} from './root.js';
import type { AuthenticatedRoot, RecordReference } from './root.js';
import {
    participantRecordStores,
    participantStores,
    snapshotParticipant,
} from './storage.js';

export type EnrollmentRequest = Readonly<
    | {
          role: 'creator';
          manifest: Uint8Array;
          topCount: number;
          username: string;
      }
    | {
          role: 'join';
          poll: Uint8Array;
          definition: Uint8Array;
          definitionSignature: Uint8Array;
          username: string;
      }
>;

// Validation of the empty namespace and of the intent is bounded by the
// foreground visit limit.
const validationMilliseconds = 15 * 60 * 1000;

// A lone surrogate cannot be encoded without replacement, which would change
// the name that the credential binds.
const encodeUsername = (username: string) => {
    for (let index = 0; index < username.length; index++) {
        const unit = username.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = username.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) return undefined;
            index++;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) return undefined;
    }
    return encodeText(username);
};

// Signing purposes in the credential's order, each with the last generation
// at which the root still shows it unused. A purpose whose intent the root
// retains stays unlocked until its completion generation.
const lastUnusedGeneration = [2, 8, 10, 16, 18, 20, 21, 23, 28];

const unusedPurposes = (generation: number) =>
    lastUnusedGeneration.reduce(
        (mask, last, purpose) =>
            generation <= last ? mask | (1 << purpose) : mask,
        0,
    );

type StagedRecord = { kind: number; offset: number; bytes: Uint8Array };

// Creates the original credential and recipient key for an empty namespace.
// The intent commits before any private generation, and the completed root,
// head and every record commit together; interruption between them stops
// the participant, so the caller learns when the intent exists. A refusal
// leaves the namespace unchanged.
export const createEnrollment = async (
    context: ParticipantContext,
    request: EnrollmentRequest,
    onIntent: () => void,
): Promise<AuthenticatedRoot | undefined> => {
    const { database, descriptor, kernel, handlers, runtime } = context;
    const empty = await snapshotParticipant(database);
    if (participantStores.some((store) => empty.counts[store] !== 0))
        return undefined;
    const name = encodeUsername(request.username);
    if (
        name === undefined ||
        name.length > descriptor.registration.maximumUsernameIngressBytes
    )
        return undefined;
    let input: Uint8Array;
    if (request.role === 'creator') {
        if (
            !Number.isSafeInteger(request.topCount) ||
            request.topCount < 1 ||
            request.topCount > 0xffff
        )
            return undefined;
        input = concatenate(
            runtime,
            unsigned16(request.topCount),
            unsigned32(request.manifest.length),
            request.manifest,
            unsigned32(name.length),
            name,
        );
        if (input.length + 64 > kernel.input_capacity()) return undefined;
        sessionInput(context, input);
        if (kernel.validate_creator(input.length) !== 0) return undefined;
    } else {
        if (
            request.poll.length !== 64 ||
            request.definitionSignature.length !==
                descriptor.registration.signatureBytes
        )
            return undefined;
        input = concatenate(
            request.poll,
            runtime,
            unsigned32(request.definition.length),
            request.definition,
            request.definitionSignature,
            unsigned32(name.length),
            name,
        );
        if (input.length + 64 > kernel.input_capacity()) return undefined;
        sessionInput(context, input);
        if (kernel.validate_join(input.length) !== 0) return undefined;
    }
    const estimate = await navigator.storage.estimate();
    if (
        estimate.quota === undefined ||
        estimate.usage === undefined ||
        estimate.quota - estimate.usage <
            2 *
                (descriptor.registration.publicKeyBytes +
                    descriptor.registration.maximumProofBytes)
    )
        return undefined;
    const associatedData = rootAssociatedData(runtime);
    const key = await createRootKey();
    const intentPlaintext = concatenate(
        encodeText('INI2'),
        await sha512(input),
    );
    const intent = await sealRoot(key, 0, associatedData, intentPlaintext);
    const intentHead = {
        generation: 0,
        hash: hexadecimal(await sha512(intent)),
    };
    await commitParticipantState({
        database,
        stores: participantStores,
        timeoutMilliseconds: validationMilliseconds,
        validate: async (reader) => {
            for (const store of participantStores)
                if ((await reader.count(store)) !== 0)
                    throw new Error('The participant namespace is not empty.');
        },
        write: (transaction) => {
            transaction.objectStore('key').add(key, 0);
            transaction.objectStore('root').add(intent, 0);
            transaction.objectStore('head').add(intentHead, 0);
        },
    });
    onIntent();
    // The two capsule data keys must differ.
    const dataKeys = crypto.getRandomValues(new Uint8Array(64));
    if (equalBytes(dataKeys.subarray(0, 32), dataKeys.subarray(32)))
        throw new Error('Repeated enrollment data keys.');
    const maximums = dataKindMaximums(descriptor);
    const lengths = maximums.map(() => 0);
    const records: StagedRecord[] = [];
    handlers.staged = (kind, offset, bytes) => {
        if (
            kind > dataKind.pollSignature ||
            bytes.length === 0 ||
            bytes.length > chunkBytes ||
            offset !== lengths[kind] ||
            bytes.length > maximums[kind] - offset
        )
            throw new Error('Invalid staged enrollment record.');
        records.push({ kind, offset, bytes });
        lengths[kind] += bytes.length;
    };
    let randomBytes = 0;
    handlers.random = (source, target) => {
        if (source === 'ballot')
            throw new Error('Enrollment requested ballot randomness.');
        crypto.getRandomValues(target);
        randomBytes += target.length;
    };
    const control = concatenate(input, dataKeys);
    let prepared: number;
    try {
        sessionInput(context, control);
        prepared =
            request.role === 'creator'
                ? kernel.prepare_creator(control.length)
                : kernel.prepare_join(control.length);
    } finally {
        control.fill(0);
        delete handlers.staged;
        delete handlers.random;
    }
    if (prepared !== 0 || kernel.check_retained() !== 0)
        throw new Error('Enrollment preparation failed.');
    const poll = readKernel(kernel, kernel.poll_identity_pointer(), 64);
    if (request.role === 'join') {
        if (request.definition.length > maximums[dataKind.pollDefinition])
            throw new Error('The poll definition exceeds its bound.');
        records.push(
            {
                kind: dataKind.pollDefinition,
                offset: 0,
                bytes: request.definition,
            },
            {
                kind: dataKind.pollSignature,
                offset: 0,
                bytes: request.definitionSignature,
            },
        );
        lengths[dataKind.pollDefinition] = request.definition.length;
        lengths[dataKind.pollSignature] = request.definitionSignature.length;
    }
    const registration = descriptor.registration;
    if (
        lengths[dataKind.publicKey] !== registration.publicKeyBytes ||
        lengths[dataKind.proof] === 0 ||
        lengths[dataKind.header] === 0 ||
        lengths[dataKind.signature] !== registration.signatureBytes ||
        lengths[dataKind.recipientCapsule] !==
            registration.recipientCapsuleBytes ||
        lengths[dataKind.signingCapsule] !== registration.signingCapsuleBytes ||
        lengths[dataKind.pollDefinition] === 0 ||
        lengths[dataKind.pollSignature] !== registration.signatureBytes
    )
        throw new Error('Incomplete enrollment.');
    const before = randomBytes;
    if (
        kernel.prepare_creator(0) !== 1 ||
        kernel.prepare_join(0) !== 1 ||
        kernel.check_retained() !== 0 ||
        randomBytes !== before
    )
        throw new Error('Repeated preparation changed authority.');
    records.sort((left, right) =>
        left.kind === right.kind
            ? left.offset - right.offset
            : left.kind - right.kind,
    );
    const references: RecordReference[] = [];
    for (const record of records)
        references.push({
            kind: record.kind,
            offset: record.offset,
            length: record.bytes.length,
            hash: await sha512(record.bytes),
        });
    const plaintext = encodeManifest(
        { dataKeys, poll, references, suffixes: {} },
        1,
    );
    dataKeys.fill(0);
    if (plaintext.length + 16 > descriptor.root.maximumRootBytes)
        throw new Error('The enrollment root exceeds its bound.');
    // The initial key seals the intent and the completed root under their
    // distinct generation nonces.
    const sealed = await sealRoot(key, 1, associatedData, plaintext);
    plaintext.fill(0);
    const head = { generation: 1, hash: hexadecimal(await sha512(sealed)) };
    await commitParticipantState({
        database,
        stores: participantStores,
        timeoutMilliseconds: validationMilliseconds,
        validate: (reader) =>
            validateParticipantPredecessor(reader, {
                head: intentHead,
                manifest: intentPlaintext,
                rootContext: associatedData,
                maximumRootBytes: descriptor.root.maximumRootBytes,
                recordStores: participantRecordStores,
                records: [],
            }),
        write: (transaction) => {
            for (const record of records)
                transaction
                    .objectStore('data')
                    .add(new Blob([new Uint8Array(record.bytes)]), [
                        record.kind,
                        record.offset,
                    ]);
            transaction.objectStore('root').put(sealed, 0);
            transaction.objectStore('head').put(head, 0);
        },
    });
    for (const record of records) record.bytes.fill(0);
    const root = await authenticateRoot(database, runtime, descriptor);
    if (root.head.generation !== 1 || root.head.hash !== head.hash)
        throw new Error('Enrollment readback failed.');
    return root;
};

export type RestoredEnrollment = Readonly<{
    username: string;
    isOrganizer: boolean;
    bodyDigest: Uint8Array;
    proofHash: Uint8Array;
    header: Uint8Array;
    signature: Uint8Array;
    definition: Uint8Array;
    definitionSignature: Uint8Array;
}>;

// Verifies the retained registration through the module's own registration
// verifier, checks the retained poll definition, and restores the original
// keys. The purposes the root shows unused stay available; an instance that
// created the credential in this invocation keeps its live authority.
export const restoreEnrollment = async (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    created: boolean,
): Promise<RestoredEnrollment> => {
    const { database, kernel, runtime } = context;
    const manifest = root.manifest;
    const read = (kind: number) => readDataKind(database, manifest, kind);
    const header = await read(dataKind.header);
    const signature = await read(dataKind.signature);
    const definition = await read(dataKind.pollDefinition);
    const definitionSignature = await read(dataKind.pollSignature);
    const pollContext = concatenate(manifest.poll, runtime);
    const own = (operation: number, bytes: Uint8Array = new Uint8Array()) => {
        ownRegistrationInput(context, bytes);
        if (kernel.own_registration_command(operation, bytes.length) !== 0)
            throw new Error('The original registration verification refused.');
    };
    own(
        0,
        concatenate(
            pollContext,
            unsigned32(definition.length),
            definition,
            definitionSignature,
            unsigned32(header.length),
            header,
            signature,
        ),
    );
    const publicKey = await read(dataKind.publicKey);
    for (let offset = 0; offset < publicKey.length; offset += chunkBytes)
        own(1, publicKey.subarray(offset, offset + chunkBytes));
    own(2);
    for (const reference of manifest.references)
        if (reference.kind === dataKind.proof)
            own(3, await readDataRecord(database, reference));
    own(4);
    const proofHash = readKernel(
        kernel,
        kernel.own_registration_proof_hash_pointer(),
        64,
    );
    const bodyDigest = readKernel(
        kernel,
        kernel.own_registration_body_digest_pointer(),
        64,
    );
    const usernameBytes = readKernel(
        kernel,
        kernel.own_registration_username_pointer(),
        kernel.own_registration_username_length(),
    );
    const username = new TextDecoder('utf-8', { fatal: true }).decode(
        usernameBytes,
    );
    const pollInput = concatenate(
        pollContext,
        unsigned32(definition.length),
        definition,
        definitionSignature,
        unsigned32(usernameBytes.length),
        usernameBytes,
    );
    sessionInput(context, pollInput);
    if (kernel.validate_join(pollInput.length) !== 0)
        throw new Error('The retained poll definition was refused.');
    const isOrganizer = equalBytes(
        tupleFields(header)[3],
        tupleFields(definition)[3],
    );
    const control = concatenate(
        pollContext,
        unsigned32(header.length),
        header,
        proofHash,
        bodyDigest,
        manifest.dataKeys,
        publicKey,
        await read(dataKind.recipientCapsule),
        await read(dataKind.signingCapsule),
        unsigned16(created ? 0 : unusedPurposes(root.head.generation)),
    );
    let status: number;
    try {
        sessionInput(context, control);
        status = kernel.restore(control.length);
    } finally {
        control.fill(0);
    }
    if (
        status !== 0 ||
        kernel.check_retained() !== 0 ||
        kernel.prepare_creator(0) !== 1 ||
        kernel.prepare_join(0) !== 1 ||
        kernel.restore(0) !== 1 ||
        kernel.check_retained() !== 0
    )
        throw new Error('The original enrollment keys could not be restored.');
    return {
        username,
        isOrganizer,
        bodyDigest,
        proofHash,
        header,
        signature,
        definition,
        definitionSignature,
    };
};
