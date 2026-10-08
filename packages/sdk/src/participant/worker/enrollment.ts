import { participantDataKindMaximums } from './bounds.js';
import {
    concatenate,
    encodeText,
    equalBytes,
    hexadecimal,
    readUnsigned16,
    readUnsigned32,
    tupleFields,
    unsigned16,
    unsigned32,
} from './bytes.js';
import { describe, ownRegistrationInput, sessionInput } from './context.js';
import type { ParticipantContext } from './context.js';
import {
    custodyIdentities,
    custodyIdentity,
    custodyPurpose,
} from './identity.js';
import { readKernel } from './kernel.js';
import type { ParticipantRefusalReason } from './outcome.js';
import { validateParticipantPredecessor } from './predecessor.js';
import { unusedPreparationPurposes } from './preparation-state.js';
import { rootGeneration } from './root-generation.js';
import {
    authenticateRoot,
    chunkBytes,
    createRootKey,
    dataKind,
    encodeManifest,
    readDataKind,
    requiresFheKeySources,
    rootAssociatedData,
    sealRoot,
} from './root.js';
import type { AuthenticatedRoot, RecordReference } from './root.js';
import { commitParticipantState } from './state-transaction.js';
import {
    isEmptyParticipant,
    participantRecordStores,
    participantStores,
} from './storage.js';

// Why an enrollment was refused.
type EnrollmentRefusal = Extract<
    ParticipantRefusalReason,
    'participant exists' | 'invalid request' | 'insufficient storage'
>;

export type EnrollmentRequest = Readonly<
    | {
          role: 'creator';
          question: string;
          options: readonly string[];
          topCount: number;
          maximumParticipants: number;
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
// the text that the poll or the credential binds.
const encodeWellFormed = (value: string) => {
    for (let index = 0; index < value.length; index++) {
        const unit = value.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) return undefined;
            index++;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) return undefined;
    }
    return encodeText(value);
};

// Only a completed signature consumes its one-shot purpose. Preparation
// has independent authenticated intents; later stages use global generations.
const unusedPurposes = (root: AuthenticatedRoot) => {
    const generation = root.head.generation;
    const lastUnused = [2, 0, 0, 0, 15, 18, 20, 21, 23, 27];
    let mask = lastUnused.reduce(
        (value, last, purpose) =>
            generation <= last ? value | (1 << purpose) : value,
        0,
    );
    if (generation < 4) mask |= 0b1110;
    else if (generation === 4) {
        const preparation = root.manifest.suffixes.preparation;
        if (preparation === undefined)
            throw new Error('Missing preparation journal.');
        mask |= unusedPreparationPurposes(preparation);
    }
    return mask;
};

type StagedRecord = { kind: number; offset: number; bytes: Uint8Array };

// Creates the original credential and recipient key for an empty namespace.
// The intent commits before any private generation, and the completed root,
// head and every record commit together; interruption between them stops
// the participant, so the caller learns when the intent exists. A refusal
// leaves the namespace unchanged and says why.
export const createEnrollment = async (
    context: ParticipantContext,
    request: EnrollmentRequest,
    onIntent: () => void,
): Promise<AuthenticatedRoot | EnrollmentRefusal> => {
    let enrollmentIncomplete = false;
    try {
        const { database, limits, kernel, handlers, runtime } = context;
        if (!(await isEmptyParticipant(database))) return 'participant exists';
        const name = encodeWellFormed(request.username);
        if (
            name === undefined ||
            name.length > limits.registration.maximumUsernameIngressBytes
        )
            return 'invalid request';
        let input: Uint8Array;
        if (request.role === 'creator') {
            const question = encodeWellFormed(request.question);
            if (
                question === undefined ||
                request.options.length > limits.options.maximum ||
                [request.topCount, request.maximumParticipants].some(
                    (value) =>
                        !Number.isSafeInteger(value) ||
                        value < 1 ||
                        value > 0xffff,
                )
            )
                return 'invalid request';
            // The module frames the question and labels as the poll's manifest.
            const labels: Uint8Array[] = [];
            for (const option of request.options) {
                const label = encodeWellFormed(option);
                if (label === undefined) return 'invalid request';
                labels.push(unsigned32(label.length), label);
            }
            input = concatenate(
                runtime,
                unsigned16(request.topCount),
                unsigned16(request.maximumParticipants),
                unsigned32(question.length),
                question,
                unsigned16(request.options.length),
                ...labels,
                unsigned32(name.length),
                name,
            );
            if (input.length + 96 > kernel.input_capacity())
                return 'invalid request';
            sessionInput(context, input);
            if (kernel.validate_creator(input.length) !== 0)
                return 'invalid request';
        } else {
            if (
                request.poll.length !== 64 ||
                request.definitionSignature.length !==
                    limits.registration.signatureBytes
            )
                return 'invalid request';
            input = concatenate(
                request.poll,
                runtime,
                unsigned32(request.definition.length),
                request.definition,
                request.definitionSignature,
                unsigned32(name.length),
                name,
            );
            if (input.length + 96 > kernel.input_capacity())
                return 'invalid request';
            sessionInput(context, input);
            if (kernel.validate_join(input.length) !== 0)
                return 'invalid request';
        }
        const estimate = await navigator.storage.estimate();
        if (
            estimate.quota === undefined ||
            estimate.usage === undefined ||
            estimate.quota - estimate.usage <
                2 * limits.registration.publicKeyBytes
        )
            return 'insufficient storage';
        const associatedData = rootAssociatedData(runtime);
        const key = await createRootKey();
        const intentPlaintext = concatenate(
            encodeText('INI2'),
            custodyIdentity(kernel, custodyPurpose.enrollmentInput, input),
        );
        const intent = await sealRoot(
            key,
            rootGeneration.enrollmentIntent,
            associatedData,
            intentPlaintext,
        );
        const intentHead = {
            generation: rootGeneration.enrollmentIntent,
            hash: hexadecimal(
                custodyIdentity(kernel, custodyPurpose.root, intent),
            ),
            runtime: hexadecimal(runtime),
        };
        await commitParticipantState({
            database,
            stores: participantStores,
            timeoutMilliseconds: validationMilliseconds,
            validate: async (reader) => {
                for (const store of participantStores)
                    if ((await reader.count(store)) !== 0)
                        throw new Error(
                            'The participant namespace is not empty.',
                        );
            },
            write: (transaction) => {
                transaction.objectStore('key').add(key, 0);
                transaction.objectStore('root').add(intent, 0);
                transaction.objectStore('head').add(intentHead, 0);
            },
        });
        enrollmentIncomplete = true;
        onIntent();
        // Each capsule uses its own one-use data key.
        const dataKeys = crypto.getRandomValues(new Uint8Array(96));
        if (
            equalBytes(dataKeys.subarray(0, 32), dataKeys.subarray(32, 64)) ||
            equalBytes(dataKeys.subarray(0, 32), dataKeys.subarray(64)) ||
            equalBytes(dataKeys.subarray(32, 64), dataKeys.subarray(64))
        )
            throw new Error('Repeated enrollment data keys.');
        const maximums = participantDataKindMaximums(limits);
        const lengths = maximums.map(() => 0);
        const records: StagedRecord[] = [];
        handlers.staged = (kind, offset, bytes) => {
            if (
                (kind > dataKind.pollSignature &&
                    kind !== dataKind.sourceCapsule) ||
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
            lengths[dataKind.pollSignature] =
                request.definitionSignature.length;
        }
        const registration = limits.registration;
        if (
            lengths[dataKind.publicKey] !== registration.publicKeyBytes ||
            lengths[dataKind.header] === 0 ||
            lengths[dataKind.signature] !== registration.signatureBytes ||
            lengths[dataKind.recipientCapsule] !==
                registration.recipientCapsuleBytes ||
            lengths[dataKind.signingCapsule] !==
                registration.signingCapsuleBytes ||
            lengths[dataKind.sourceCapsule] === 0 ||
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
                hash: custodyIdentity(
                    kernel,
                    custodyPurpose.record,
                    record.bytes,
                ),
            });
        const plaintext = encodeManifest(
            { dataKeys, poll, references, suffixes: {} },
            1,
        );
        dataKeys.fill(0);
        if (plaintext.length + 16 > limits.root.maximumEnrollmentRootBytes)
            throw new Error('The enrollment root exceeds its bound.');
        // The initial key seals the intent and the completed root under their
        // distinct generation nonces.
        const sealed = await sealRoot(
            key,
            rootGeneration.registered,
            associatedData,
            plaintext,
        );
        plaintext.fill(0);
        const head = {
            generation: rootGeneration.registered,
            hash: hexadecimal(
                custodyIdentity(kernel, custodyPurpose.root, sealed),
            ),
            runtime: hexadecimal(runtime),
        };
        await commitParticipantState({
            database,
            stores: participantStores,
            timeoutMilliseconds: validationMilliseconds,
            validate: (reader) =>
                validateParticipantPredecessor(reader, {
                    head: intentHead,
                    manifest: intentPlaintext,
                    rootContext: associatedData,
                    maximumRootBytes: limits.root.maximumEnrollmentRootBytes,
                    recordStores: participantRecordStores,
                    records: [],
                    identities: custodyIdentities(kernel),
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
        enrollmentIncomplete = false;
        for (const record of records) record.bytes.fill(0);
        const root = await authenticateRoot(context);
        if (
            root.head.generation !== rootGeneration.registered ||
            root.head.hash !== head.hash
        )
            throw new Error('Enrollment readback failed.');
        return root;
    } catch (error) {
        // The committed intent cannot recreate the unpublished credential or
        // its randomness. Even a module or resource failure loses required
        // state in this interval; a completed enrollment remains resumable.
        if (enrollmentIncomplete)
            throw Object.assign(
                new Error(
                    'Enrollment stopped before its required secrets were retained: ' +
                        describe(error),
                ),
                { cause: error },
            );
        throw error;
    }
};

// The poll the module verified the participant's own registration against.
type VerifiedPoll = Readonly<{
    question: string;
    options: readonly Readonly<{ identifier: string; label: string }>[];
    topCount: number;
}>;

export type RestoredEnrollment = Readonly<{
    username: string;
    isOrganizer: boolean;
    poll: VerifiedPoll;
    bodyDigest: Uint8Array;
    header: Uint8Array;
    signature: Uint8Array;
    definition: Uint8Array;
    definitionSignature: Uint8Array;
}>;

// The credential keys the module's verification of the participant's own
// registration, so that later visits restore it instead of reading and
// verifying its signature again.
export const retainRegistration = (context: ParticipantContext) => {
    const { kernel } = context;
    if (kernel.retain_registration() !== 0)
        throw new Error('The credential refused the verified registration.');
    return readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
};

// The result length, question and options the module writes for the poll it
// verified the participant's own registration against.
const readVerifiedPoll = (context: ParticipantContext): VerifiedPoll => {
    const { kernel } = context;
    if (kernel.own_registration_poll() !== 0)
        throw new Error('The module verified no poll.');
    const bytes = readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let offset = 0;
    const take = (length: number) => {
        if (length > bytes.length - offset)
            throw new Error('The verified poll is truncated.');
        offset += length;
        return bytes.subarray(offset - length, offset);
    };
    const text = () => decoder.decode(take(readUnsigned32(take(4), 0)));
    const topCount = readUnsigned16(take(2), 0);
    const question = text();
    const options = Array.from({ length: readUnsigned16(take(2), 0) }, () => {
        const identifier = text();
        return { identifier, label: text() };
    });
    if (offset !== bytes.length)
        throw new Error('The verified poll has trailing bytes.');
    return { question, options, topCount };
};

// Verifies the retained registration through the module's own registration
// verifier, or restores that verification from its retained copy in place of
// the record, restores the original keys and checks the retained poll
// definition. The purposes the root shows unused stay available; an instance
// that created the credential in this invocation keeps its live authority.
export const restoreEnrollment = async (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    created: boolean,
): Promise<RestoredEnrollment> => {
    const { kernel, runtime } = context;
    const manifest = root.manifest;
    const read = (kind: number) => readDataKind(context, manifest, kind);
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
    let bodyDigest: Uint8Array;
    // From the roster transition on, the root retains the module's
    // verification of the participant's own registration, keyed to its
    // credential.
    if (root.head.generation >= rootGeneration.rosterLocked) {
        // The module checks the copy's tag once the capsules open the
        // credential it is keyed to.
        const retained = await read(dataKind.retainedRegistration);
        own(5, retained);
        bodyDigest = retained.slice(0, 64);
    } else {
        own(4);
        bodyDigest = readKernel(
            kernel,
            kernel.own_registration_body_digest_pointer(),
            64,
        );
    }
    const sourcesRequired = requiresFheKeySources(root.head.generation);
    const sourceState = sourcesRequired
        ? await read(dataKind.sourceCapsule)
        : await read(dataKind.setupReference);
    const control = concatenate(
        pollContext,
        unsigned32(header.length),
        header,
        bodyDigest,
        manifest.dataKeys,
        publicKey,
        await read(dataKind.recipientCapsule),
        await read(dataKind.signingCapsule),
        ...(sourcesRequired
            ? [sourceState]
            : [unsigned32(sourceState.length), sourceState]),
        unsigned16(created ? 0 : unusedPurposes(root)),
    );
    let status: number;
    try {
        sessionInput(context, control);
        status = sourcesRequired
            ? kernel.restore(control.length)
            : kernel.restore_prepared(control.length);
    } finally {
        control.fill(0);
    }
    if (
        status !== 0 ||
        kernel.prepare_creator(0) !== 1 ||
        kernel.prepare_join(0) !== 1 ||
        kernel.restore(0) !== 1 ||
        kernel.restore_prepared(0) !== 1
    )
        throw new Error('The original enrollment keys could not be restored.');
    const poll = readVerifiedPoll(context);
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
    return {
        username,
        isOrganizer,
        poll,
        bodyDigest,
        header,
        signature,
        definition,
        definitionSignature,
    };
};
