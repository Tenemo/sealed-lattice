import {
    errorMessage,
    ownRegistrationInput,
    writeModuleInput,
} from '../../module/context.js';
import type { ParticipantContext } from '../../module/context.js';
import {
    custodyIdentities,
    custodyIdentity,
    custodyPurpose,
} from '../../module/custody-identity.js';
import {
    readModuleMemory,
    readParticipantOutput,
} from '../../module/participant-module.js';
import {
    chunkBytes,
    foregroundVisitMilliseconds,
    participantDataKindMaximums,
    tagBytes,
} from '../../module/runtime-bounds.js';
import { purposeBit, signingPurpose } from '../../module/signing-purpose.js';
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
} from '../../shared/bytes.js';
import type { ParticipantRefusalReason } from '../../shared/operation-status.js';
import {
    isEmptyParticipant,
    participantRecordStores,
    participantStores,
} from '../../storage/database.js';
import { validateParticipantPredecessor } from '../../storage/predecessor.js';
import {
    ballotPhase,
    closePhase,
    releasePhase,
    rootGeneration,
    targetPhase,
} from '../../storage/root-generation.js';
import type { AuthenticatedRoot, RecordReference } from '../../storage/root.js';
import {
    authenticateRoot,
    createRootKey,
    dataKind,
    encodeManifest,
    readDataKind,
    requiresFheKeySources,
    rootAssociatedData,
    sealRoot,
} from '../../storage/root.js';
import { commitParticipantState } from '../../storage/state-transaction.js';
import { unusedPreparationPurposes } from '../contribution/preparation-state.js';

// The staged output that carries the three capsule keys, which the root
// retains rather than as a record.
const stagedDataKeys = 14;

// Why an enrollment was refused.
type EnrollmentRefusal = Extract<
    ParticipantRefusalReason,
    'participant exists' | 'invalid request' | 'insufficient storage'
>;

export type EnrollmentRequest = Readonly<
    | {
          role: 'organizer';
          question: string;
          options: readonly string[];
          topCount: number;
          maximumParticipants: number;
          username: string;
      }
    | {
          role: 'joiner';
          poll: Uint8Array;
          definition: Uint8Array;
          definitionSignature: Uint8Array;
          username: string;
      }
>;

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

// The last generation at which each staged purpose's message is retained
// without its completed signature, which a restored credential signs again.
// Only a completed signature consumes a one-shot purpose.
const lastUnsignedGeneration = [
    [signingPurpose.rosterProposal, rootGeneration.rosterLocked],
    [signingPurpose.ballot, ballotPhase.body],
    [signingPurpose.closeIntent, closePhase.intent],
    [signingPurpose.closeResponse, closePhase.responding],
    [signingPurpose.closeProposal, closePhase.responded],
    [signingPurpose.target, targetPhase.intent],
    [signingPurpose.release, releasePhase.body],
] as const;

// The purposes a restored credential may still sign at the root's
// generation. Preparation has independent authenticated intents, which its
// journal records; the other stages follow the root's generations.
export const unusedSigningPurposes = (
    generation: number,
    preparation: Uint8Array | undefined,
) => {
    let mask = 0;
    for (const [purpose, last] of lastUnsignedGeneration)
        if (generation <= last) mask |= purposeBit(purpose);
    if (generation < rootGeneration.preparation)
        mask |=
            purposeBit(signingPurpose.offer) |
            purposeBit(signingPurpose.selectionProposal) |
            purposeBit(signingPurpose.selectionEndorsement);
    else if (generation === rootGeneration.preparation) {
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
        const { database, limits, module, handlers, runtime } = context;
        if (!(await isEmptyParticipant(database))) return 'participant exists';
        const name = encodeWellFormed(request.username);
        if (
            name === undefined ||
            name.length > limits.registration.maximumUsernameIngressBytes
        )
            return 'invalid request';
        let input: Uint8Array;
        if (request.role === 'organizer') {
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
            if (input.length > module.input_capacity())
                return 'invalid request';
            writeModuleInput(context, input);
            if (module.validate_organizer(input.length) !== 0)
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
            if (input.length > module.input_capacity())
                return 'invalid request';
            writeModuleInput(context, input);
            if (module.validate_joiner(input.length) !== 0)
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
            custodyIdentity(module, custodyPurpose.enrollmentInput, input),
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
                custodyIdentity(module, custodyPurpose.root, intent),
            ),
            runtime: hexadecimal(runtime),
        };
        await commitParticipantState({
            database,
            stores: participantStores,
            timeoutMilliseconds: foregroundVisitMilliseconds,
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
        // The module seals each capsule under its own fresh key and stages
        // the three keys once, for the root rather than as a record.
        const dataKeys = new Uint8Array(96);
        let dataKeysStaged = false;
        const maximums = participantDataKindMaximums(limits);
        const lengths = maximums.map(() => 0);
        const records: StagedRecord[] = [];
        handlers.staged = (kind, offset, bytes) => {
            if (kind === stagedDataKeys) {
                if (
                    dataKeysStaged ||
                    offset !== 0 ||
                    bytes.length !== dataKeys.length
                )
                    throw new Error('Invalid staged enrollment keys.');
                dataKeys.set(bytes);
                bytes.fill(0);
                dataKeysStaged = true;
                return;
            }
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
        handlers.random = (target) => {
            crypto.getRandomValues(target);
            randomBytes += target.length;
        };
        let prepared: number;
        try {
            writeModuleInput(context, input);
            prepared =
                request.role === 'organizer'
                    ? module.prepare_organizer(input.length)
                    : module.prepare_joiner(input.length);
        } finally {
            delete handlers.staged;
            delete handlers.random;
        }
        if (prepared !== 0) throw new Error('Enrollment preparation failed.');
        const poll = readModuleMemory(
            module,
            module.poll_identity_pointer(),
            64,
        );
        if (request.role === 'joiner') {
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
            !dataKeysStaged ||
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
            module.prepare_organizer(0) !== 1 ||
            module.prepare_joiner(0) !== 1 ||
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
                    module,
                    custodyPurpose.record,
                    record.bytes,
                ),
            });
        const plaintext = encodeManifest(
            { dataKeys, poll, references, suffixes: {} },
            1,
        );
        dataKeys.fill(0);
        if (
            plaintext.length + tagBytes >
            limits.root.maximumEnrollmentRootBytes
        )
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
                custodyIdentity(module, custodyPurpose.root, sealed),
            ),
            runtime: hexadecimal(runtime),
        };
        await commitParticipantState({
            database,
            stores: participantStores,
            timeoutMilliseconds: foregroundVisitMilliseconds,
            validate: (reader) =>
                validateParticipantPredecessor(reader, {
                    head: intentHead,
                    manifest: intentPlaintext,
                    rootContext: associatedData,
                    maximumRootBytes: limits.root.maximumEnrollmentRootBytes,
                    recordStores: participantRecordStores,
                    records: [],
                    identities: custodyIdentities(module),
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
                        errorMessage(error),
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
    registrationBodyDigest: Uint8Array;
    header: Uint8Array;
    signature: Uint8Array;
    definition: Uint8Array;
    definitionSignature: Uint8Array;
}>;

// The credential keys the module's verification of the participant's own
// registration, so that later operations restore it instead of reading and
// verifying its signature again.
export const retainRegistration = (context: ParticipantContext) => {
    const { module } = context;
    if (module.retain_registration() !== 0)
        throw new Error('The credential refused the verified registration.');
    return readParticipantOutput(module);
};

// The result length, question and options the module writes for the poll it
// verified the participant's own registration against.
const readVerifiedPoll = (context: ParticipantContext): VerifiedPoll => {
    const { module } = context;
    if (module.own_registration_poll() !== 0)
        throw new Error('The module verified no poll.');
    const bytes = readParticipantOutput(module);
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

// The steps of the verification of the participant's own registration; its
// retained step takes an earlier visit's retained copy.
const ownRegistrationStep = {
    begin: 0,
    key: 1,
    keyFinish: 2,
    finish: 4,
    retained: 5,
} as const;

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
    const { module, runtime } = context;
    const manifest = root.manifest;
    const read = (kind: number) => readDataKind(context, manifest, kind);
    const header = await read(dataKind.header);
    const signature = await read(dataKind.signature);
    const definition = await read(dataKind.pollDefinition);
    const definitionSignature = await read(dataKind.pollSignature);
    const pollContext = concatenate(manifest.poll, runtime);
    const own = (step: number, bytes: Uint8Array = new Uint8Array()) => {
        ownRegistrationInput(context, bytes);
        if (module.own_registration_command(step, bytes.length) !== 0)
            throw new Error('The original registration verification refused.');
    };
    own(
        ownRegistrationStep.begin,
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
        own(
            ownRegistrationStep.key,
            publicKey.subarray(offset, offset + chunkBytes),
        );
    own(ownRegistrationStep.keyFinish);
    let registrationBodyDigest: Uint8Array;
    // From the roster transition on, the root retains the module's
    // verification of the participant's own registration, keyed to its
    // credential.
    if (root.head.generation >= rootGeneration.rosterLocked) {
        // The module checks the copy's tag once the capsules open the
        // credential it is keyed to.
        const retained = await read(dataKind.retainedRegistration);
        own(ownRegistrationStep.retained, retained);
        registrationBodyDigest = retained.slice(0, 64);
    } else {
        own(ownRegistrationStep.finish);
        registrationBodyDigest = readModuleMemory(
            module,
            module.own_registration_body_digest_pointer(),
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
        registrationBodyDigest,
        manifest.dataKeys,
        publicKey,
        await read(dataKind.recipientCapsule),
        await read(dataKind.signingCapsule),
        ...(sourcesRequired
            ? [sourceState]
            : [unsigned32(sourceState.length), sourceState]),
        unsigned16(
            created
                ? 0
                : unusedSigningPurposes(
                      root.head.generation,
                      root.manifest.suffixes.preparation,
                  ),
        ),
    );
    let status: number;
    try {
        writeModuleInput(context, control);
        status = sourcesRequired
            ? module.restore(control.length)
            : module.restore_prepared(control.length);
    } finally {
        control.fill(0);
    }
    if (
        status !== 0 ||
        module.prepare_organizer(0) !== 1 ||
        module.prepare_joiner(0) !== 1 ||
        module.restore(0) !== 1 ||
        module.restore_prepared(0) !== 1
    )
        throw new Error('The original enrollment keys could not be restored.');
    const poll = readVerifiedPoll(context);
    const usernameBytes = readModuleMemory(
        module,
        module.own_registration_username_pointer(),
        module.own_registration_username_length(),
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
    writeModuleInput(context, pollInput);
    if (module.validate_joiner(pollInput.length) !== 0)
        throw new Error('The retained poll definition was refused.');
    const isOrganizer = equalBytes(
        tupleFields(header)[3],
        tupleFields(definition)[3],
    );
    return {
        username,
        isOrganizer,
        poll,
        registrationBodyDigest,
        header,
        signature,
        definition,
        definitionSignature,
    };
};
