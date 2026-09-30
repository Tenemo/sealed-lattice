import { readParticipantProfile } from './bounds.js';
import type { ParticipantLimits } from './bounds.js';
import {
    concatenate,
    equalBytes,
    hexadecimal,
    readUnsigned32,
    tupleFields,
    unsigned16,
    unsigned32,
} from './bytes.js';
import { InvalidRequest, PublicInputFailure, sessionInput } from './context.js';
import type { ParticipantContext, ProfileContext } from './context.js';
import { retainRegistration } from './enrollment.js';
import type { RestoredEnrollment } from './enrollment.js';
import { readKernel } from './kernel.js';
import type { ParticipantKernel } from './kernel.js';
import { readPublic, streamPublic } from './public.js';
import type { PublicRelay } from './public.js';
import {
    addedReferences,
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
    rootBound,
} from './root.js';
import type { AuthenticatedRoot } from './root.js';

// Registration record files as each participant publishes them, named by the
// registration body digest.
export const registrationFile = {
    publicKey: 'polynomial-01.bin',
    proof: 'proof.bin',
    header: 'registration-header.bin',
    signature: 'signature.bin',
} as const;

export const registrationPath = (
    bodyDigest: string,
    file: (typeof registrationFile)[keyof typeof registrationFile],
) => 'registration/' + bodyDigest + '/' + file;

// The ordered registration body digests a proposal lists: the fourth tuple
// value holds its own length, the count and one digest per participant.
export const proposalRecordIds = (body: Uint8Array): string[] => {
    const fields = tupleFields(body);
    const bodies = fields[3];
    if (
        fields.length !== 4 ||
        bodies.length < 8 ||
        readUnsigned32(bodies, 0) !== bodies.length - 4
    )
        throw new Error('Malformed roster proposal.');
    const count = readUnsigned32(bodies, 4);
    if (bodies.length !== 8 + 64 * count)
        throw new Error('Malformed roster proposal records.');
    return Array.from({ length: count }, (_unused, index) =>
        hexadecimal(bodies.subarray(8 + 64 * index, 8 + 64 * (index + 1))),
    );
};

// The steps of one registration record in a roster verifier. A record
// begins with its position, header and signature.
const recordStep = {
    begin: 0,
    key: 1,
    keyFinish: 2,
    proof: 3,
    finish: 4,
} as const;

// Streams the proposed registration records into a roster verifier, as many
// at once as it keeps open, so that their verifications run side by side on
// the module's helpers. A verifier that restores a retained roster takes
// each record's header and key alone. The first refused step stops every
// record and is thrown once every started record has stopped.
export const streamRegistrations = async (
    relay: PublicRelay,
    recordIds: readonly string[],
    registration: ParticipantLimits['registration'],
    openRecords: number,
    step: (operation: number, position: number, bytes: Uint8Array) => boolean,
    restoring = false,
) => {
    let failure: { error: unknown } | undefined;
    const run = (
        operation: number,
        position: number,
        bytes: Uint8Array,
        refusal: string,
    ) => {
        if (failure !== undefined) throw failure.error;
        if (!step(operation, position, bytes))
            throw new PublicInputFailure(refusal);
    };
    const record = async (position: number) => {
        const id = recordIds[position];
        const header = await readPublic(
            relay,
            registrationPath(id, registrationFile.header),
            registration.maximumHeaderBytes,
        );
        const signature = restoring
            ? new Uint8Array()
            : await readPublic(
                  relay,
                  registrationPath(id, registrationFile.signature),
                  registration.signatureBytes,
              );
        run(
            recordStep.begin,
            position,
            concatenate(
                unsigned16(position),
                unsigned32(header.length),
                header,
                signature,
            ),
            'A registration header was refused.',
        );
        await streamPublic(
            relay,
            registrationPath(id, registrationFile.publicKey),
            registration.publicKeyBytes,
            (bytes) => {
                run(
                    recordStep.key,
                    position,
                    bytes,
                    'A registration key was refused.',
                );
            },
        );
        run(
            recordStep.keyFinish,
            position,
            new Uint8Array(),
            'A registration key is incomplete.',
        );
        if (!restoring)
            await streamPublic(
                relay,
                registrationPath(id, registrationFile.proof),
                registration.maximumProofBytes,
                (bytes) => {
                    run(
                        recordStep.proof,
                        position,
                        bytes,
                        'A registration proof was refused.',
                    );
                },
            );
        run(
            recordStep.finish,
            position,
            new Uint8Array(),
            'A registration record was refused.',
        );
    };
    let next = 0;
    const stream = async () => {
        while (failure === undefined && next < recordIds.length) {
            const position = next;
            next += 1;
            try {
                await record(position);
            } catch (error) {
                failure ??= { error };
            }
        }
    };
    await Promise.all(
        Array.from(
            { length: Math.min(Math.max(openRecords, 1), recordIds.length) },
            stream,
        ),
    );
    if (failure !== undefined) throw failure.error;
};

// The module decides whether it supports a roster of this size; a request
// outside every supported size is refused before it reaches the module.
const validRecordIds = (ids: readonly string[], limits: ParticipantLimits) =>
    ids.length >= limits.participants.minimum &&
    ids.length <= limits.participants.maximum &&
    new Set(ids).size === ids.length &&
    ids.every((id) => /^[0-9a-f]{128}$/u.test(id));

export type VerifiedProposal = Readonly<{
    body: Uint8Array;
    identity: Uint8Array;
    recordIds: readonly string[];
    // The verified registrations' usernames in roster order.
    usernames: readonly string[];
    position: number;
}>;

// The usernames of the proposal the module's roster verifier built, in
// roster order.
export const verifiedRosterUsernames = (kernel: ParticipantKernel) => {
    if (kernel.roster_usernames() !== 0)
        throw new Error('The roster verifier holds no proposal.');
    const bytes = readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const usernames: string[] = [];
    for (let offset = 0; offset < bytes.length;) {
        const start = offset + 4;
        const end = start + readUnsigned32(bytes, offset);
        if (end > bytes.length)
            throw new Error('The roster usernames are truncated.');
        usernames.push(decoder.decode(bytes.subarray(start, end)));
        offset = end;
    }
    return usernames;
};

// A roster verifier's begin input: the retained poll, its definition and
// signature, and the record count.
export const rosterBegin = (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    definition: Uint8Array,
    definitionSignature: Uint8Array,
    count: number,
) =>
    concatenate(
        root.manifest.poll,
        context.runtime,
        unsigned16(count),
        unsigned32(definition.length),
        definition,
        definitionSignature,
    );

// Streams the records into the module's roster verifier, which the caller
// began. The verified proposal stays live in the module; its body must list
// exactly the requested records and include this participant.
const finishProposal = async (
    context: ParticipantContext,
    relay: PublicRelay,
    enrollment: RestoredEnrollment,
    recordIds: readonly string[],
    restoring: boolean,
): Promise<VerifiedProposal> => {
    const { kernel, limits } = context;
    await streamRegistrations(
        relay,
        recordIds,
        limits.registration,
        kernel.roster_open_records(),
        (operation, position, bytes) => {
            sessionInput(context, bytes);
            return (
                kernel.roster_record(operation, position, bytes.length) === 0
            );
        },
        restoring,
    );
    if (kernel.roster_finish() !== 1)
        throw new PublicInputFailure(
            restoring
                ? 'The published registrations are not the retained roster.'
                : 'The roster proposal was refused.',
        );
    const body = readKernel(
        kernel,
        kernel.roster_body_pointer(),
        kernel.roster_body_length(),
    );
    if (proposalRecordIds(body).join(',') !== recordIds.join(','))
        throw new PublicInputFailure('The proposal lists other records.');
    const position = recordIds.indexOf(hexadecimal(enrollment.bodyDigest));
    if (position < 0)
        throw new PublicInputFailure('The proposal omits this participant.');
    const usernames = verifiedRosterUsernames(kernel);
    if (usernames.length !== recordIds.length)
        throw new Error('The roster verifier named another roster.');
    return {
        body,
        identity: readKernel(kernel, kernel.roster_identity_pointer(), 64),
        recordIds,
        usernames,
        position,
    };
};

// Verifies every proposed registration record in the module's roster
// verifier.
const verifyProposalInputs = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    recordIds: readonly string[],
): Promise<VerifiedProposal> => {
    // The module verified the poll with the participant's own registration,
    // and the poll's signed maximum bounds the roster.
    if (
        !validRecordIds(recordIds, context.limits) ||
        recordIds.length >
            context.kernel.own_registration_maximum_participants()
    )
        throw new InvalidRequest('The proposed records are invalid.');
    const begin = rosterBegin(
        context,
        root,
        enrollment.definition,
        enrollment.definitionSignature,
        recordIds.length,
    );
    sessionInput(context, begin);
    if (context.kernel.roster_begin(begin.length) !== 0)
        throw new PublicInputFailure('The proposed poll was refused.');
    return finishProposal(context, relay, enrollment, recordIds, false);
};

// The credential keys the roster the module verified in full, so that later
// visits restore it from the published headers and keys alone.
const retainRoster = (context: ParticipantContext) => {
    const { kernel } = context;
    if (kernel.retain_roster() !== 0)
        throw new Error('The credential refused the verified roster.');
    return readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
};

const verifySignature = (
    context: ParticipantContext,
    signature: Uint8Array,
) => {
    sessionInput(context, signature);
    return context.kernel.verify_roster_signature(signature.length) === 1;
};

// A roster this participant verified and retained, with its verified
// usernames in roster order.
export type RetainedRoster = Readonly<{
    root: AuthenticatedRoot;
    usernames: readonly string[];
}>;

// The organizer locks the verified proposal and its signing coins before the
// signature exists, then signs. A restored intent signs the same proposal
// with the retained coins after verifying its records again.
export const proposeRoster = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    recordIds: readonly string[],
): Promise<RetainedRoster | undefined> => {
    if (!enrollment.isOrganizer || root.head.generation !== 1) return undefined;
    const proposal = await verifyProposalInputs(
        context,
        relay,
        root,
        enrollment,
        recordIds,
    );
    if (context.kernel.validate_roster_signer() !== 0) return undefined;
    const added = [
        { kind: dataKind.proposal, bytes: proposal.body },
        { kind: dataKind.retainedRoster, bytes: retainRoster(context) },
        {
            kind: dataKind.retainedRegistration,
            bytes: retainRegistration(context),
        },
    ];
    const proposalCoins = crypto.getRandomValues(new Uint8Array(32));
    const locked = await commitRoot(context, root, {
        generation: 2,
        manifest: {
            ...root.manifest,
            references: addedReferences(
                context,
                root.manifest.references,
                added,
            ),
            proposalCoins,
        },
        predecessorRecords: dataRecordInventory(root.manifest),
        addedData: added,
    });
    return {
        root: await signRoster(context, locked, proposal),
        usernames: proposal.usernames,
    };
};

export const signRoster = async (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    proposal: VerifiedProposal,
): Promise<AuthenticatedRoot> => {
    const coins = root.manifest.proposalCoins;
    if (root.head.generation !== 2 || coins === undefined)
        throw new Error('No locked roster proposal exists.');
    const { kernel, limits } = context;
    const signing = concatenate(proposal.identity, coins);
    let signed: number;
    try {
        sessionInput(context, signing);
        signed = kernel.sign_roster_proposal(signing.length);
    } finally {
        signing.fill(0);
    }
    if (signed !== 0)
        throw new Error('The original credential refused the locked proposal.');
    const signature = readKernel(
        kernel,
        kernel.roster_signature_pointer(),
        limits.registration.signatureBytes,
    );
    if (!verifySignature(context, signature))
        throw new Error('The proposal signature did not verify.');
    const { proposalCoins: _retired, ...manifest } = root.manifest;
    return commitRoot(context, root, {
        generation: 3,
        manifest: {
            ...manifest,
            references: addedReferences(context, manifest.references, [
                { kind: dataKind.proposalSignature, bytes: signature },
            ]),
        },
        predecessorRecords: dataRecordInventory(root.manifest),
        addedData: [{ kind: dataKind.proposalSignature, bytes: signature }],
    });
};

// Another participant accepts only a proposal whose records it verified and
// whose organizer signature verifies over them.
export const acceptRoster = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    recordIds: readonly string[],
): Promise<RetainedRoster | undefined> => {
    if (enrollment.isOrganizer || root.head.generation !== 1) return undefined;
    const proposal = await verifyProposalInputs(
        context,
        relay,
        root,
        enrollment,
        recordIds,
    );
    const signature = await readPublic(
        relay,
        'proposal-signature.bin',
        context.limits.registration.signatureBytes,
    );
    if (!verifySignature(context, signature))
        throw new PublicInputFailure(
            'The organizer proposal signature failed.',
        );
    const added = [
        { kind: dataKind.proposal, bytes: proposal.body },
        { kind: dataKind.proposalSignature, bytes: signature },
        { kind: dataKind.retainedRoster, bytes: retainRoster(context) },
        {
            kind: dataKind.retainedRegistration,
            bytes: retainRegistration(context),
        },
    ];
    return {
        root: await commitRoot(context, root, {
            generation: 3,
            manifest: {
                ...root.manifest,
                references: addedReferences(
                    context,
                    root.manifest.references,
                    added,
                ),
            },
            predecessorRecords: dataRecordInventory(root.manifest),
            addedData: added,
        }),
        usernames: proposal.usernames,
    };
};

// Restores this participant's roster verification from the retained roster
// and the published headers and keys, so that the module holds the live
// signed proposal that contribution generation needs.
export const reverifyRoster = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
): Promise<VerifiedProposal> => {
    const stored = await readDataKind(
        context,
        root.manifest,
        dataKind.proposal,
    );
    const recordIds = proposalRecordIds(stored);
    const begin = rosterBegin(
        context,
        root,
        enrollment.definition,
        enrollment.definitionSignature,
        recordIds.length,
    );
    const input = concatenate(
        begin,
        await readDataKind(context, root.manifest, dataKind.retainedRoster),
    );
    sessionInput(context, input);
    if (context.kernel.roster_begin_retained(begin.length, input.length) !== 0)
        throw new Error('The credential refused the retained roster.');
    const proposal = await finishProposal(
        context,
        relay,
        enrollment,
        recordIds,
        true,
    );
    if (!equalBytes(proposal.body, stored))
        throw new Error('The retained proposal differs from its records.');
    if (root.head.generation >= 3) {
        const signature = await readDataKind(
            context,
            root.manifest,
            dataKind.proposalSignature,
        );
        if (!verifySignature(context, signature))
            throw new Error('The retained proposal signature failed.');
    }
    return proposal;
};

// The profile the retained roster names: its participant count from the
// retained proposal and its option count from the poll the module verified.
// The retained root, proposal, retained roster, setup reference and setup
// inventory must meet its bounds. The participant's position is its
// registration's in the retained proposal.
export const retainedProfile = async (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
): Promise<ProfileContext> => {
    const proposal = await readDataKind(
        context,
        root.manifest,
        dataKind.proposal,
    );
    const profile = readParticipantProfile(
        context.kernel,
        context.limits,
        proposalRecordIds(proposal).length,
        context.kernel.own_registration_option_count(),
    );
    const retainedLength = (kind: number) =>
        root.manifest.references
            .filter((reference) => reference.kind === kind)
            .reduce((total, reference) => total + reference.length, 0);
    const setupReference = retainedLength(dataKind.setupReference);
    const setupInventory = retainedLength(dataKind.setupInventory);
    if (
        profile === undefined ||
        proposal.length !== profile.proposalBytes ||
        retainedLength(dataKind.retainedRoster) !==
            profile.root.retainedRosterBytes ||
        root.plaintext.length + 16 >
            rootBound({ ...context, profile }, root.head.generation) ||
        (setupReference !== 0 &&
            setupReference !== profile.root.setupReferenceBytes) ||
        (setupInventory !== 0 &&
            setupInventory !== profile.root.setupInventoryBytes)
    )
        throw new Error(
            'The retained roster does not name a supported profile.',
        );
    const position = proposalRecordIds(proposal).indexOf(
        hexadecimal(enrollment.bodyDigest),
    );
    if (position < 0)
        throw new Error('The retained roster omits this participant.');
    return { ...context, profile, position };
};

export const parseRecordIds = (value: unknown): string[] => {
    if (
        !Array.isArray(value) ||
        !value.every(
            (id) => typeof id === 'string' && /^[0-9a-f]{128}$/u.test(id),
        )
    )
        throw new InvalidRequest('Malformed proposed record identifiers.');
    return value as string[];
};
