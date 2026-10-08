import { writeModuleInput } from '../../module/context.js';
import type {
    ParticipantContext,
    ParticipantProfileContext,
    PublicContext,
} from '../../module/context.js';
import {
    readModuleMemory,
    readParticipantOutput,
} from '../../module/participant-module.js';
import type { ParticipantModule } from '../../module/participant-module.js';
import type { ParticipantLimits } from '../../module/runtime-bounds.js';
import {
    readParticipantProfile,
    tagBytes,
} from '../../module/runtime-bounds.js';
import {
    findCandidate,
    readCandidateFile,
    streamCandidateFile,
} from '../../relay/relay.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    equalBytes,
    fromHexadecimal,
    hexadecimal,
    readUnsigned32,
    tupleFields,
    unsigned16,
    unsigned32,
} from '../../shared/bytes.js';
import { InvalidRequest, PublicInputFailure } from '../../shared/failures.js';
import { rootGeneration } from '../../storage/root-generation.js';
import {
    addedReferences,
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
    rootBound,
} from '../../storage/root.js';
import type { AuthenticatedRoot } from '../../storage/root.js';
import type { RestoredEnrollment } from '../enrollment/enrollment.js';
import { retainRegistration } from '../enrollment/enrollment.js';

// Registration record files as each participant publishes them, named by the
// registration body digest.
export const registrationFile = {
    publicKey: 'polynomial-01.bin',
    header: 'registration-header.bin',
    signature: 'signature.bin',
} as const;

export const registrationCandidateKey = (registrationBodyDigest: string) =>
    'registration/' + registrationBodyDigest;

// The ordered registration body digests a proposal lists: the fourth tuple
// value holds its own length, the count and one digest per participant.
export const proposalRegistrationBodyDigests = (body: Uint8Array): string[] => {
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
    finish: 4,
    discard: 5,
} as const;

// Streams the proposed registration records into a roster verifier, as many
// at once as it keeps open, so that their verifications run side by side on
// the module's helpers. A verifier that restores a retained roster takes
// each record's header and key alone. The first refused step stops every
// record and is thrown once every started record has stopped.
export const streamRegistrations = async (
    relay: PublicRelay,
    registrationBodyDigests: readonly string[],
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
        const id = registrationBodyDigests[position];
        await findCandidate(
            relay,
            registrationCandidateKey(id),
            async (candidate) => {
                try {
                    const header = await readCandidateFile(
                        relay,
                        candidate,
                        registrationFile.header,
                        registration.maximumHeaderBytes,
                    );
                    const signature = restoring
                        ? new Uint8Array()
                        : await readCandidateFile(
                              relay,
                              candidate,
                              registrationFile.signature,
                              registration.signatureBytes,
                          );
                    run(
                        recordStep.begin,
                        position,
                        concatenate(
                            unsigned16(position),
                            fromHexadecimal(id),
                            unsigned32(header.length),
                            header,
                            signature,
                        ),
                        'A registration header was refused.',
                    );
                    await streamCandidateFile(
                        relay,
                        candidate,
                        registrationFile.publicKey,
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
                    run(
                        recordStep.finish,
                        position,
                        new Uint8Array(),
                        'A registration record was refused.',
                    );
                } catch (error) {
                    if (
                        error instanceof PublicInputFailure &&
                        !step(recordStep.discard, position, new Uint8Array())
                    )
                        throw Object.assign(
                            new Error(
                                'The roster verifier could not discard tentative input.',
                            ),
                            { cause: error },
                        );
                    throw error;
                }
            },
        );
    };
    let next = 0;
    const stream = async () => {
        while (failure === undefined && next < registrationBodyDigests.length) {
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
            {
                length: Math.min(
                    Math.max(openRecords, 1),
                    registrationBodyDigests.length,
                ),
            },
            stream,
        ),
    );
    if (failure !== undefined) throw failure.error;
};

// The module decides whether it supports a roster of this size; a request
// outside every supported size is refused before it reaches the module.
export const validRegistrationBodyDigests = (
    ids: readonly string[],
    limits: ParticipantLimits,
) =>
    ids.length >= limits.participants.minimum &&
    ids.length <= limits.participants.maximum &&
    new Set(ids).size === ids.length &&
    ids.every((id) => /^[0-9a-f]{128}$/u.test(id));

export type VerifiedProposal = Readonly<{
    body: Uint8Array;
    identity: Uint8Array;
    registrationBodyDigests: readonly string[];
    // The verified registrations' usernames in roster order.
    usernames: readonly string[];
    position: number;
}>;

// The usernames of the proposal the module's roster verifier built, in
// roster order.
export const verifiedRosterUsernames = (module: ParticipantModule) => {
    if (module.roster_usernames() !== 0)
        throw new Error('The roster verifier holds no proposal.');
    const bytes = readParticipantOutput(module);
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

// A roster verifier's begin input: the poll's identity, its definition and
// signature, and the record count.
export const rosterBegin = (
    context: PublicContext,
    poll: Uint8Array,
    definition: Uint8Array,
    definitionSignature: Uint8Array,
    count: number,
) =>
    concatenate(
        poll,
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
    registrationBodyDigests: readonly string[],
    restoring: boolean,
): Promise<VerifiedProposal> => {
    const { module, limits } = context;
    await streamRegistrations(
        relay,
        registrationBodyDigests,
        limits.registration,
        module.roster_open_records(),
        (operation, position, bytes) => {
            writeModuleInput(context, bytes);
            return (
                module.roster_record(operation, position, bytes.length) === 0
            );
        },
        restoring,
    );
    if (module.roster_finish() !== 0)
        throw new PublicInputFailure(
            restoring
                ? 'The published registrations are not the retained roster.'
                : 'The roster proposal was refused.',
        );
    const body = readModuleMemory(
        module,
        module.roster_body_pointer(),
        module.roster_body_length(),
    );
    if (
        proposalRegistrationBodyDigests(body).join(',') !==
        registrationBodyDigests.join(',')
    )
        throw new PublicInputFailure('The proposal lists other records.');
    const position = registrationBodyDigests.indexOf(
        hexadecimal(enrollment.registrationBodyDigest),
    );
    if (position < 0)
        throw new PublicInputFailure('The proposal omits this participant.');
    const usernames = verifiedRosterUsernames(module);
    if (usernames.length !== registrationBodyDigests.length)
        throw new Error('The roster verifier named another roster.');
    return {
        body,
        identity: readModuleMemory(
            module,
            module.roster_identity_pointer(),
            64,
        ),
        registrationBodyDigests,
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
    registrationBodyDigests: readonly string[],
): Promise<VerifiedProposal> => {
    // The module verified the poll with the participant's own registration,
    // and the poll's signed maximum bounds the roster.
    if (
        !validRegistrationBodyDigests(
            registrationBodyDigests,
            context.limits,
        ) ||
        registrationBodyDigests.length >
            context.module.own_registration_maximum_participants()
    )
        throw new InvalidRequest('The proposed records are invalid.');
    const begin = rosterBegin(
        context,
        root.manifest.poll,
        enrollment.definition,
        enrollment.definitionSignature,
        registrationBodyDigests.length,
    );
    writeModuleInput(context, begin);
    if (context.module.roster_begin(begin.length) !== 0)
        throw new PublicInputFailure('The proposed poll was refused.');
    return finishProposal(
        context,
        relay,
        enrollment,
        registrationBodyDigests,
        false,
    );
};

// The credential keys the roster the module verified in full, so that later
// operations restore it from the published headers and keys alone.
const retainRoster = (context: ParticipantContext) => {
    const { module } = context;
    if (module.retain_roster() !== 0)
        throw new Error('The credential refused the verified roster.');
    return readParticipantOutput(module);
};

const verifySignature = (
    context: ParticipantContext,
    signature: Uint8Array,
) => {
    writeModuleInput(context, signature);
    return context.module.verify_roster_signature(signature.length) === 0;
};

// A roster this participant verified and retained, with its verified
// usernames in roster order.
export type RetainedRoster = Readonly<{
    root: AuthenticatedRoot;
    usernames: readonly string[];
}>;

// The organizer locks the verified proposal before the
// signature exists, then signs. A restored intent signs the same proposal
// deterministically after verifying its records again.
export const proposeRoster = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    registrationBodyDigests: readonly string[],
): Promise<RetainedRoster | undefined> => {
    if (
        !enrollment.isOrganizer ||
        root.head.generation !== rootGeneration.registered
    )
        return undefined;
    const proposal = await verifyProposalInputs(
        context,
        relay,
        root,
        enrollment,
        registrationBodyDigests,
    );
    if (context.module.validate_roster_signer() !== 0) return undefined;
    const added = [
        { kind: dataKind.proposal, bytes: proposal.body },
        { kind: dataKind.retainedRoster, bytes: retainRoster(context) },
        {
            kind: dataKind.retainedRegistration,
            bytes: retainRegistration(context),
        },
    ];
    const locked = await commitRoot(context, root, {
        generation: rootGeneration.rosterLocked,
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
    if (root.head.generation !== rootGeneration.rosterLocked)
        throw new Error('No locked roster proposal exists.');
    const { module, limits } = context;
    const signing = proposal.identity.slice();
    let signed: number;
    try {
        writeModuleInput(context, signing);
        signed = module.sign_roster_proposal(signing.length);
    } finally {
        signing.fill(0);
    }
    if (signed !== 0)
        throw new Error('The original credential refused the locked proposal.');
    const signature = readModuleMemory(
        module,
        module.roster_signature_pointer(),
        limits.registration.signatureBytes,
    );
    if (!verifySignature(context, signature))
        throw new Error('The proposal signature did not verify.');
    const manifest = root.manifest;
    return commitRoot(context, root, {
        generation: rootGeneration.rosterSigned,
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
    registrationBodyDigests: readonly string[],
): Promise<RetainedRoster | undefined> => {
    if (
        enrollment.isOrganizer ||
        root.head.generation !== rootGeneration.registered
    )
        return undefined;
    const proposal = await verifyProposalInputs(
        context,
        relay,
        root,
        enrollment,
        registrationBodyDigests,
    );
    const signature = await findCandidate(
        relay,
        'roster',
        async (candidate) => {
            const body = await readCandidateFile(
                relay,
                candidate,
                'proposal.bin',
                context.limits.registration.maximumProposalBytes,
            );
            const publishedSignature = await readCandidateFile(
                relay,
                candidate,
                'signature.bin',
                context.limits.registration.signatureBytes,
            );
            if (
                !equalBytes(body, proposal.body) ||
                !verifySignature(context, publishedSignature)
            )
                throw new PublicInputFailure(
                    'The organizer proposal signature failed.',
                );
            return publishedSignature;
        },
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
            generation: rootGeneration.rosterSigned,
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
    const registrationBodyDigests = proposalRegistrationBodyDigests(stored);
    const begin = rosterBegin(
        context,
        root.manifest.poll,
        enrollment.definition,
        enrollment.definitionSignature,
        registrationBodyDigests.length,
    );
    const input = concatenate(
        begin,
        await readDataKind(context, root.manifest, dataKind.retainedRoster),
    );
    writeModuleInput(context, input);
    if (context.module.roster_begin_retained(begin.length, input.length) !== 0)
        throw new Error('The credential refused the retained roster.');
    const proposal = await finishProposal(
        context,
        relay,
        enrollment,
        registrationBodyDigests,
        true,
    );
    if (!equalBytes(proposal.body, stored))
        throw new Error('The retained proposal differs from its records.');
    if (root.head.generation >= rootGeneration.rosterSigned) {
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
// certificate must meet its bounds. The participant's position is its
// registration's in the retained proposal.
export const retainedProfile = async (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
): Promise<ParticipantProfileContext> => {
    const proposal = await readDataKind(
        context,
        root.manifest,
        dataKind.proposal,
    );
    const profile = readParticipantProfile(
        context.module,
        context.limits,
        proposalRegistrationBodyDigests(proposal).length,
        context.module.own_registration_option_count(),
    );
    const retainedLength = (kind: number) =>
        root.manifest.references
            .filter((reference) => reference.kind === kind)
            .reduce((total, reference) => total + reference.length, 0);
    const setupReference = retainedLength(dataKind.setupReference);
    const setupCertificate = retainedLength(dataKind.setupCertificate);
    if (
        profile === undefined ||
        proposal.length !== profile.proposalBytes ||
        retainedLength(dataKind.retainedRoster) !==
            profile.root.retainedRosterBytes ||
        root.plaintext.length + tagBytes >
            rootBound({ ...context, profile }, root.head.generation) ||
        (setupReference !== 0 &&
            setupReference !== profile.root.setupReferenceBytes) ||
        (setupCertificate !== 0 &&
            setupCertificate !== profile.root.setupCertificateBytes)
    )
        throw new Error(
            'The retained roster does not name a supported profile.',
        );
    const position = proposalRegistrationBodyDigests(proposal).indexOf(
        hexadecimal(enrollment.registrationBodyDigest),
    );
    if (position < 0)
        throw new Error('The retained roster omits this participant.');
    return { ...context, profile, position };
};

export const parseRegistrationBodyDigests = (value: unknown): string[] => {
    if (
        !Array.isArray(value) ||
        !value.every(
            (id) => typeof id === 'string' && /^[0-9a-f]{128}$/u.test(id),
        )
    )
        throw new InvalidRequest('Malformed proposed record identifiers.');
    return value as string[];
};
