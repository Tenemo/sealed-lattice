import {
    concatenate,
    equalBytes,
    fromHexadecimal,
    hexadecimal,
    readUnsigned32,
    tupleFields,
    unsigned16,
    unsigned32,
} from './bytes.js';
import { PublicInputFailure, sessionInput } from './context.js';
import type { ParticipantContext } from './context.js';
import type { RestoredEnrollment } from './enrollment.js';
import { readKernel } from './kernel.js';
import { readPublic, streamPublic } from './public.js';
import type { PublicRelay } from './public.js';
import {
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
    referenceData,
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

const validRecordIds = (ids: readonly string[], participantCount: number) =>
    ids.length === participantCount &&
    new Set(ids).size === ids.length &&
    ids.every((id) => /^[0-9a-f]{128}$/u.test(id));

export type VerifiedProposal = Readonly<{
    body: Uint8Array;
    identity: Uint8Array;
    recordIds: readonly string[];
    position: number;
}>;

// Streams every proposed registration record into the module's roster
// verifier. The verified proposal stays live in the module; its body must
// list exactly the requested records and include this participant.
const verifyProposalInputs = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    recordIds: readonly string[],
): Promise<VerifiedProposal> => {
    const { kernel, descriptor, runtime } = context;
    const registration = descriptor.registration;
    if (!validRecordIds(recordIds, descriptor.participantCount))
        throw new PublicInputFailure('The proposed records are invalid.');
    const begin = concatenate(
        root.manifest.poll,
        runtime,
        unsigned16(recordIds.length),
        unsigned32(enrollment.definition.length),
        enrollment.definition,
        enrollment.definitionSignature,
    );
    sessionInput(context, begin);
    if (kernel.roster_begin(begin.length) !== 0)
        throw new PublicInputFailure('The proposed poll was refused.');
    for (const [position, id] of recordIds.entries()) {
        const header = await readPublic(
            relay,
            registrationPath(id, registrationFile.header),
            registration.maximumHeaderBytes,
        );
        const signature = await readPublic(
            relay,
            registrationPath(id, registrationFile.signature),
            registration.signatureBytes,
        );
        const record = concatenate(
            unsigned16(position),
            unsigned32(header.length),
            header,
            signature,
        );
        sessionInput(context, record);
        if (kernel.roster_record_begin(record.length) !== 0)
            throw new PublicInputFailure('A registration header was refused.');
        await streamPublic(
            relay,
            registrationPath(id, registrationFile.publicKey),
            registration.publicKeyBytes,
            (bytes) => {
                sessionInput(context, bytes);
                if (kernel.roster_record_key(bytes.length) !== 0)
                    throw new PublicInputFailure(
                        'A registration key was refused.',
                    );
            },
        );
        if (kernel.roster_record_key_finish() !== 0)
            throw new PublicInputFailure('A registration key is incomplete.');
        await streamPublic(
            relay,
            registrationPath(id, registrationFile.proof),
            registration.maximumProofBytes,
            (bytes) => {
                sessionInput(context, bytes);
                if (kernel.roster_record_proof(bytes.length) !== 0)
                    throw new PublicInputFailure(
                        'A registration proof was refused.',
                    );
            },
        );
        if (kernel.roster_record_finish() !== 0)
            throw new PublicInputFailure('A registration record was refused.');
    }
    if (kernel.roster_finish() !== 1)
        throw new PublicInputFailure('The roster proposal was refused.');
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
    return {
        body,
        identity: readKernel(kernel, kernel.roster_identity_pointer(), 64),
        recordIds,
        position,
    };
};

const verifySignature = (
    context: ParticipantContext,
    signature: Uint8Array,
) => {
    sessionInput(context, signature);
    return context.kernel.verify_roster_signature(signature.length) === 1;
};

// The organizer locks the verified proposal and its signing coins before the
// signature exists, then signs. A restored intent signs the same proposal
// with the retained coins after verifying its records again.
export const proposeRoster = async (
    context: ParticipantContext,
    relay: PublicRelay,
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    recordIds: readonly string[],
): Promise<AuthenticatedRoot | undefined> => {
    if (!enrollment.isOrganizer || root.head.generation !== 1) return undefined;
    const proposal = await verifyProposalInputs(
        context,
        relay,
        root,
        enrollment,
        recordIds,
    );
    if (context.kernel.validate_roster_signer() !== 0) return undefined;
    const proposalCoins = crypto.getRandomValues(new Uint8Array(32));
    const locked = await commitRoot(context, root, {
        generation: 2,
        manifest: {
            ...root.manifest,
            references: [
                ...root.manifest.references,
                ...referenceData(context, [
                    { kind: dataKind.proposal, bytes: proposal.body },
                ]),
            ],
            proposalCoins,
        },
        predecessorRecords: dataRecordInventory(root.manifest),
        addedData: [{ kind: dataKind.proposal, bytes: proposal.body }],
    });
    return signRoster(context, locked, proposal);
};

export const signRoster = async (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    proposal: VerifiedProposal,
): Promise<AuthenticatedRoot> => {
    const coins = root.manifest.proposalCoins;
    if (root.head.generation !== 2 || coins === undefined)
        throw new Error('No locked roster proposal exists.');
    const { kernel, descriptor } = context;
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
        descriptor.registration.signatureBytes,
    );
    if (!verifySignature(context, signature))
        throw new Error('The proposal signature did not verify.');
    const { proposalCoins: _retired, ...manifest } = root.manifest;
    return commitRoot(context, root, {
        generation: 3,
        manifest: {
            ...manifest,
            references: [
                ...manifest.references,
                ...referenceData(context, [
                    { kind: dataKind.proposalSignature, bytes: signature },
                ]),
            ],
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
): Promise<AuthenticatedRoot | undefined> => {
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
        context.descriptor.registration.signatureBytes,
    );
    if (!verifySignature(context, signature))
        throw new PublicInputFailure(
            'The organizer proposal signature failed.',
        );
    const added = [
        { kind: dataKind.proposal, bytes: proposal.body },
        { kind: dataKind.proposalSignature, bytes: signature },
    ];
    return commitRoot(context, root, {
        generation: 3,
        manifest: {
            ...root.manifest,
            references: [
                ...root.manifest.references,
                ...referenceData(context, added),
            ],
        },
        predecessorRecords: dataRecordInventory(root.manifest),
        addedData: added,
    });
};

// Verifies the retained proposal again from its public records so that the
// module holds the live signed proposal that contribution generation needs.
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
    const proposal = await verifyProposalInputs(
        context,
        relay,
        root,
        enrollment,
        proposalRecordIds(stored),
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

export const parseRecordIds = (value: unknown): string[] => {
    if (!Array.isArray(value) || !value.every((id) => typeof id === 'string'))
        throw new PublicInputFailure('Malformed proposed record identifiers.');
    fromHexadecimal(value.join(''));
    return value;
};
