import { writeModuleInput } from '../../module/context.js';
import type { PublicProfileContext } from '../../module/context.js';
import {
    readParticipantOutput,
    writeSetupInput,
} from '../../module/participant-module.js';
import { createCandidatePublication } from '../../relay/publication.js';
import type { PublicRelay } from '../../relay/relay.js';
import { concatenate, equalBytes, unsigned32 } from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import type { SignedPacket } from '../../shared/signed-packet.js';
import { openDelivery } from '../../storage/delivery.js';
import type { RecordContext } from '../../storage/private-records.js';
import { rootGeneration } from '../../storage/root-generation.js';
import type { AuthenticatedRoot } from '../../storage/root.js';
import {
    addedReferences,
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
} from '../../storage/root.js';
import {
    collectingCloseState,
    encodeCloseState,
} from '../close/close-state.js';
import type { ParticipantSession } from '../contribution/contribution.js';
import { contributionRecords } from '../contribution/contribution.js';
import { encodePreparationState } from '../contribution/preparation-state.js';
import {
    proposalRegistrationBodyDigests,
    rosterBegin,
    streamRegistrations,
} from '../roster/roster.js';

import { holdsFinalAggregate } from './setup-cache.js';
import {
    aggregateSelection,
    authenticateCertificate,
    authenticateSelection,
    preparedRosters,
    readSetupCertificate,
    verifyCertificateInputs,
} from './setup-verification.js';

// A participant's setup activation. It verifies the setup from its retained
// roster and preparation state, publishes the complete certificate it
// collected, retains the setup reference and certificate in its root while
// retiring its preparation records, and restores the verified setup in later
// operations, rebuilding the public aggregate cache from fresh verification
// when the cache lost it.

export const verifySetupRoster = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    const { context } = session;
    const { module, profile } = context;
    if (preparedRosters.has(module)) return;
    const { manifest } = session.root;
    const proposal = await readDataKind(context, manifest, dataKind.proposal);
    const definition = await readDataKind(
        context,
        manifest,
        dataKind.pollDefinition,
    );
    const pollSignature = await readDataKind(
        context,
        manifest,
        dataKind.pollSignature,
    );
    const registrationBodyDigests = proposalRegistrationBodyDigests(proposal);
    const begin = rosterBegin(
        context,
        manifest.poll,
        definition,
        pollSignature,
        registrationBodyDigests.length,
    );
    // The verified registrations are restored from the retained roster and
    // the published headers and keys.
    const input = concatenate(
        begin,
        await readDataKind(context, manifest, dataKind.retainedRoster),
    );
    writeModuleInput(context, input);
    if (module.setup_roster_begin_retained(begin.length, input.length) !== 0)
        throw new Error('The setup verifier refused the retained roster.');
    await streamRegistrations(
        relay,
        registrationBodyDigests,
        profile.registration,
        module.roster_open_records(),
        (operation, position, bytes) => {
            writeSetupInput(module, bytes);
            return (
                module.setup_roster_record(
                    operation,
                    position,
                    bytes.length,
                ) === 0
            );
        },
        true,
    );
    const proposalSignature = await readDataKind(
        context,
        manifest,
        dataKind.proposalSignature,
    );
    const proposalPacket = concatenate(
        unsigned32(proposal.length),
        proposal,
        proposalSignature,
    );
    writeSetupInput(module, proposalPacket);
    // The retained roster, proposal and signature are authenticated, so a
    // refusal means the relay served other headers or keys under their
    // names.
    if (module.setup_roster_finish(proposalPacket.length) !== 0)
        throw new PublicInputFailure(
            'The published registrations are not the retained roster.',
        );
    preparedRosters.add(module);
};

export const verifySelectionInputs = async (
    session: ParticipantSession,
    relay: PublicRelay,
    packet: SignedPacket,
    retained = false,
) => {
    await verifySetupRoster(session, relay);
    const selection = authenticateSelection(session.context, packet, retained);
    await aggregateSelection(session.context, relay, selection);
    return selection;
};

const retainedReference = (context: PublicProfileContext) => {
    if (context.module.retain_setup() !== 0)
        throw new Error('The credential refused the verified setup.');
    const reference = readParticipantOutput(context.module);
    if (reference.length !== context.profile.root.setupReferenceBytes)
        throw new Error('The setup reference has another length.');
    return reference;
};

export type VerifiedSetup = Readonly<{
    reference: Uint8Array;
    certificate: Uint8Array;
}>;

const referenceSetupIdentity = (reference: Uint8Array) =>
    reference.subarray(4, 68);

const certifyRetainedSelection = (
    session: ParticipantSession,
    certificate: Uint8Array,
) => {
    const retained = session.preparation.endorsement;
    if (retained === undefined) return undefined;
    const selection = authenticateCertificate(session.context, certificate);
    const original = authenticateSelection(
        session.context,
        retained.selection,
        true,
    );
    writeModuleInput(session.context, retained.reference);
    if (
        session.context.module.restore_selection_inputs(
            retained.reference.length,
        ) !== 0
    )
        throw new Error(
            'The original selection verification could not be restored.',
        );
    // Installing a different winning proposal discards the losing inputs in
    // Rust. Equality preserves the credential-keyed original verified inputs.
    authenticateCertificate(session.context, certificate);
    if (!equalBytes(original.identity, selection.identity)) return undefined;
    if (session.context.module.setup_finish_certificate() !== 0)
        throw new PublicInputFailure(
            'The certificate does not match the verified selection.',
        );
    return selection;
};

export const verifySetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
): Promise<VerifiedSetup> => {
    if (session.root.head.generation !== rootGeneration.preparation)
        throw new Error('No confirmed roster awaits setup activation.');
    await verifySetupRoster(session, relay);
    const certificate = await readSetupCertificate(session.context, relay);
    const certificateBytes = certificate.bytes;
    const selection =
        certifyRetainedSelection(session, certificateBytes) ??
        (await verifyCertificateInputs(
            session.context,
            relay,
            certificateBytes,
        ));
    // The complete certificate determines the semantic setup identity. Its
    // correlated manifest and every chunk have exact named readback before
    // the participant may retire its preparation state.
    if (certificate.retrieved === undefined) {
        const delivery = await openDelivery(session.context, session.root);
        const publication = createCandidatePublication(
            relay,
            'setup-certificate',
            delivery,
        );
        await publication.addBytes('certificate.bin', certificateBytes);
        await publication.finish();
    }
    const reference = retainedReference(session.context);
    if (!equalBytes(referenceSetupIdentity(reference), selection.identity))
        throw new Error('The retained setup names another selection.');
    return { reference, certificate: certificateBytes };
};

export const ensureFinalAggregate = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    if (session.root.head.generation < rootGeneration.setupRetained)
        throw new Error('No setup reference is retained.');
    if (await holdsFinalAggregate(session.context)) return false;
    // A cache loss can also occur after certification in this same operation.
    // Rebuild from fresh owning verification, not an existing aggregate flag.
    preparedRosters.delete(session.context.module);
    await verifySetupRoster(session, relay);
    const certificate = await readDataKind(
        session.context,
        session.root.manifest,
        dataKind.setupCertificate,
    );
    await verifyCertificateInputs(session.context, relay, certificate, true);
    if (
        !equalBytes(
            retainedReference(session.context),
            await readDataKind(
                session.context,
                session.root.manifest,
                dataKind.setupReference,
            ),
        )
    )
        throw new Error('The verified setup differs from the retained one.');
    return true;
};

export const restoreSetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    if (await ensureFinalAggregate(session, relay)) return;
    await verifySetupRoster(session, relay);
    const { context, root } = session;
    authenticateCertificate(
        context,
        await readDataKind(context, root.manifest, dataKind.setupCertificate),
        true,
    );
    const reference = await readDataKind(
        context,
        root.manifest,
        dataKind.setupReference,
    );
    writeModuleInput(context, reference);
    if (context.module.restore_setup(reference.length) !== 0)
        throw new Error('The credential refused the retained setup.');
};

// The record context of a participant whose setup is retained.
export const retainedRecordContext = async (
    session: ParticipantSession,
): Promise<RecordContext> => ({
    poll: session.root.manifest.poll,
    runtime: session.context.runtime,
    setupIdentity: referenceSetupIdentity(
        await readDataKind(
            session.context,
            session.root.manifest,
            dataKind.setupReference,
        ),
    ).slice(),
    position: session.records.position,
});

export const retainSetup = async (
    session: ParticipantSession,
    verified: VerifiedSetup,
): Promise<AuthenticatedRoot> => {
    const { context, root } = session;
    const added = [
        { kind: dataKind.setupReference, bytes: verified.reference },
        { kind: dataKind.setupCertificate, bytes: verified.certificate },
    ];
    const retainedKeys = root.manifest.dataKeys.slice(0, 64);
    const retainedReferences = root.manifest.references.filter(
        (reference) => reference.kind !== dataKind.sourceCapsule,
    );
    const retained = await commitRoot(context, root, {
        generation: rootGeneration.setupRetained,
        manifest: {
            ...root.manifest,
            dataKeys: retainedKeys,
            references: addedReferences(context, retainedReferences, added),
            suffixes: {
                ...root.manifest.suffixes,
                preparation: encodePreparationState({}),
                ballot: new Uint8Array(),
                close: encodeCloseState(12, false, collectingCloseState()),
            },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(session),
        ],
        addedData: added,
        write: (transaction) => {
            transaction.objectStore('data').delete([dataKind.sourceCapsule, 0]);
            transaction.objectStore('contribution').clear();
            transaction.objectStore('checkpoint').clear();
        },
    });
    // Both storage and live private sources retire only after the exact
    // predecessor and committed successor have authenticated.
    root.manifest.dataKeys.subarray(64).fill(0);
    root.plaintext.subarray(4 + 64, 4 + 96).fill(0);
    if (context.module.retire_contribution_sources() !== 0)
        throw new Error('The original key sources could not be retired.');
    session.root = retained;
    session.preparation = {};
    delete session.state;
    return retained;
};
