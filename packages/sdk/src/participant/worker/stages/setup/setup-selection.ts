import { writeModuleInput } from '../../module/context.js';
import {
    readParticipantOutput,
    writeSetupInput,
} from '../../module/participant-module.js';
import { discoverContributionOffers } from '../../relay/offer-discovery.js';
import {
    createCandidatePublication,
    readOfferAnnouncements,
} from '../../relay/relay.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    equalBytes,
    readUnsigned16,
    readUnsigned32,
    tupleFields,
    unsigned16,
} from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import {
    decodeSignedPacket,
    encodeSignedPacket,
} from '../../shared/signed-packet.js';
import type { SignedPacket } from '../../shared/signed-packet.js';
import { openDelivery } from '../../storage/delivery.js';
import { rootGeneration } from '../../storage/root-generation.js';
import { commitPreparation } from '../contribution/contribution.js';
import type { ParticipantSession } from '../contribution/contribution.js';
import type { PreparationEndorsement } from '../contribution/preparation-state.js';

import {
    authenticateSelection,
    endorsementCandidateKey,
    readSelection,
    setupOutput,
    verifyOffer,
} from './setup-verification.js';
import type { SelectedOffer } from './setup-verification.js';
import { verifySelectionInputs, verifySetupRoster } from './setup.js';

// The original preparation signer's operations, as the module numbers them.
const selectionOperation = {
    unsignedBody: 0,
    signProposal: 1,
    endorse: 2,
    restoreProposal: 3,
    restoreEndorsement: 4,
    endorsementBody: 5,
} as const;

const selectionCommand = (
    session: ParticipantSession,
    operation: number,
    input: Uint8Array = new Uint8Array(),
) => {
    const { context } = session;
    writeModuleInput(context, input);
    if (context.module.selection_signing_command(operation, input.length) !== 0)
        throw new Error('The original preparation signer refused.');
    return readParticipantOutput(context.module);
};

// Only transport destinations are recovered from an authenticated original
// signing intent. Rust rebuilds the proposal from complete verified offers and
// must reproduce that exact body before its one-shot purpose is consumed.
const originalSelectedOffers = (
    session: ParticipantSession,
    body: Uint8Array,
): SelectedOffer[] => {
    const fields = tupleFields(body);
    const entries = fields[2];
    if (fields.length !== 3 || entries === undefined || entries.length < 8)
        throw new Error('The retained selection is malformed.');
    const length = readUnsigned32(entries, 0);
    const count = readUnsigned32(entries, 4);
    if (
        length !== entries.length - 4 ||
        count !== session.context.profile.setupContributorCount ||
        entries.length !== 8 + count * 66
    )
        throw new Error('The retained selection has another shape.');
    return Array.from({ length: count }, (_, ordinal) => {
        const offset = 8 + ordinal * 66;
        const position = readUnsigned16(entries, offset);
        if (
            position >= session.context.profile.eligibleContributorCount ||
            (ordinal > 0 && readUnsigned16(entries, offset - 66) >= position)
        )
            throw new Error('The retained selection has another author.');
        return { position, identity: entries.slice(offset + 2, offset + 66) };
    });
};

const buildOriginalSelection = (
    session: ParticipantSession,
    offers: readonly SelectedOffer[],
) => {
    const bytes = concatenate(
        ...offers.map(({ position }) => unsigned16(position)),
    );
    writeSetupInput(session.context.module, bytes);
    if (session.context.module.setup_selection_build(bytes.length) !== 0)
        throw new PublicInputFailure(
            'The complete selected offers were refused.',
        );
    const expected = setupOutput(session.context);
    const actual = selectionCommand(session, selectionOperation.unsignedBody);
    if (!equalBytes(actual, expected))
        throw new Error('The organizer signer changed the verified selection.');
    return actual;
};

export const selectSetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    if (session.root.head.generation !== rootGeneration.preparation)
        throw new Error('No confirmed roster permits setup selection.');
    await verifySetupRoster(session, relay);
    let retained = session.preparation.selection;
    if (retained?.stage === 'signed') {
        selectionCommand(
            session,
            selectionOperation.restoreProposal,
            encodeSignedPacket(retained),
        );
    } else {
        const offers: SelectedOffer[] = [];
        if (retained !== undefined) {
            offers.push(...originalSelectedOffers(session, retained.body));
            for (const offer of offers)
                await verifyOffer(session.context, relay, offer);
        } else {
            const profile = session.context.profile;
            offers.push(
                ...(await discoverContributionOffers(
                    profile.eligibleContributorCount,
                    profile.setupContributorCount,
                    (position, offset) =>
                        readOfferAnnouncements(relay, position, offset),
                    (offer) => verifyOffer(session.context, relay, offer),
                )),
            );
        }
        const body = buildOriginalSelection(session, offers);
        if (retained === undefined) {
            await commitPreparation(session, {
                selection: {
                    stage: 'intent',
                    body,
                },
            });
            retained = session.preparation.selection;
        }
        if (retained?.stage !== 'intent' || !equalBytes(retained.body, body))
            throw new Error('The original selection intent changed.');
        const signed = decodeSignedPacket(
            selectionCommand(session, selectionOperation.signProposal),
            session.context.profile.registration.signatureBytes,
        );
        if (signed === undefined)
            throw new Error('The signed selection has another shape.');
        if (!equalBytes(signed.body, retained.body))
            throw new Error('The organizer changed its locked selection.');
        await commitPreparation(session, {
            selection: { stage: 'signed', ...signed },
        });
        retained = session.preparation.selection;
    }
    if (retained?.stage !== 'signed')
        throw new Error('No completed selection is retained.');
    const delivery = await openDelivery(session.context, session.root);
    const publication = createCandidatePublication(
        relay,
        'selection',
        delivery,
    );
    await publication.addBytes('selection.bin', retained.body);
    await publication.addBytes('signature.bin', retained.signature);
    await publication.finish();
    // Keep the positive offer holders in this worker. Endorsement still has
    // its own durable intent and one-shot purpose, including after a restart.
    await endorseSetup(session, relay, retained);
};

const endorsementPacket = (
    session: ParticipantSession,
    retained: PreparationEndorsement,
) => {
    if (retained.stage !== 'signed')
        throw new Error('No signed endorsement is retained.');
    const fields = tupleFields(retained.body);
    if (
        fields.length !== 3 ||
        fields[1].length !== 64 ||
        fields[2].length !== 2 ||
        readUnsigned16(fields[2], 0) !== session.context.position
    )
        throw new Error('The retained endorsement names another participant.');
    return concatenate(fields[2], fields[1], retained.signature);
};

export const endorseSetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
    // The organizer's own retained signed selection, which is retained state
    // rather than public input.
    ownSelection?: SignedPacket,
) => {
    if (session.root.head.generation !== rootGeneration.preparation)
        throw new Error('No confirmed roster permits setup endorsement.');
    await verifySetupRoster(session, relay);
    let retained = session.preparation.endorsement;
    if (retained === undefined) {
        const selection =
            ownSelection ?? (await readSelection(session.context, relay));
        await verifySelectionInputs(
            session,
            relay,
            selection,
            ownSelection !== undefined,
        );
        const { module, profile } = session.context;
        if (module.retain_selection_inputs() !== 0)
            throw new Error(
                'The credential refused the verified selection inputs.',
            );
        const reference = readParticipantOutput(module);
        if (reference.length !== profile.preparation.selectionReferenceBytes)
            throw new Error(
                'The retained selection inputs have another length.',
            );
        const body = selectionCommand(
            session,
            selectionOperation.endorsementBody,
        );
        await commitPreparation(session, {
            endorsement: {
                stage: 'intent',
                selection,
                reference,
                body,
            },
        });
        retained = session.preparation.endorsement;
    } else {
        authenticateSelection(session.context, retained.selection, true);
        writeModuleInput(session.context, retained.reference);
        if (
            session.context.module.restore_selection_inputs(
                retained.reference.length,
            ) !== 0
        )
            throw new Error(
                'The original selection inputs could not be restored.',
            );
    }
    if (retained === undefined)
        throw new Error('No endorsement intent is retained.');
    if (retained.stage === 'intent') {
        if (
            !equalBytes(
                selectionCommand(session, selectionOperation.endorsementBody),
                retained.body,
            )
        )
            throw new Error('The original endorsement intent changed.');
        const signed = selectionCommand(session, selectionOperation.endorse);
        const fields = tupleFields(retained.body);
        const prefix = concatenate(fields[2], fields[1]);
        if (
            signed.length !==
                session.context.profile.preparation.endorsementPacketBytes ||
            !equalBytes(signed.subarray(0, 66), prefix)
        )
            throw new Error('The signer changed the endorsement context.');
        await commitPreparation(session, {
            endorsement: {
                stage: 'signed',
                selection: retained.selection,
                reference: retained.reference,
                body: retained.body,
                signature: signed.slice(66),
            },
        });
        retained = session.preparation.endorsement;
    } else {
        selectionCommand(
            session,
            selectionOperation.restoreEndorsement,
            concatenate(
                encodeSignedPacket(retained.selection),
                endorsementPacket(session, retained),
            ),
        );
    }
    if (retained === undefined)
        throw new Error('No completed endorsement is retained.');
    const bytes = endorsementPacket(session, retained);
    const delivery = await openDelivery(session.context, session.root);
    const publication = createCandidatePublication(
        relay,
        endorsementCandidateKey(session.context.position),
        delivery,
    );
    await publication.addBytes('endorsement.bin', bytes);
    await publication.finish();
};
