import { publishOfferAnnouncement } from '../../relay/offer-discovery.js';
import { createCandidatePublication } from '../../relay/publication.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    equalBytes,
    hexadecimal,
    tupleFields,
    unsigned16,
    unsigned32,
    unsigned64,
} from '../../shared/bytes.js';
import { decodeSignedPacket } from '../../shared/signed-packet.js';
import type { SignedPacket } from '../../shared/signed-packet.js';
import { openDelivery } from '../../storage/delivery.js';
import type { ContributionSession } from '../participant-session.js';

import {
    openContributionRecord,
    signing,
    offerSigningOperation,
    openSigning,
    sealContributionRecord,
    commitContribution,
} from './contribution-custody.js';
import { proofLength, readProof } from './contribution-proof.js';
import {
    contributionPhase,
    signingObject,
    proofObject,
} from './contribution-state.js';

// Reads every authenticated private proof slot and its padding. Only the
// exact framed proof reaches the signer or relay, and completion of either
// caller waits for the full fixed record pass.
const readRetainedProof = (
    session: ContributionSession,
    consume: (offset: number, bytes: Uint8Array) => void | Promise<void>,
) => {
    const { profile } = session.context;
    const records = session.state.publicRecords.filter(
        (record) => record.object === proofObject(profile),
    );
    return readProof(
        profile.contribution,
        session.state.header,
        async (slot, index) => {
            const record = records[index];
            if (
                record === undefined ||
                record.offset !== slot.offset ||
                record.length !== slot.length
            )
                throw new Error('The private proof record plan changed.');
            return openContributionRecord(session, record);
        },
        consume,
    );
};

// Recomputes the commitment to the retained body in the module's signer.
const bodyOffer = async (session: ContributionSession) => {
    const { context, state } = session;
    const { profile } = context;
    const control = concatenate(
        unsigned16(state.position),
        unsigned64(BigInt(proofLength(profile.contribution, state.header))),
    );
    try {
        const header = signing(
            context,
            offerSigningOperation.beginBody,
            control,
        );
        if (!equalBytes(header, state.header))
            throw new Error('The original source opening changed.');
    } finally {
        control.fill(0);
    }
    for (const polynomial of profile.contribution.polynomials.filter(
        (candidate) =>
            !profile.contribution.committedPolynomials.includes(
                candidate.expandedIndex,
            ),
    ))
        for (const record of state.publicRecords.filter(
            (value) => value.object === polynomial.expandedIndex + 1,
        )) {
            const bytes = await openContributionRecord(session, record);
            const input = concatenate(unsigned32(record.offset), bytes);
            try {
                signing(
                    context,
                    offerSigningOperation.polynomial,
                    input,
                    polynomial.expandedIndex,
                );
            } finally {
                bytes.fill(0);
                input.fill(0);
            }
        }
    await readRetainedProof(session, (offset, bytes) => {
        signing(context, offerSigningOperation.proof, bytes, offset);
    });
    return signing(context, offerSigningOperation.finishBody);
};

const storedOffer = async (
    session: ContributionSession,
): Promise<SignedPacket> => ({
    body: await openSigning(session, 'offerEnvelope'),
    signature: await openSigning(session, 'offerSignature'),
});

export const signOffer = async (
    session: ContributionSession,
): Promise<SignedPacket> => {
    const { context } = session;
    const { profile } = context;
    if (session.state.phase < contributionPhase.body)
        throw new Error('No complete contribution is retained.');
    if (session.state.phase === contributionPhase.signed)
        return storedOffer(session);
    const envelope = await bodyOffer(session);
    if (session.state.phase === contributionPhase.body) {
        const output = await sealContributionRecord(
            session,
            signingObject(profile, 'offerEnvelope'),
            0,
            envelope,
        );
        await commitContribution(session, {
            state: {
                ...session.state,
                phase: contributionPhase.signingIntent,
                signingRecords: [output.record],
            },
            signing: [output],
        });
    }
    const body = await openSigning(session, 'offerEnvelope');
    if (!equalBytes(envelope, body))
        throw new Error('The locked offer changed.');
    const signed = decodeSignedPacket(
        signing(context, offerSigningOperation.signOffer),
        profile.registration.signatureBytes,
    );
    if (signed === undefined)
        throw new Error('Malformed signed contribution packet.');
    if (!equalBytes(signed.body, body))
        throw new Error('The signer changed the offer.');
    const output = await sealContributionRecord(
        session,
        signingObject(profile, 'offerSignature'),
        0,
        signed.signature,
    );
    await commitContribution(session, {
        state: {
            ...session.state,
            phase: contributionPhase.signed,
            signingRecords: [...session.state.signingRecords, output.record],
        },
        signing: [output],
    });
    return storedOffer(session);
};

export const contributionCandidateKey = (
    position: number,
    bodyIdentity: Uint8Array,
) => 'contribution-' + String(position) + '/' + hexadecimal(bodyIdentity);

export const polynomialFile = (expandedIndex: number) =>
    'polynomial-' + String(expandedIndex).padStart(2, '0') + '.bin';

// Publishes one correlated complete signed offer, then announces its body.
export const publishOffer = async (
    session: ContributionSession,
    relay: PublicRelay,
    offer: SignedPacket,
) => {
    const { profile } = session.context;
    const fields = tupleFields(offer.body);
    if (fields.length !== 5 || fields[4].length !== 64)
        throw new Error('The retained offer envelope is malformed.');
    const bodyIdentity = fields[4];
    const key = contributionCandidateKey(session.state.position, bodyIdentity);
    const delivery = await openDelivery(session.context, session.root);
    const publication = createCandidatePublication(relay, key, delivery);
    await publication.addBytes('offer.bin', offer.body);
    await publication.addBytes('offer-signature.bin', offer.signature);
    await publication.addBytes('body-header.bin', session.state.header);
    for (const polynomial of profile.contribution.polynomials) {
        await publication.addStream(
            polynomialFile(polynomial.expandedIndex),
            polynomial.bytes,
            async (accept) => {
                for (const record of session.state.publicRecords.filter(
                    (value) => value.object === polynomial.expandedIndex + 1,
                )) {
                    const bytes = await openContributionRecord(session, record);
                    try {
                        await accept(bytes);
                    } finally {
                        bytes.fill(0);
                    }
                }
            },
        );
    }
    await publication.addStream(
        'proof.bin',
        proofLength(profile.contribution, session.state.header),
        async (accept) => {
            await readRetainedProof(session, async (_offset, bytes) => {
                try {
                    await accept(bytes);
                } finally {
                    bytes.fill(0);
                }
            });
        },
    );
    await publication.finish();
    await delivery.transfer(() =>
        publishOfferAnnouncement(relay, session.state.position, bodyIdentity),
    );
};
