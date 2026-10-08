import type { PublicProfileContext } from '../../module/context.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '../../module/custody-identity.js';
import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import { identityBytes } from '../../module/runtime-bounds.js';
import {
    equalBytes,
    hexadecimal,
    readUnsigned16,
    readUnsigned32,
} from '../../shared/bytes.js';
import { ballotEnvelopeOffset } from '../ballot/ballot-state.js';

// The public close records: their discovery keys and file names, and what
// a response or proposal packet names. A participant's close work and the
// close barrier verifier read them alike.

export const listedEntryBytes = 2 + identityBytes;

export const closeIntentCandidateKey = 'close-intent';

export const closeResponseCandidateKey = (position: number) =>
    'close-response-' + String(position);

export const closeProposalCandidateKey = 'close-proposal';

export const closureResponseFile = (identity: Uint8Array) =>
    'response-' + hexadecimal(identity) + '.bin';

export const closureSubmissionFile = (identity: Uint8Array) =>
    'submission-' + hexadecimal(identity) + '.bin';

export const closureBodyFile = (identity: Uint8Array) =>
    'body-' + hexadecimal(identity) + '.bin';

// The identity of the envelope a retained submission begins with, derived
// without the close module, so that an operation that restores no setup can name
// what its custody holds.
export const custodyEnvelopeIdentity = (
    context: PublicProfileContext,
    submission: Uint8Array,
) =>
    custodyIdentity(
        context.module,
        custodyPurpose.envelope,
        submission.subarray(0, context.profile.ballot.envelopeBytes),
    );

// Whether a submission is the listed author's envelope with the listed
// identity, followed by a signature. Only the listed envelope's bytes have
// its identity, so a copy selected here is the one the barrier verifier then
// authenticates.
export const isListedSubmission = (
    context: PublicProfileContext,
    submission: Uint8Array,
    author: number,
    identity: Uint8Array,
) =>
    submission.length === context.profile.close.submissionBytes &&
    readUnsigned16(submission, ballotEnvelopeOffset.author) === author &&
    equalBytes(custodyEnvelopeIdentity(context, submission), identity);

// Whether bytes frame one response packet of the profile.
export const isResponsePacket = (
    profile: ParticipantProfile,
    bytes: Uint8Array,
) => {
    if (bytes.length < 4) return false;
    const length = readUnsigned32(bytes, 0);
    return (
        length >= profile.close.minimumResponseBodyBytes &&
        length <= profile.close.maximumResponseBodyBytes &&
        bytes.length === 4 + length + profile.registration.signatureBytes
    );
};

// A response packet's identity, by which a proposal names it: the identity
// of its signed body.
export const responseIdentity = (
    context: PublicProfileContext,
    response: Uint8Array,
) =>
    custodyIdentity(
        context.module,
        custodyPurpose.closeResponse,
        response.subarray(4, 4 + readUnsigned32(response, 0)),
    );

// The author and envelope identity of each entry a response packet lists.
export const responseListing = (
    profile: ParticipantProfile,
    response: Uint8Array,
) => {
    const end = 4 + readUnsigned32(response, 0);
    const entries: { author: number; identity: Uint8Array }[] = [];
    for (
        let offset = 4 + profile.close.minimumResponseBodyBytes;
        offset + listedEntryBytes <= end;
        offset += listedEntryBytes
    )
        entries.push({
            author: readUnsigned16(response, offset),
            identity: response.slice(offset + 2, offset + listedEntryBytes),
        });
    return entries;
};

// The responders and response identities that end a proposal packet's body.
export const proposalResponses = (
    profile: ParticipantProfile,
    proposal: Uint8Array,
) => {
    const { proposalBodyBytes, quorum } = profile.close;
    return Array.from({ length: quorum }, (_unused, index) => {
        const offset =
            4 + proposalBodyBytes - (quorum - index) * listedEntryBytes;
        return {
            responder: readUnsigned16(proposal, offset),
            identity: proposal.slice(offset + 2, offset + listedEntryBytes),
        };
    });
};
