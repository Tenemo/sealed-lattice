import type { PublicProfileContext } from '../../module/context.js';
import {
    readModuleMemory,
    writeBufferInput,
} from '../../module/participant-module.js';
import {
    candidateLists,
    readCandidateFile,
    scanCandidatesFairly,
    streamCandidateFile,
} from '../../relay/relay.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    readUnsigned16,
    readUnsigned32,
} from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import {
    deliverFinalAggregate,
    readFinalAggregate,
} from '../setup/setup-cache.js';
import { discardEvaluation } from '../target-vote/evaluation.js';
import { targetVoteCandidateKey } from '../target-vote/target.js';

// The release verification. The completion verifier certifies the target
// from the published target votes, and combines the published release shares
// that pass the owning envelope and body verifiers under each position's
// certified release context into the result.

const words = (bytes: Uint8Array) =>
    Array.from({ length: Math.floor(bytes.length / 4) }, (_unused, index) =>
        readUnsigned32(bytes, 4 * index),
    );

// The completion verifier's operations, as its command numbers them.
const completionOperation = {
    beginVotes: 0,
    insertVote: 1,
    certify: 2,
    // A release share's two public operands, the constant then the linear
    // polynomial, each delivered in chunks.
    beginShareConstant: 3,
    pushOperand: 4,
    finishOperand: 5,
    authenticateRelease: 6,
    beginReleaseBody: 7,
    pushReleaseBody: 8,
    finishRelease: 9,
    result: 10,
} as const;

const tryCompletionCommand = (
    context: PublicProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const { module } = context;
    writeBufferInput(module, 'completion', input);
    if (module.completion_command(operation, argument, input.length) !== 0)
        return undefined;
    return readModuleMemory(
        module,
        module.completion_output_pointer(),
        module.completion_output_length(),
    );
};

const completionCommand = (
    context: PublicProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const output = tryCompletionCommand(context, operation, argument, input);
    if (output === undefined)
        throw new Error(
            'The completion refused operation ' + String(operation) + '.',
        );
    return output;
};

// Certifies the target from the published target votes, stopping at the
// certificate threshold. A missing or refused vote is skipped; too few leave
// the participant pending. A restored target that the votes leave
// uncertified while one of them was refused, as every vote for another target
// is, is discarded, so that the next operation evaluates the target the public
// close records name; missing votes alone keep it. Returns whether the target
// is encrypted.
export const certifyTarget = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    restored: boolean,
) => {
    const [count, threshold] = words(
        completionCommand(context, completionOperation.beginVotes),
    );
    let accepted = 0;
    // The authors whose vote the completion verifier refused.
    const refusals = new Set<number>();
    await scanCandidatesFairly(
        candidateLists(relay, count, targetVoteCandidateKey),
        async (position, candidate) => {
            let vote: Uint8Array;
            try {
                vote = await readCandidateFile(
                    relay,
                    candidate,
                    'vote.bin',
                    context.profile.target.votePacketBytes,
                );
            } catch (error) {
                if (error instanceof PublicInputFailure) return false;
                throw error;
            }
            // A copied valid vote in another author's discovery list must
            // not consume that list's opportunity to supply its own vote.
            if (
                vote.length !== context.profile.target.votePacketBytes ||
                readUnsigned16(vote, 0) !== position
            )
                return false;
            const inserted = tryCompletionCommand(
                context,
                completionOperation.insertVote,
                0,
                vote,
            );
            if (inserted === undefined) {
                refusals.add(position);
                return false;
            }
            accepted = words(inserted)[1];
            return true;
        },
        () => (accepted >= threshold ? accepted : undefined),
    );
    const certified = tryCompletionCommand(
        context,
        completionOperation.certify,
    );
    if (certified === undefined) {
        if (restored && refusals.size > 0) await discardEvaluation(context);
        throw new PublicInputFailure('The target votes are incomplete.');
    }
    return words(certified)[0] === 1;
};

// Creates the certified release context of one position from its two share
// polynomials of the verified aggregate.
export const establishReleaseContext = async (
    context: PublicProfileContext,
    position: number,
) => {
    const stream = (index: number) =>
        readFinalAggregate(context, index, (offset, bytes) => {
            if (
                tryCompletionCommand(
                    context,
                    completionOperation.pushOperand,
                    offset,
                    bytes,
                ) === undefined
            )
                throw new PublicInputFailure('A release key was refused.');
        });
    // Finishing a polynomial checks its bytes against the retained setup
    // reference.
    const finish = () => {
        const output = tryCompletionCommand(
            context,
            completionOperation.finishOperand,
        );
        if (output === undefined)
            throw new PublicInputFailure('A release key was refused.');
        return output;
    };
    const constant = words(
        completionCommand(
            context,
            completionOperation.beginShareConstant,
            position,
        ),
    )[0];
    await deliverFinalAggregate(context, async () => {
        await stream(constant);
        await stream(words(finish())[0]);
        finish();
    });
};

export const releaseCandidateKey = (position: number) =>
    'release-' + String(position);

// Combines the published release shares of the target this instance
// certified into the result: the ordered option identifiers, or none for a
// certified no-result target. Each share passes the owning envelope and body
// verifiers under its position's release context; too few verified shares
// leave the work pending.
export const combineReleaseShares = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    encrypted: boolean,
) => {
    const { profile } = context;
    const bounds = profile.release;
    let combined = encrypted
        ? undefined
        : tryCompletionCommand(context, completionOperation.result);
    const result = await scanCandidatesFairly(
        candidateLists(relay, profile.participantCount, releaseCandidateKey),
        async (position, candidate) => {
            let packet: Uint8Array;
            try {
                packet = await readCandidateFile(
                    relay,
                    candidate,
                    'envelope.bin',
                    bounds.envelopeBytes + profile.registration.signatureBytes,
                );
            } catch (error) {
                if (error instanceof PublicInputFailure) return false;
                throw error;
            }
            await establishReleaseContext(context, position);
            const authenticated = tryCompletionCommand(
                context,
                completionOperation.authenticateRelease,
                0,
                packet,
            );
            if (authenticated === undefined) return false;
            let header: Uint8Array = new Uint8Array();
            let accepted = true;
            try {
                await streamCandidateFile(
                    relay,
                    candidate,
                    'body.bin',
                    bounds.maximumBodyBytes,
                    (bytes) => {
                        let rest = bytes;
                        if (header.length < bounds.bodyHeaderBytes) {
                            const taken = rest.subarray(
                                0,
                                bounds.bodyHeaderBytes - header.length,
                            );
                            header = concatenate(header, taken);
                            rest = rest.subarray(taken.length);
                            if (header.length < bounds.bodyHeaderBytes) return;
                            accepted &&=
                                tryCompletionCommand(
                                    context,
                                    completionOperation.beginReleaseBody,
                                    0,
                                    header,
                                ) !== undefined;
                        }
                        if (rest.length > 0 && accepted)
                            accepted =
                                tryCompletionCommand(
                                    context,
                                    completionOperation.pushReleaseBody,
                                    0,
                                    rest,
                                ) !== undefined;
                    },
                );
            } catch (error) {
                if (!(error instanceof PublicInputFailure)) throw error;
                accepted = false;
            }
            if (
                !accepted ||
                tryCompletionCommand(
                    context,
                    completionOperation.finishRelease,
                ) === undefined
            )
                return false;
            combined = tryCompletionCommand(
                context,
                completionOperation.result,
            );
            return true;
        },
        () => combined,
    );
    if (result === undefined)
        throw new PublicInputFailure('The release shares are incomplete.');
    const identifiers: string[] = [];
    const decoder = new TextDecoder('utf-8', { fatal: true });
    for (
        let offset = 4, index = 0;
        index < readUnsigned32(result, 0);
        index++
    ) {
        const length = readUnsigned32(result, offset);
        identifiers.push(
            decoder.decode(result.subarray(offset + 4, offset + 4 + length)),
        );
        offset += 4 + length;
    }
    return { encrypted, identifiers };
};
