import type { ArchiveReference } from '@sealed-lattice/wasm';

import { openTranscript } from '../../transcript-archive.js';

import type { PublicContext } from './context.js';
import type { PublicRelay } from './public.js';
import { certifyTarget, combineReleaseShares } from './release.js';
import { verifyPublicSetup } from './setup.js';
import {
    completionDirectory,
    evaluateClosedTarget,
    publicCloseRecords,
} from './target.js';
import { discoverTranscripts } from './transcript.js';
import type { OpenedArchive } from './transcript.js';

// The standalone verifier runs the owning verifiers over a poll's archived
// transcript from the poll's identity alone, in a worker that holds no
// participant state, credential or randomness, only public working storage.
// The module certifies one target and verifies its release shares once per
// instance, so each candidate transcript runs in a fresh worker.

// Verifies the outcome of the poll the identity names from the transcript
// that serves every read: the complete setup, the close barrier and each
// usable ballot's classification, the evaluated target and its certificate,
// and the release shares of a result. Returns whether the certified target
// is encrypted and the ordered option identifiers, none for no result.
export const verifyTranscript = async (
    context: PublicContext,
    relay: PublicRelay,
    poll: Uint8Array,
) => {
    const profiled = await verifyPublicSetup(context, relay, poll);
    await evaluateClosedTarget(publicCloseRecords(profiled), relay);
    return combineReleaseShares(
        profiled,
        relay,
        await certifyTarget(profiled, relay, false),
    );
};

const releaseEnvelopeRoute = completionDirectory + 'release-envelope-';

// The discovered transcripts in the order a verifier tries them: those that
// hold more release envelopes first, since only release shares reach a
// result, and a no-result target needs none. A transcript that does not open
// is left out. The order is a hint; verification decides.
export const transcriptsToVerify = async (opened: OpenedArchive) => {
    const counted: { index: ArchiveReference; releases: number }[] = [];
    for (const index of await discoverTranscripts(opened)) {
        const transcript = await openTranscript(opened.archive, index).catch(
            () => undefined,
        );
        if (transcript !== undefined)
            counted.push({
                index,
                releases: transcript
                    .files()
                    .filter((file) =>
                        file.route.startsWith(releaseEnvelopeRoute),
                    ).length,
            });
    }
    return counted
        .sort((left, right) => right.releases - left.releases)
        .map(({ index }) => index);
};
