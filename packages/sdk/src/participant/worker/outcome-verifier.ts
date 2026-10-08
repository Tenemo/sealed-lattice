import type { PublicContext } from './context.js';
import type { PublicRelay } from './relay.js';
import { certifyTarget, combineReleaseShares } from './release.js';
import { verifyPublicSetup } from './setup.js';
import { evaluateClosedTarget, publicCloseRecords } from './target.js';

// The outcome verifier runs the owning verifiers over a poll's published
// records from the poll's identity alone, in a worker that holds no
// participant state, credential or randomness, only public working storage.

// Verifies the outcome of the poll the identity names from the relay's
// public records: the complete setup, the close barrier and each usable
// ballot's classification, the evaluated target and its certificate, and the
// release shares of a result. Returns whether the certified target is
// encrypted and the ordered option identifiers, none for no result.
export const verifyPublishedOutcome = async (
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
