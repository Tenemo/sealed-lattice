import { describe, expect, it } from 'vitest';

import {
    foundationBoardCandidateObjectHash,
    loadTranscriptCoreKernel,
    openFoundationBoardSession,
    type FoundationBoardSessionInput,
} from '#packages/wasm/src/index';
import {
    createAuthenticatedSetupIntentTestVector,
    createCanonicalTestRosterBytes,
} from '#packages/wasm/tests/foundation-board-test-vectors';

const configuration = (
    canonicalRosterBytes = createCanonicalTestRosterBytes(),
): FoundationBoardSessionInput => ({
    actionContextHash: new Uint8Array(64).fill(0x33),
    canonicalRosterBytes,
    ceremonyContextHash: new Uint8Array(64).fill(0x22),
    limits: {
        maximumCarrierByteLength: 131_072,
        maximumCarrierCount: 32,
        maximumRetainedCarrierByteLength: 1_048_576,
        maximumUnresolvedDependencyCount: 128,
    },
    suiteIdentifier: new Uint8Array(64).fill(0x11),
});

describe('foundation board session in browser WASM', () => {
    it('begins from a canonical external roster and refuses malformed carriers without consuming the session', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const authenticatedSetupIntent =
            createAuthenticatedSetupIntentTestVector();
        const opened = openFoundationBoardSession({
            configuration: configuration(
                authenticatedSetupIntent.canonicalRosterBytes,
            ),
            kernel,
        });
        expect(opened.isValid).toBe(true);
        if (!opened.isValid) {
            throw new Error(opened.refusalReason);
        }

        const session = opened.value;
        try {
            expect(session.ingest(Uint8Array.from([0xff]))).toEqual({
                isValid: false,
                refusalReason: 'malformedEncoding',
            });
            const accepted = session.ingest(
                authenticatedSetupIntent.canonicalCarrierBytes,
            );
            expect(accepted.isValid).toBe(true);
            if (!accepted.isValid) {
                throw new Error(accepted.refusalReason);
            }
            expect(foundationBoardCandidateObjectHash(accepted.value)).toEqual(
                authenticatedSetupIntent.objectHash,
            );
            expect(session.requireCompleteCarrierGraph()).toEqual({
                isValid: true,
                value: undefined,
            });
        } finally {
            session.cancel();
        }
        expect(session.state()).toBe('cancelled');
    });
});
