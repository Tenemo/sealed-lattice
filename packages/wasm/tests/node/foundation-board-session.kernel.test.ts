import { describe, expect, it } from 'vitest';

import {
    foundationBoardCandidateObjectHash,
    loadTranscriptCoreKernel,
    openFoundationBoardSession,
    type FoundationBoardCandidate,
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
    publicSetupSeedObjectHash: new Uint8Array(64).fill(0x44),
    suiteIdentifier: new Uint8Array(64).fill(0x11),
    verifiedSetupSourceObjectHash: new Uint8Array(64).fill(0x55),
});

describe('foundation board session in Node WASM', () => {
    it('owns one capability-bound session and keeps malformed carrier refusals non-consuming', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const authenticatedSetupIntent =
            createAuthenticatedSetupIntentTestVector();
        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'sealed_lattice_foundation_board_begin',
                'sealed_lattice_foundation_board_cancel',
                'sealed_lattice_foundation_board_ingest',
                'sealed_lattice_foundation_board_require_complete_carrier_graph',
            ]),
        );

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
            expect(session.requireCompleteCarrierGraph()).toEqual({
                isValid: true,
                value: undefined,
            });
            expect(session.ingest(Uint8Array.from([1, 2, 3]))).toEqual({
                isValid: false,
                refusalReason: 'malformedEncoding',
            });
            expect(session.requireCompleteCarrierGraph()).toEqual({
                isValid: true,
                value: undefined,
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

            expect(
                openFoundationBoardSession({
                    configuration: configuration(
                        authenticatedSetupIntent.canonicalRosterBytes,
                    ),
                    kernel,
                }),
            ).toEqual({
                isValid: false,
                refusalReason: 'outsideSupportedProfile',
            });
        } finally {
            session.cancel();
        }

        expect(session.state()).toBe('cancelled');
        expect(session.ingest(Uint8Array.from([1]))).toEqual({
            isValid: false,
            refusalReason: 'consumedState',
        });
        expect(() => session.cancel()).not.toThrow();

        const reopened = openFoundationBoardSession({
            configuration: configuration(
                authenticatedSetupIntent.canonicalRosterBytes,
            ),
            kernel,
        });
        expect(reopened.isValid).toBe(true);
        if (reopened.isValid) {
            reopened.value.cancel();
        }
    });

    it('rejects structurally forged candidates at the runtime boundary', () => {
        expect(() =>
            foundationBoardCandidateObjectHash(
                Object.freeze({}) as FoundationBoardCandidate,
            ),
        ).toThrow('was not issued by this runtime');
    });
});
