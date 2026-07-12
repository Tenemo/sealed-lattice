import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    VerificationResult,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

import type {
    FoundationBoardCandidate,
    FoundationBoardSessionInput,
} from '#packages/sdk/src/index';
import { createAuthenticatedSetupIntentTestVector } from '#packages/wasm/tests/foundation-board-test-vectors';

type VerifyBoardConsistency = (
    input: BoardConsistencyInput,
) => BoardConsistencyVerification;
type TestedFoundationBoardSession = Readonly<{
    cancel(): void;
    ingest(
        canonicalCarrierBytes: Uint8Array,
    ): VerificationResult<FoundationBoardCandidate>;
    requireCompleteCarrierGraph(): VerificationResult<undefined>;
}>;
type CreateFoundationBoardSession = (
    configuration: FoundationBoardSessionInput,
) => Promise<VerificationResult<TestedFoundationBoardSession>>;
type FoundationBoardCandidateObjectHash = (
    candidate: FoundationBoardCandidate,
) => Uint8Array;

const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const verifyBoardConsistency =
    publicApiRuntimeRecord.verifyBoardConsistency as VerifyBoardConsistency;
const createFoundationBoardSession =
    publicApiRuntimeRecord.createFoundationBoardSession as CreateFoundationBoardSession;
const foundationBoardCandidateObjectHash =
    publicApiRuntimeRecord.foundationBoardCandidateObjectHash as FoundationBoardCandidateObjectHash;
const requiredPublicFunctionNames = [
    'deriveThresholdParameters',
    'validatePollSpec',
    'deriveValidatedFirstValidOrder',
    'verifyBoardConsistency',
    'createFoundationBoardSession',
    'foundationBoardCandidateObjectHash',
] as const;

describe('election foundation public package API in browsers', () => {
    it('exposes callable safe runtime functions', () => {
        const runtimeExportNames = Object.keys(publicApiRuntimeRecord).sort();

        expect(runtimeExportNames).toEqual(
            expect.arrayContaining([...requiredPublicFunctionNames]),
        );
        for (const publicFunctionName of runtimeExportNames) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
    });

    it('runs a no-WASM board-consistency smoke path', () => {
        expect(
            verifyBoardConsistency({
                ceremonyId: 'ceremony',
                boardPolicyHash: 'policy',
                expectedBoardPublicKeyHash: 'board-key',
                signedBoardHeads: [],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
    });

    it('runs the canonical board boundary through packaged browser WASM', async () => {
        const authenticatedSetupIntent =
            createAuthenticatedSetupIntentTestVector();
        const opened = await createFoundationBoardSession({
            actionContextHash: new Uint8Array(64).fill(0x33),
            canonicalRosterBytes: authenticatedSetupIntent.canonicalRosterBytes,
            ceremonyContextHash: new Uint8Array(64).fill(0x22),
            limits: {
                maximumCarrierByteLength: 131_072,
                maximumCarrierCount: 32,
                maximumRetainedCarrierByteLength: 1_048_576,
                maximumUnresolvedDependencyCount: 128,
            },
            suiteIdentifier: new Uint8Array(64).fill(0x11),
        });
        expect(opened.isValid).toBe(true);
        if (!opened.isValid) {
            throw new Error(opened.refusalReason);
        }
        try {
            expect(opened.value.ingest(Uint8Array.from([0xff]))).toEqual({
                isValid: false,
                refusalReason: 'malformedEncoding',
            });
            const accepted = opened.value.ingest(
                authenticatedSetupIntent.canonicalCarrierBytes,
            );
            expect(accepted.isValid).toBe(true);
            if (!accepted.isValid) {
                throw new Error(accepted.refusalReason);
            }
            expect(foundationBoardCandidateObjectHash(accepted.value)).toEqual(
                authenticatedSetupIntent.objectHash,
            );
            expect(opened.value.requireCompleteCarrierGraph()).toEqual({
                isValid: true,
                value: undefined,
            });
        } finally {
            opened.value.cancel();
        }
        expect(
            publicApiRuntimeRecord.verifyFoundationTranscript,
        ).toBeUndefined();
        expect(publicApiRuntimeRecord.verifyTargetFinality).toBeUndefined();
    });
});
