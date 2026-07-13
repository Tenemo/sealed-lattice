import type { VerificationResult } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

import type {
    FoundationBoardCandidate,
    FoundationBoardSessionInput,
} from '#packages/sdk/src/index';
import { createAuthenticatedComplaintTestVector } from '#packages/wasm/tests/foundation-board-test-vectors';

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
const createFoundationBoardSession =
    publicApiRuntimeRecord.createFoundationBoardSession as CreateFoundationBoardSession;
const foundationBoardCandidateObjectHash =
    publicApiRuntimeRecord.foundationBoardCandidateObjectHash as FoundationBoardCandidateObjectHash;

describe('election foundation public package API in browsers', () => {
    it('runs an authenticated complaint carrier through packaged browser WASM', async () => {
        const authenticatedComplaint = createAuthenticatedComplaintTestVector();
        const opened = await createFoundationBoardSession({
            actionContextHash: new Uint8Array(64).fill(0x33),
            canonicalRosterBytes: authenticatedComplaint.canonicalRosterBytes,
            ceremonyContextHash: new Uint8Array(64).fill(0x22),
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
                authenticatedComplaint.canonicalCarrierBytes,
            );
            expect(accepted.isValid).toBe(true);
            if (!accepted.isValid) {
                throw new Error(accepted.refusalReason);
            }
            expect(foundationBoardCandidateObjectHash(accepted.value)).toEqual(
                authenticatedComplaint.objectHash,
            );
            expect(opened.value.requireCompleteCarrierGraph()).toEqual({
                isValid: true,
                value: undefined,
            });
        } finally {
            opened.value.cancel();
        }
    });
});
