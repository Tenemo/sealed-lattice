import { describe, expect, it } from 'vitest';

import {
    createDirectBallotSetupPackage,
    runDirectEncryptedBallot,
} from './direct-encrypted-ballot';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('direct encrypted ballot kernel command', () => {
    it('generates and verifies one full direct ballot proof through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const result = await runDirectEncryptedBallot({
            setupPackage,
        });

        expect(result.encryptedBallots.encryptedBallotHashes).toHaveLength(1);
        expect(result.encryptedBallots.ciphertextRoots).toHaveLength(1);
        expect(result.ballotValidityProofs).toHaveLength(1);
        const ballotValidityProof = result.ballotValidityProofs[0];
        expect(
            ballotValidityProof.proofTransport.chunkHashes.length,
        ).toBeGreaterThan(0);
        expect(
            ballotValidityProof.proofTransport.chunkHashes.every(
                (chunkHash) => chunkHash.length === 128,
            ),
        ).toBe(true);
        expect(
            new Set([
                ballotValidityProof.statementHash,
                ballotValidityProof.proofBytesHash,
                ballotValidityProof.proofTransport.chunkMerkleRoot,
                ballotValidityProof.proofTransport.publicTransportHash,
            ]).size,
        ).toBe(4);
        expect(result.aggregation.aggregateCiphertextRoot).toBe(
            result.encryptedBallots.ciphertextRoots[0],
        );
    });
});
