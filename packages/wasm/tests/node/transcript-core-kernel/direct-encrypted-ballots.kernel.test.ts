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

        expect(result.input.ballotCount).toBe(1);
        expect(result.ballotLayout.optionCount).toBe(20);
        expect(result.parameters.dataPrimeCount).toBe(17);
        expect(result.proofAttempt).toMatchObject({
            proofCount: 1,
            rnsLimbCount: 17,
        });
        expect(result.encryptedBallots.encryptedBallotHashes).toHaveLength(1);
        expect(result.encryptedBallots.ciphertextRoots).toHaveLength(1);
        expect(
            result.encryptedBallots.ciphertextCanonicalByteLengths[0],
        ).toBeGreaterThan(0);
        expect(result.proofAttempt.proofSizeBytes).toBeGreaterThan(0);
        expect(result.proofAttempt.totalProofBytes).toBe(
            result.proofAttempt.proofSizeBytes,
        );
        expect(result.aggregation.ballotCount).toBe(1);
        expect(result.aggregation.aggregateCiphertextRoot).toHaveLength(128);
        expect(
            result.aggregation.aggregateCiphertextCanonicalByteLength,
        ).toBeGreaterThan(0);
    });
});
