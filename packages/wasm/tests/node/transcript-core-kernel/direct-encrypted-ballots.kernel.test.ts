import { describe, expect, it } from 'vitest';

import {
    createDirectBallotInputs,
    createDirectBallotSetupPackage,
    runDirectEncryptedBallot,
} from './direct-encrypted-ballot';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type { BgvPassiveSetupPackage } from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';

describe('direct encrypted ballot kernel command', () => {
    it('requires explicit acknowledgement for caller-supplied deterministic randomness', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);

        expect(() =>
            runDirectEncryptedBallot({
                ballotEncryptionSeedHexes: ['11'.repeat(32)],
                setupPackage,
            }),
        ).toThrow(/requires developmentRandomnessOverrideAcknowledged/u);
        expect(() =>
            runDirectEncryptedBallot({
                ballotProofRandomnessHexes: ['22'.repeat(32)],
                setupPackage,
            }),
        ).toThrow(/requires developmentRandomnessOverrideAcknowledged/u);
    });

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

        expect(setupPackage).toMatchObject({
            objectType: 'BgvPassiveSetupPackage',
            setupMode: 'passive-full-roster-development',
        } satisfies Partial<BgvPassiveSetupPackage>);
    });

    it('rejects duplicate voter identities before proof generation through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const ballots = createDirectBallotInputs(2).map((ballot) => ({
            ...ballot,
            voterIdentity: 'duplicate-voter',
        }));

        await expect(
            runDirectEncryptedBallot({
                ballots,
                setupPackage,
            }),
        ).rejects.toThrow('duplicate voter identity');
    });

    it('rejects out-of-order voter identities before proof generation through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const ballots = [...createDirectBallotInputs(2)].reverse();

        await expect(
            runDirectEncryptedBallot({
                ballots,
                setupPackage,
            }),
        ).rejects.toThrow('deterministic voter identity order');
    });

    it('rejects invalid direct ballot scores before proof generation through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);
        const ballot = createDirectBallotInputs(1)[0];
        if (ballot === undefined) {
            throw new Error('direct ballot test input was not created.');
        }

        await expect(
            runDirectEncryptedBallot({
                ballots: [
                    {
                        ...ballot,
                        scores: ballot.scores.map((score, optionIndex) =>
                            optionIndex === 8 ? 11 : score,
                        ),
                    },
                ],
                setupPackage,
            }),
        ).rejects.toThrow('score at option 8');
    });

    it('rejects a mismatched setup witness seed before proof generation through Node/WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupPackage = createDirectBallotSetupPackage(kernel);

        await expect(
            runDirectEncryptedBallot({
                setupPackage,
                setupSeed: 'direct-encrypted-ballot-wrong-setup-seed',
            }),
        ).rejects.toThrow('private setup witness seed commitment');
    });
});
