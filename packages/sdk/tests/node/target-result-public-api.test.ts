import { describe, expect, it, vi } from 'vitest';

describe('target-result public package API', () => {
    it('drives the staged kernel release session and returns the verified target result', async () => {
        vi.resetModules();
        const releaseSetupContext = {
            objectType: 'BgvTargetDecryptionReleaseSetupContext',
            releaseSetupContextHash: 'release-setup-hash',
        };
        const shareEvidence = [
            {
                trusteeIdentity: 'trustee-1',
                rosterPosition: 0,
                interpolationPoint: 1,
                targetDecryptionShareHash: 'share-hash',
                proofStatementRoot: 'statement-root',
                proofMaterialRoot: 'proof-root',
            },
        ];
        const calls: string[] = [];
        const kernel = {
            deriveBgvTargetDecryptionResultReleaseSetupContext: vi.fn(
                (input: Record<string, unknown>) => {
                    calls.push('derive');
                    expect(input.setupPackage).toEqual({
                        objectType: 'SetupPackage',
                    });

                    return releaseSetupContext;
                },
            ),
            beginBgvTargetDecryptionResultRelease: vi.fn(
                (input: Record<string, unknown>) => {
                    calls.push('begin');
                    expect(input.releaseSetupContext).toBe(releaseSetupContext);
                    expect(input.targetAcceptedRecord).toEqual({
                        target: 'accepted',
                    });

                    return { ok: true };
                },
            ),
            absorbBgvTargetDecryptionResultReleaseShare: vi.fn(
                (input: Record<string, unknown>) => {
                    calls.push('absorb');
                    expect(input.targetShareProof).toEqual({
                        targetDecryptionShare: { share: 'value' },
                        proofStatement: { statement: 'value' },
                        proofMaterial: { proof: 'value' },
                    });

                    return { ok: true };
                },
            ),
            finishBgvTargetDecryptionResultRelease: vi.fn(
                (input: Record<string, unknown>) => {
                    calls.push('finish');
                    expect(input.releaseVerificationId).toEqual(
                        expect.stringMatching(/^sdk-target-result-release-/u),
                    );

                    return {
                        ok: true,
                        targetResultHash: 'target-result-hash',
                        targetIdByOption: [4, 8],
                        targetOrderByOption: [1, 0],
                        topCount: 1,
                        shareEvidence,
                    };
                },
            ),
        };
        vi.doMock('../../dist/kernel.js', () => ({
            loadTranscriptCoreKernel: () => Promise.resolve(kernel),
        }));

        const publicPackage = await import('../../dist/index.js');
        const setupPackage = {
            objectType: 'SetupPackage',
        } as unknown as Parameters<
            typeof publicPackage.verifyTargetDecryptionResult
        >[0]['setupPackage'];
        const verification = await publicPackage.verifyTargetDecryptionResult({
            setupPackage,
            targetAcceptedRecord: { target: 'accepted' },
            targetCiphertextBinding: { binding: 'value' },
            targetCiphertexts: { ciphertexts: 'value' },
            targetShareProfile: { profile: 'value' },
            targetShareProofs: [
                {
                    targetDecryptionShare: { share: 'value' },
                    proofStatement: { statement: 'value' },
                    proofMaterial: { proof: 'value' },
                },
            ],
        });

        expect(calls).toEqual(['derive', 'begin', 'absorb', 'finish']);
        expect(verification).toEqual({
            ok: true,
            operation: 'verifyTargetDecryptionResult',
            verifierStatus: 'accepted',
            acceptedResult: {
                targetResultHash: 'target-result-hash',
                targetIdByOption: [4, 8],
                targetOrderByOption: [1, 0],
                topCount: 1,
                shareEvidence,
            },
        });
    });
});
