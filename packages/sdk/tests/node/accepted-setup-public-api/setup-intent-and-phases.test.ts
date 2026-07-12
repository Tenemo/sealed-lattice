import { describe, expect, it } from 'vitest';

import {
    hashFromKernel,
    loadPublicTranscriptCoreKernel,
    publicSetupApi,
    setupContextFromKernel,
    setupIntentSigner,
    trusteeIdentity,
    trusteeRosterPosition,
} from './support.js';

describe('accepted setup public package API in Node', () => {
    it('creates signed setup intent objects and deterministic setup phase records', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const { keyFixture, signRoot } = setupIntentSigner(
            'accepted-setup-public-api-intent',
        );
        const mailboxPublicKeyHash = hashFromKernel(kernel, 'mailbox-key');
        const mailboxPublicKeyBytesHash = hashFromKernel(
            kernel,
            'mailbox-key-bytes',
        );

        const setupIntent = await publicSetupApi.createSetupIntent({
            setupContext,
            trusteeIdentity,
            rosterPosition: trusteeRosterPosition,
            recoveryEpoch: 0,
            deviceEpoch: 2,
            signingPublicKeyHash: keyFixture.publicKeyHash,
            privateVssMailboxPublicKeyHash: mailboxPublicKeyHash,
            privateVssMailboxPublicKeyBytesHash: mailboxPublicKeyBytesHash,
            signRoot,
        });
        const setupIntentPhase = publicSetupApi.createSetupPhaseRecord({
            setupContext,
            phaseId: 'setupIntent',
            phaseNumber: 2,
            previousPhaseRoot: null,
            participantPhaseObjects: [setupIntent],
        });

        expect(setupIntent).toMatchObject({
            objectType: 'SetupPhaseParticipantObject',
            phaseId: 'setupIntent',
            phaseNumber: 2,
            trusteeIdentity,
            rosterPosition: trusteeRosterPosition,
            privateVssMailboxPublicKeyHash: mailboxPublicKeyHash,
            privateVssMailboxPublicKeyBytesHash: mailboxPublicKeyBytesHash,
            signingPublicKeyHash: keyFixture.publicKeyHash,
        });
        expect(String(setupIntent.phaseObjectRoot)).toHaveLength(128);
        expect(String(setupIntent.signatureEnvelopeHash)).toBe(
            String(
                (setupIntent.signatureEnvelope as Record<string, unknown>)
                    .signatureHash,
            ),
        );
        expect(setupIntentPhase).toMatchObject({
            phaseId: 'setupIntent',
            phaseNumber: 2,
            previousPhaseRoot: null,
            participantPhaseObjects: [setupIntent],
        });
        expect(String(setupIntentPhase.phaseRoot)).toHaveLength(128);
    });

    it('assembles full-roster common randomness and refuses stale commit bindings', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const revealRecords: Record<string, unknown>[] = [];
        const commitRecords: Record<string, unknown>[] = [];
        for (let rosterPosition = 0; rosterPosition < 10; rosterPosition += 1) {
            const recordTrusteeIdentity = `trustee-${String(rosterPosition)}`;
            const { keyFixture, signRoot } = setupIntentSigner(
                `common-randomness-${String(rosterPosition)}`,
            );
            const revealRecord =
                await publicSetupApi.createCommonRandomnessReveal({
                    setupContext,
                    trusteeIdentity: recordTrusteeIdentity,
                    rosterPosition,
                    recoveryEpoch: 0,
                    deviceEpoch: 2,
                    signingPublicKeyHash: keyFixture.publicKeyHash,
                    signRoot,
                    revealHex: hashFromKernel(
                        kernel,
                        `common-randomness-reveal-${String(rosterPosition)}`,
                    ).slice(0, 64),
                });
            revealRecords.push(revealRecord);
            commitRecords.push(
                await publicSetupApi.createCommonRandomnessCommit({
                    setupContext,
                    trusteeIdentity: recordTrusteeIdentity,
                    rosterPosition,
                    recoveryEpoch: 0,
                    deviceEpoch: 2,
                    signingPublicKeyHash: keyFixture.publicKeyHash,
                    signRoot,
                    revealHash: revealRecord.revealHash,
                }),
            );
        }

        const commonRandomness =
            await publicSetupApi.createSetupCommonRandomness({
                setupContext,
                commitRecords: [...commitRecords].reverse(),
                revealRecords: [...revealRecords].reverse(),
            });

        expect(commonRandomness).toMatchObject({
            objectType: 'SetupCommonRandomness',
            setupParametersHash: setupContext.setupParametersHash,
            publicDerivations: {
                objectType: 'SetupPublicDerivations',
                publicMatrixSeedHash: String(
                    commonRandomness.publicMatrixSeedHash,
                ),
            },
        });
        expect(commonRandomness.commitRecords).toEqual(
            expect.arrayContaining([commitRecords[0]]),
        );
        expect(commonRandomness.revealRecords).toEqual(
            expect.arrayContaining([revealRecords[0]]),
        );
        expect(
            commonRandomness.commitRecords.map(
                (commitRecord) => commitRecord.rosterPosition,
            ),
        ).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        expect(String(commonRandomness.commonRandomnessRoot)).toHaveLength(128);
        expect(JSON.stringify(commonRandomness)).not.toMatch(
            /setupSeed|shareValues|coefficientMessage|randomnessByColumn/u,
        );

        const staleSigner = setupIntentSigner('common-randomness-stale');
        const staleCommit = await publicSetupApi.createCommonRandomnessCommit({
            setupContext,
            trusteeIdentity,
            rosterPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 2,
            signingPublicKeyHash: staleSigner.keyFixture.publicKeyHash,
            signRoot: staleSigner.signRoot,
            revealHash: revealRecords[1]?.revealHash,
        });

        await expect(
            publicSetupApi.createSetupCommonRandomness({
                setupContext,
                commitRecords: [staleCommit, ...commitRecords.slice(1)],
                revealRecords,
            }),
        ).rejects.toThrow(/must match the reveal record/u);
        await expect(
            publicSetupApi.createSetupCommonRandomness({
                setupContext,
                commitRecords: commitRecords.slice(1),
                revealRecords: revealRecords.slice(1),
            }),
        ).rejects.toThrow(/one record per participant/u);
    });
});
