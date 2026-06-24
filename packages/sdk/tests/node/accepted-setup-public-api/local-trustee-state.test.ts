import { describe, expect, it } from 'vitest';

import {
    loadPublicTranscriptCoreKernel,
    localStateInput,
    publicSetupApi,
    setupContextFromKernel,
    trusteeIdentity,
    trusteeRosterPosition,
} from './support.js';

describe('accepted setup public package API in Node', () => {
    it('exports encrypted local trustee state and restores only a sealed payload', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const exportedState =
            await publicSetupApi.exportEncryptedLocalTrusteeSetupState(
                localStateInput(kernel, setupContext),
            );

        expect(exportedState).not.toHaveProperty('localStatePlaintext');
        expect(exportedState).not.toHaveProperty('localStatePlaintextHash');
        expect(exportedState.sealedLocalStatePayloadHash).toMatch(
            /^[0-9a-f]{128}$/u,
        );
        expect(JSON.stringify(exportedState.localStateCommitment)).not.toMatch(
            /shareValues|privateEnvelope|coefficientMessage/u,
        );
        expect(exportedState.encryptedLocalState).toMatchObject({
            objectType: 'EncryptedLocalTrusteeSetupState',
            localStateRoot: (
                exportedState.localStateCommitment as Record<string, unknown>
            ).localStateRoot,
        });

        const restoredState =
            await publicSetupApi.restoreLocalTrusteeSetupState({
                encryptedLocalState: exportedState.encryptedLocalState,
                localStateCommitment: exportedState.localStateCommitment,
                setupContext,
                storageKeyBytesHex: '41'.repeat(32),
                expectedTrusteeIdentity: trusteeIdentity,
                expectedTrusteeRosterPosition: trusteeRosterPosition,
                expectedDeviceEpoch: 2,
                minimumDeviceEpoch: 2,
                expectedAggregateThresholdShareRoot: (
                    exportedState.localStateCommitment as Record<
                        string,
                        unknown
                    >
                ).aggregateThresholdShareRoot,
                expectedThresholdShareCommitmentRecipientRoot: (
                    exportedState.localStateCommitment as Record<
                        string,
                        unknown
                    >
                ).thresholdShareCommitmentRecipientRoot,
                expectedIssuedVssAcceptanceRoot: (
                    exportedState.localStateCommitment as Record<
                        string,
                        unknown
                    >
                ).issuedVssAcceptanceRoot,
            });

        expect(restoredState).toMatchObject({
            ok: true,
            operation: 'restoreLocalTrusteeSetupState',
            localStateVerification: {
                ok: true,
                operation: 'verifyLocalTrusteeSetupState',
                localStateRoot: (
                    exportedState.localStateCommitment as Record<
                        string,
                        unknown
                    >
                ).localStateRoot,
            },
        });
        expect(restoredState).not.toHaveProperty('localStatePlaintext');
        expect(restoredState).not.toHaveProperty('localStatePlaintextHash');
        expect(restoredState.sealedLocalStatePayloadHash).toBe(
            exportedState.sealedLocalStatePayloadHash,
        );
        expect(
            JSON.stringify(restoredState.sealedLocalStatePayload),
        ).not.toMatch(/shareValues|rawShare|coefficientMessage/u);
    });

    it('rejects incomplete export input and stale restored device state', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const exportInput = localStateInput(kernel, setupContext);

        await expect(
            publicSetupApi.exportEncryptedLocalTrusteeSetupState({
                ...exportInput,
                verifiedPrivateVssShareEnvelopes: [],
            }),
        ).rejects.toThrow(/must include the private envelope/u);

        const exportedState =
            await publicSetupApi.exportEncryptedLocalTrusteeSetupState(
                exportInput,
            );

        await expect(
            publicSetupApi.restoreLocalTrusteeSetupState({
                encryptedLocalState: exportedState.encryptedLocalState,
                localStateCommitment: exportedState.localStateCommitment,
                setupContext,
                storageKeyBytesHex: '41'.repeat(32),
                expectedTrusteeIdentity: trusteeIdentity,
                expectedTrusteeRosterPosition: trusteeRosterPosition,
                minimumDeviceEpoch: 3,
            }),
        ).rejects.toThrow(/older than the minimum accepted device epoch/u);
    });
});
