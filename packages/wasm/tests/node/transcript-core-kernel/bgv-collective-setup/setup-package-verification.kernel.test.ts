import { describe, expect, it } from 'vitest';

import { setupRequest } from '../bgv-passive-setup-fixtures.js';

import {
    acceptedShapedSetupPackage,
    acceptedVssComplaintSet,
    rebindCollectiveSetupPackageHash,
} from './accepted-setup-package-fixtures.js';
import { type JsonRecord } from './setup-fixture-primitives.js';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
    it('classifies passive setup packages as outside parameters', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const passiveSetup = kernel.generateBgvPassiveSetup(setupRequest);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage: passiveSetup,
        });

        expect(result).toMatchObject({
            isValid: false,
            operation: 'verifyCollectiveBgvSetupPackage',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'outsideCollectiveBgvSetupParameters',
        );
    });

    it('maps malformed accepted setup command errors to neutral protocol errors', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() => {
            kernel.verifyCollectiveBgvSetup({
                setupPackage: undefined,
            });
        }).toThrow(TranscriptCoreKernelCommandError);

        let thrownError: unknown;
        try {
            kernel.verifyCollectiveBgvSetup({
                setupPackage: undefined,
            });
            throw new Error('verifyCollectiveBgvSetup should have failed.');
        } catch (error) {
            thrownError = error;
        }
        expect(thrownError).toBeInstanceOf(TranscriptCoreKernelCommandError);
        const commandError = thrownError as TranscriptCoreKernelCommandError;
        expect(commandError.code).toBe('InvalidProtocolObject');
        expect(commandError.message).not.toContain('InvalidFixture');
        expect(commandError.message).toContain('setupPackage is required');
    });

    it('refuses malformed setup context before reporting missing prerequisites', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });

        for (const [fieldName, malformedValue] of [
            ['setupEpoch', 'setup-epoch 1'],
            ['ceremonyId', 'ceremony-1\nfork'],
        ] as const) {
            const setupPackage = await acceptedShapedSetupPackage(
                kernel,
                parameters,
            );
            const setupContext = setupPackage.setupContext as JsonRecord;
            setupContext[fieldName] = malformedValue;
            delete setupPackage.phaseTranscript;
            rebindCollectiveSetupPackageHash(kernel, setupPackage);

            const result = kernel.verifyCollectiveBgvSetup({
                setupPackage,
                expectedManifestHash: setupRequest.manifestHash,
                expectedRosterHash: String(
                    (setupPackage.setupContext as JsonRecord).rosterHash,
                ),
            });

            expect(result.isValid).toBe(false);
            expect(result.refusedObjects[0]).toMatchObject({
                reasonCode: 'setupContextTokenMalformed',
                objectPath: `setupPackage.setupContext.${fieldName}`,
            });
        }
    });

    it('aborts accepted-shaped setup on a protocol-built VSS complaint', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });
        const setupPackage = await acceptedShapedSetupPackage(
            kernel,
            parameters,
        );
        setupPackage.vssComplaints = await acceptedVssComplaintSet(
            setupPackage.setupContext as JsonRecord,
            setupPackage.privateVssEnvelopeCommitments as JsonRecord,
        );
        rebindCollectiveSetupPackageHash(kernel, setupPackage);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: String(
                (setupPackage.setupContext as JsonRecord).rosterHash,
            ),
        });

        expect(result.isValid).toBe(false);
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'vssComplaintAcceptedAbort',
        );
    });
});
