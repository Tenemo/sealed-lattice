import { describe, expect, it, vi } from 'vitest';

import {
    generateCompactPublicKeyReferenceInClosedWorker,
    openBrowserOwnedSetupGenerationAuthorityInClosedWorker,
} from '#packages/wasm/src/index';
import { openCompactPublicKeyProductionGenerationFixture } from '#packages/wasm/tests/support/compact-public-key-production-generation-fixture';

describe('Compact public-key reference generation from production sources in real scalar WASM', () => {
    it('enters exact source loading without suite authority and retires on bounded cancellation', async () => {
        const fixture = await openCompactPublicKeyProductionGenerationFixture();
        const cancellationController = new AbortController();
        const openExternalMemory = vi.fn();
        let yieldedTurnCount = 0;
        try {
            await expect(
                openBrowserOwnedSetupGenerationAuthorityInClosedWorker({
                    canonicalSuiteRecordBytes:
                        fixture.canonicalSuiteRecordBytes,
                    kernel: fixture.kernel,
                    orderedPublicRandomnessCommitmentObjects:
                        fixture.orderedPublicRandomnessCommitmentObjects,
                    orderedPublicRandomnessRevealObjects:
                        fixture.orderedPublicRandomnessRevealObjects,
                    orderedSetupIntentObjects:
                        fixture.orderedSetupIntentObjects,
                    productionOperationIdentifiers:
                        fixture.productionOperationIdentifiers,
                    workerKernel: fixture.workerKernel,
                }),
            ).rejects.toMatchObject({
                name: 'FoundationBootstrapRefusalError',
                refusalReason: 'unsupportedVersionOrSuite',
            });
            await expect(
                generateCompactPublicKeyReferenceInClosedWorker({
                    checkpointLineageIdentifier: new Uint8Array(32).fill(0x71),
                    kernel: fixture.kernel,
                    maximumWorkUnitCountPerPoll: 1,
                    openExternalMemory,
                    orderedPublicRandomnessCommitmentObjects:
                        fixture.orderedPublicRandomnessCommitmentObjects,
                    orderedPublicRandomnessRevealObjects:
                        fixture.orderedPublicRandomnessRevealObjects,
                    orderedSetupIntentObjects:
                        fixture.orderedSetupIntentObjects,
                    productionOperationIdentifiers:
                        fixture.productionOperationIdentifiers,
                    setupIntentObject: fixture.setupIntentObject,
                    signal: cancellationController.signal,
                    workerKernel: fixture.workerKernel,
                    yieldControl: () => {
                        yieldedTurnCount += 1;
                        cancellationController.abort(
                            'focused reference cancellation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({
                name: 'CanonicalStreamCancellationError',
            });
            expect(yieldedTurnCount).toBe(1);
            expect(openExternalMemory).not.toHaveBeenCalled();
        } finally {
            await fixture.close();
        }
    });
});
