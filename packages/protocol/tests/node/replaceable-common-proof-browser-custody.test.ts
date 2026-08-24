import { describe, expect, it } from 'vitest';

import type { CommonProofBrowserCustody } from '#packages/protocol/src/runtime/common-proof-browser-custody';
import { createReplaceableCommonProofBrowserCustody } from '#packages/protocol/tests/support/replaceable-common-proof-browser-custody';

const controlledCustody = (input: {
    events: string[];
    label: string;
    suspendFailure?: Error;
    withCheckpointCustody?: boolean;
}): CommonProofBrowserCustody => {
    const recordEvent = (operation: string): void => {
        input.events.push(`${input.label}:${operation}`);
    };
    return Object.freeze({
        armApplicationHandoff: () => {
            recordEvent('arm');
            return Promise.resolve({
                canonicalMarkerRecordBytes: Uint8Array.of(1),
                logicalRecordKey: `${input.label}-handoff`,
            });
        },
        ...(input.withCheckpointCustody === false
            ? {}
            : {
                  checkpointCustody: Object.freeze({
                      publishAuthenticatedCheckpoint: () => {
                          recordEvent('publish-checkpoint');
                          return Promise.resolve();
                      },
                      restoreAuthenticatedCheckpoint: () => {
                          recordEvent('restore-checkpoint');
                          return Promise.resolve(
                              Object.freeze({
                                  canonicalStateBytes: Uint8Array.of(2),
                                  generationCursorManifestBytes:
                                      Uint8Array.of(3),
                              }),
                          );
                      },
                  }),
              }),
        completeVerifiedOutput: () => {
            recordEvent('complete');
            return Promise.resolve();
        },
        copyPhysicalStorageAccounting: () => {
            recordEvent('copy-accounting');
            throw new Error('Synthetic accounting snapshot is unavailable.');
        },
        copyCheckpointResumeDescriptor: () => {
            recordEvent('copy-resume');
            return undefined;
        },
        externalMemory: Object.freeze({
            executeTransaction: () => {
                recordEvent('external-memory');
                return Promise.resolve([]);
            },
        }),
        prefixReplayExternalMemory: Object.freeze({
            confirmAuthenticatedCheckpointExternalMemoryState: () => {
                recordEvent('confirm-prefix-replay');
            },
            executeDeterministicPrefixReplayTransaction: () => {
                recordEvent('prefix-replay');
                return Promise.resolve([]);
            },
        }),
        outputStore: Object.freeze({
            commitChunk: () => {
                recordEvent('commit-output');
                return Promise.resolve();
            },
            readChunk: () => {
                recordEvent('read-output');
                return Promise.resolve(Uint8Array.of(3));
            },
        }),
        authenticatedOutput: () => {
            recordEvent('authenticated-output');
            return Object.freeze({
                declaredByteLength: 1,
                readCommittedChunk: () => Promise.resolve(Uint8Array.of(3)),
            });
        },
        releaseExternalMemory: () => {
            recordEvent('release-external-memory');
            return Promise.resolve();
        },
        retire: () => {
            recordEvent('retire');
            return Promise.resolve();
        },
        sealCanonicalOutput: () => recordEvent('seal-output'),
        suspendForAuthenticatedResume: () => {
            recordEvent('suspend');
            return input.suspendFailure === undefined
                ? Promise.resolve()
                : Promise.reject(input.suspendFailure);
        },
    });
};

describe('Replaceable common-proof browser custody', () => {
    it('routes every checkpoint and proof operation to the current storage authority', async () => {
        const events: string[] = [];
        const freshCustody = controlledCustody({
            events,
            label: 'fresh',
        });
        const resumedCustody = controlledCustody({
            events,
            label: 'resumed',
        });
        const replaceable =
            createReplaceableCommonProofBrowserCustody(freshCustody);

        await replaceable.custody.checkpointCustody?.publishAuthenticatedCheckpoint(
            {} as never,
        );
        await replaceable.custody.outputStore.commitChunk(0, Uint8Array.of(4));
        await replaceable.custody.suspendForAuthenticatedResume();
        replaceable.replaceAfterAuthenticatedSuspension(resumedCustody);
        await replaceable.custody.checkpointCustody?.restoreAuthenticatedCheckpoint();
        await replaceable.custody.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
            {} as never,
        );
        replaceable.custody.prefixReplayExternalMemory.confirmAuthenticatedCheckpointExternalMemoryState();
        replaceable.custody.sealCanonicalOutput();
        replaceable.custody.authenticatedOutput();
        await replaceable.custody.completeVerifiedOutput();

        expect(replaceable.currentCustody()).toBe(resumedCustody);
        expect(events).toEqual([
            'fresh:publish-checkpoint',
            'fresh:commit-output',
            'fresh:suspend',
            'resumed:restore-checkpoint',
            'resumed:prefix-replay',
            'resumed:confirm-prefix-replay',
            'resumed:seal-output',
            'resumed:authenticated-output',
            'resumed:complete',
        ]);
    });

    it('permits replacement only after a successful suspension and only with a new checkpoint custody', async () => {
        const events: string[] = [];
        const freshCustody = controlledCustody({ events, label: 'fresh' });
        const resumedCustody = controlledCustody({ events, label: 'resumed' });
        const replaceable =
            createReplaceableCommonProofBrowserCustody(freshCustody);

        expect(() =>
            replaceable.replaceAfterAuthenticatedSuspension(resumedCustody),
        ).toThrow('only after authenticated suspension');
        await replaceable.custody.suspendForAuthenticatedResume();
        expect(() =>
            replaceable.replaceAfterAuthenticatedSuspension(freshCustody),
        ).toThrow('must be a new storage authority');
        expect(() =>
            replaceable.replaceAfterAuthenticatedSuspension(
                controlledCustody({
                    events,
                    label: 'missing-checkpoint',
                    withCheckpointCustody: false,
                }),
            ),
        ).toThrow('requires authenticated checkpoint custody');
        replaceable.replaceAfterAuthenticatedSuspension(resumedCustody);
        expect(() =>
            replaceable.replaceAfterAuthenticatedSuspension(freshCustody),
        ).toThrow('only after authenticated suspension');
    });

    it('does not unlock replacement when authenticated suspension fails', async () => {
        const events: string[] = [];
        const suspensionFailure = new Error('checkpoint persistence failed');
        const replaceable = createReplaceableCommonProofBrowserCustody(
            controlledCustody({
                events,
                label: 'fresh',
                suspendFailure: suspensionFailure,
            }),
        );

        await expect(
            replaceable.custody.suspendForAuthenticatedResume(),
        ).rejects.toBe(suspensionFailure);
        expect(() =>
            replaceable.replaceAfterAuthenticatedSuspension(
                controlledCustody({ events, label: 'resumed' }),
            ),
        ).toThrow('only after authenticated suspension');
        expect(events).toEqual(['fresh:suspend']);
    });
});
