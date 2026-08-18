import { describe, expect, it, vi } from 'vitest';

const installedVerification = vi.hoisted(() => ({
    useWrongSourceDigests: false,
}));

vi.mock('@sealed-lattice/wasm', async (importOriginal) => {
    const original =
        await importOriginal<typeof import('@sealed-lattice/wasm')>();
    return {
        ...original,
        verifyAcceptedSetupCompactPublicKeyShareInClosedWorker: vi.fn(
            async (input: {
                options?: {
                    openCheckpointCustody?: (
                        orderedSourceDigests: readonly Uint8Array[],
                    ) => Promise<{
                        checkpointCustody: {
                            publishAuthenticatedCheckpoint(
                                canonicalCheckpointBytes: Uint8Array,
                                safeBoundaryOrdinal: number,
                            ): Promise<void>;
                            release(): Promise<void>;
                            restoreAuthenticatedCheckpoint(): Promise<{
                                canonicalCheckpointBytes: Uint8Array;
                                safeBoundaryOrdinal: number;
                            }>;
                        };
                        mode: 'fresh' | 'resumed';
                    }>;
                };
            }) => {
                const openCheckpointCustody =
                    input.options?.openCheckpointCustody;
                if (openCheckpointCustody === undefined) {
                    throw new Error(
                        'The installed verifier received no worker-owned checkpoint opener.',
                    );
                }
                const sourceSeed = installedVerification.useWrongSourceDigests
                    ? 0x91
                    : 0x31;
                const orderedSourceDigests = Object.freeze(
                    Array.from({ length: 4 }, (_unused, digestIndex) =>
                        new Uint8Array(64).fill(sourceSeed + digestIndex),
                    ),
                );
                const opened =
                    await openCheckpointCustody(orderedSourceDigests);
                try {
                    if (opened.mode === 'fresh') {
                        await opened.checkpointCustody.publishAuthenticatedCheckpoint(
                            new Uint8Array(404).fill(0x57),
                            291,
                        );
                        throw new Error(
                            'Injected operation interruption after an authenticated checkpoint.',
                        );
                    }
                    const restored =
                        await opened.checkpointCustody.restoreAuthenticatedCheckpoint();
                    if (
                        restored.safeBoundaryOrdinal !== 291 ||
                        restored.canonicalCheckpointBytes.byteLength !== 404 ||
                        restored.canonicalCheckpointBytes.some(
                            (byte) => byte !== 0x57,
                        )
                    ) {
                        restored.canonicalCheckpointBytes.fill(0);
                        throw new Error(
                            'The installed worker restored a different authenticated checkpoint.',
                        );
                    }
                    restored.canonicalCheckpointBytes.fill(0);
                    await opened.checkpointCustody.publishAuthenticatedCheckpoint(
                        new Uint8Array(404).fill(0x68),
                        292,
                    );
                    return Object.freeze({ isValid: true, value: undefined });
                } finally {
                    await opened.checkpointCustody.release();
                }
            },
        ),
    };
});

import { openSameRealmCommonProofApplicationHost } from './common-proof-worker-runtime/custody-fixtures.js';
import { createMockKernelRuntime } from './common-proof-worker-runtime/kernel-fixtures.js';

import {
    verifyAcceptedSetupCompactPublicKeyShareInInstalledCustodyWorker,
    type InstalledAcceptedSetupCompactPublicKeyCheckpointDescription,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const createAcceptedCheckpointGeometryKernel = (): TranscriptCoreKernel => {
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    registerCommonProofKernelContext(
        kernel,
        createMockKernelRuntime(() => ({
            sealed_lattice_accepted_setup_compact_public_key_verification_checkpoint_byte_length:
                () => 404,
            sealed_lattice_accepted_setup_compact_public_key_verification_safe_boundary_count:
                () => 4_509,
        })),
    );
    return kernel;
};

describe('Installed accepted-setup compact public-key checkpoint custody', () => {
    it('publishes, authenticates source digests, and resumes through the worker host', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        const publishedCheckpoints: Array<{
            checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
            safeBoundaryOrdinal: number;
        }> = [];
        const verificationInput = {
            assembly: Object.freeze({}),
            canonicalApplicationStatementBytes: Uint8Array.of(1),
            canonicalProofBytes: Uint8Array.of(2),
            canonicalPublicInputBytes: Uint8Array.of(3),
            kernel: createAcceptedCheckpointGeometryKernel(),
            onCheckpointPublished: (description: {
                checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
                safeBoundaryOrdinal: number;
            }) => {
                publishedCheckpoints.push({
                    checkpointLineageIdentifier:
                        description.checkpointLineageIdentifier.slice(),
                    safeBoundaryOrdinal: description.safeBoundaryOrdinal,
                });
            },
        };
        try {
            await expect(
                verifyAcceptedSetupCompactPublicKeyShareInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        ...verificationInput,
                        checkpoint: { mode: 'fresh' },
                    } as never,
                ),
            ).rejects.toThrow(/operation interruption/u);
            expect(publishedCheckpoints).toHaveLength(1);
            expect(publishedCheckpoints[0]?.safeBoundaryOrdinal).toBe(291);

            const resumeDescription = publishedCheckpoints[0];
            if (resumeDescription === undefined) {
                throw new Error(
                    'The fresh worker did not expose an authenticated resume boundary.',
                );
            }
            installedVerification.useWrongSourceDigests = true;
            await expect(
                verifyAcceptedSetupCompactPublicKeyShareInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        ...verificationInput,
                        checkpoint: {
                            checkpointLineageIdentifier:
                                resumeDescription.checkpointLineageIdentifier,
                            mode: 'resumed',
                            safeBoundaryOrdinal:
                                resumeDescription.safeBoundaryOrdinal,
                        },
                    } as never,
                ),
            ).rejects.toMatchObject({ code: 'AuthenticationFailed' });

            installedVerification.useWrongSourceDigests = false;
            await expect(
                verifyAcceptedSetupCompactPublicKeyShareInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        ...verificationInput,
                        checkpoint: {
                            checkpointLineageIdentifier:
                                resumeDescription.checkpointLineageIdentifier,
                            mode: 'resumed',
                            safeBoundaryOrdinal:
                                resumeDescription.safeBoundaryOrdinal,
                        },
                    } as never,
                ),
            ).resolves.toEqual({ isValid: true, value: undefined });
            expect(
                publishedCheckpoints.map(
                    ({ safeBoundaryOrdinal }) => safeBoundaryOrdinal,
                ),
            ).toEqual([291, 292]);
            const terminalDescription = publishedCheckpoints[1];
            if (terminalDescription === undefined) {
                throw new Error(
                    'The resumed worker did not expose its terminal authenticated checkpoint.',
                );
            }
            await expect(
                verifyAcceptedSetupCompactPublicKeyShareInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        ...verificationInput,
                        checkpoint: {
                            checkpointLineageIdentifier:
                                terminalDescription.checkpointLineageIdentifier,
                            mode: 'resumed',
                            safeBoundaryOrdinal:
                                terminalDescription.safeBoundaryOrdinal,
                        },
                    } as never,
                ),
            ).rejects.toMatchObject({ code: 'MissingRecord' });
        } finally {
            installedVerification.useWrongSourceDigests = false;
            for (const checkpoint of publishedCheckpoints) {
                checkpoint.checkpointLineageIdentifier.fill(0);
            }
            await host.close();
        }
    });

    it('evicts a durable checkpoint when its resume coordinate cannot be reported', async () => {
        const host = await openSameRealmCommonProofApplicationHost();
        let unreportedCheckpoint:
            | {
                  checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
                  safeBoundaryOrdinal: number;
              }
            | undefined;
        const verificationInput = {
            assembly: Object.freeze({}),
            canonicalApplicationStatementBytes: Uint8Array.of(1),
            canonicalProofBytes: Uint8Array.of(2),
            canonicalPublicInputBytes: Uint8Array.of(3),
            kernel: createAcceptedCheckpointGeometryKernel(),
        };
        try {
            await expect(
                verifyAcceptedSetupCompactPublicKeyShareInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        ...verificationInput,
                        checkpoint: { mode: 'fresh' },
                        onCheckpointPublished: (
                            description: InstalledAcceptedSetupCompactPublicKeyCheckpointDescription,
                        ) => {
                            unreportedCheckpoint = {
                                checkpointLineageIdentifier:
                                    description.checkpointLineageIdentifier.slice(),
                                safeBoundaryOrdinal:
                                    description.safeBoundaryOrdinal,
                            };
                            throw new Error(
                                'Injected checkpoint notification failure.',
                            );
                        },
                    } as never,
                ),
            ).rejects.toThrow(/notification failure/u);
            if (unreportedCheckpoint === undefined) {
                throw new Error(
                    'The notification failure did not retain its test-only checkpoint description.',
                );
            }
            await expect(
                verifyAcceptedSetupCompactPublicKeyShareInInstalledCustodyWorker(
                    host.installedHost,
                    {
                        ...verificationInput,
                        checkpoint: {
                            checkpointLineageIdentifier:
                                unreportedCheckpoint.checkpointLineageIdentifier,
                            mode: 'resumed',
                            safeBoundaryOrdinal:
                                unreportedCheckpoint.safeBoundaryOrdinal,
                        },
                    } as never,
                ),
            ).rejects.toMatchObject({ code: 'MissingRecord' });
        } finally {
            unreportedCheckpoint?.checkpointLineageIdentifier.fill(0);
            await host.close();
        }
    });
});
