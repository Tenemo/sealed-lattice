import {
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities,
    openAuthenticatedMailboxFrozenRoster,
} from '@sealed-lattice/crypto';
import { foundationProfile } from '@sealed-lattice/types';
import { afterEach, describe, expect, it } from 'vitest';

import {
    createCanonicalCarrierMailboxKeyPairFixtures,
    createCanonicalCarrierSigningKeyPairFixtures,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import type { BrowserDeviceWrappingSnapshot } from '#packages/protocol/src/runtime/browser-action-storage-custody';
import { openBrowserFoundationOperationOwnerWorker } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import {
    type BrowserFoundationAuthority,
    openBrowserFoundationAuthority,
} from '#packages/protocol/src/runtime/browser-foundation-authority-combined';
import type { TransferableBrowserFoundationOperationOwner } from '#packages/protocol/src/runtime/browser-foundation-operation-owner';
import { openCanonicalBoardRuntime } from '#packages/protocol/src/runtime/canonical-board-runtime';
import { deriveWebLockStorageNamespaceName } from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import {
    copyRuntimeBuildAuthorityBindingDescription,
    loadFreshTranscriptCoreKernel,
    type CanonicalBoardContextInput,
    type RuntimeBuildAuthorityBinding,
} from '#packages/wasm/src/index';
import { createCanonicalBoardContextTestInput } from '#packages/wasm/tests/canonical-board-context-test-vector';
import { createCanonicalTestRosterBytes } from '#packages/wasm/tests/canonical-tuple-test-helpers';
import { activateRuntimeBuildAuthorityBindingFixture } from '#packages/wasm/tests/support/runtime-build-authority-binding-fixture';

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 65_536,
    maximumLeaseCountPerTransaction: 32,
    maximumOwnedRecordCount: 256,
    maximumStoredValueByteLength: 4_194_304,
    maximumTransactionByteLength: 1_048_576,
    maximumTransactionLifetimeMilliseconds: 10_000,
} as const;
const storageNamespace = 'browser-foundation-authority-real-components';

type OpenedOperationOwner = Readonly<{
    databaseName: string;
    deviceWrappingSnapshot: BrowserDeviceWrappingSnapshot;
    operationOwner: TransferableBrowserFoundationOperationOwner;
    worker: Worker;
}>;

const liveAuthorities = new Set<BrowserFoundationAuthority>();
const liveWorkers = new Set<Worker>();
const databaseNames = new Set<string>();

const createCanonicalRosterBytes = (): Uint8Array => {
    const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
        foundationProfile.participantCount,
    );
    const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
        foundationProfile.participantCount,
    );
    try {
        return createCanonicalTestRosterBytes(
            signingKeyPairs.map(({ publicKey }, rosterPosition) => {
                const mailboxKeyPair = mailboxKeyPairs[rosterPosition];
                if (mailboxKeyPair === undefined) {
                    throw new Error(
                        'The deterministic roster mailbox fixture is incomplete.',
                    );
                }
                return {
                    mailboxEncapsulationKey: mailboxKeyPair.publicKey,
                    signingVerificationKey: publicKey,
                };
            }),
        );
    } finally {
        for (const keyPair of signingKeyPairs) {
            keyPair.secretKey.fill(0);
        }
        for (const keyPair of mailboxKeyPairs) {
            keyPair.secretKey.fill(0);
        }
    }
};

const createDatabaseName = (): string => {
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    return `sealed-lattice-foundation-authority-${Array.from(
        randomBytes,
        (byte) => byte.toString(16).padStart(2, '0'),
    ).join('')}`;
};

const deleteDatabase = (databaseName: string): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(databaseName);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ??
                        new Error(
                            'Foundation authority browser database cleanup failed.',
                        ),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () =>
                reject(
                    new Error(
                        'Foundation authority browser database cleanup was blocked by a retained worker connection.',
                    ),
                ),
            { once: true },
        );
    });

const waitForExclusiveLockRelease = (databaseName: string): Promise<void> =>
    navigator.locks.request(
        deriveWebLockStorageNamespaceName({
            databaseName,
            namespace: storageNamespace,
        }),
        { mode: 'exclusive' },
        () => undefined,
    );

const openOperationOwner = async (input: {
    binding: Readonly<{
        actionContextHash: Uint8Array;
        ceremonyContextHash: Uint8Array;
        participantId: Uint8Array;
        suiteId: Uint8Array;
    }>;
    databaseName: string;
    mode:
        | Readonly<{ kind: 'fresh' }>
        | Readonly<{
              expectedSnapshot: BrowserDeviceWrappingSnapshot;
              kind: 'recovered';
          }>;
    runtimeBuildManifestHash: Uint8Array;
}): Promise<OpenedOperationOwner> => {
    const worker = new Worker(
        new URL(
            '../support/browser-foundation-authority-real-components-worker.ts',
            import.meta.url,
        ),
        {
            name: 'sealed-lattice-roster-position:0',
            type: 'module',
        },
    );
    liveWorkers.add(worker);
    databaseNames.add(input.databaseName);
    try {
        const opened = await openBrowserFoundationOperationOwnerWorker({
            configuration: {
                binding: input.binding,
                databaseName: input.databaseName,
                ...(input.mode.kind === 'recovered'
                    ? {
                          knownStorageRootCommitment:
                              input.mode.expectedSnapshot.storageRootCommitment,
                      }
                    : {}),
                limits: transactionLimits,
                namespace: storageNamespace,
                runtimeBuildManifestHash: input.runtimeBuildManifestHash,
            },
            rootOpening:
                input.mode.kind === 'fresh'
                    ? { mode: 'fresh' }
                    : {
                          expectedSnapshot: input.mode.expectedSnapshot,
                          mode: 'recovered',
                          untrustedExpectedCommitment: {
                              storageRootCommitment:
                                  input.mode.expectedSnapshot
                                      .storageRootCommitment,
                          },
                      },
            worker,
        });
        return Object.freeze({
            ...opened,
            databaseName: input.databaseName,
            worker,
        });
    } catch (error) {
        liveWorkers.delete(worker);
        worker.terminate();
        throw error;
    }
};

const openAuthority = async (input: {
    canonicalBoardContext: CanonicalBoardContextInput;
    initializationMode: 'fresh' | 'recovered';
    operationOwner: TransferableBrowserFoundationOperationOwner;
    runtimeBuildAuthorityBinding: RuntimeBuildAuthorityBinding;
}): Promise<BrowserFoundationAuthority> => {
    const board = openCanonicalBoardRuntime({
        contextInput: input.canonicalBoardContext,
        kernel: await loadFreshTranscriptCoreKernel(),
    });
    if (!board.isValid) {
        throw new Error(
            `The real browser canonical-board runtime refused its context: ${board.refusalReason}.`,
        );
    }
    const authority = await openBrowserFoundationAuthority({
        canonicalBoardRuntime: board.value,
        initializationMode: input.initializationMode,
        operationOwner: input.operationOwner,
        runtimeBuildAuthorityBinding: input.runtimeBuildAuthorityBinding,
    });
    liveAuthorities.add(authority);
    return authority;
};

const crashAuthority = async (
    opened: OpenedOperationOwner,
    authority: BrowserFoundationAuthority,
): Promise<void> => {
    liveAuthorities.delete(authority);
    liveWorkers.delete(opened.worker);
    opened.worker.terminate();
    await waitForExclusiveLockRelease(opened.databaseName);
};

const closeAuthority = async (
    opened: OpenedOperationOwner,
    authority: BrowserFoundationAuthority,
): Promise<void> => {
    liveAuthorities.delete(authority);
    await authority.close();
    liveWorkers.delete(opened.worker);
    opened.worker.terminate();
    await waitForExclusiveLockRelease(opened.databaseName);
};

afterEach(async () => {
    for (const authority of [...liveAuthorities]) {
        try {
            await authority.close();
        } catch {
            // Workers are terminated below even when orderly cleanup fails.
        }
    }
    liveAuthorities.clear();
    for (const worker of liveWorkers) {
        worker.terminate();
    }
    liveWorkers.clear();
    for (const databaseName of databaseNames) {
        await waitForExclusiveLockRelease(databaseName);
        await deleteDatabase(databaseName);
    }
    databaseNames.clear();
});

describe('Browser foundation authority real-component composition', () => {
    it('activates authenticated fresh state and reopens the same state after interruption', async () => {
        const runtimeFixture =
            await activateRuntimeBuildAuthorityBindingFixture();
        const runtimeBindingDescription =
            copyRuntimeBuildAuthorityBindingDescription(
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
            );
        const canonicalRosterBytes = createCanonicalRosterBytes();
        const canonicalBoardContext = createCanonicalBoardContextTestInput(
            await loadFreshTranscriptCoreKernel(),
            canonicalRosterBytes,
            runtimeFixture.canonicalSuiteRecordBytes,
        );
        const orderedRosterParticipantIdentities =
            copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
                openAuthenticatedMailboxFrozenRoster(canonicalRosterBytes),
            );
        const subjectParticipantIdentity =
            orderedRosterParticipantIdentities[0];
        if (subjectParticipantIdentity === undefined) {
            throw new Error('The canonical foundation roster has no subject.');
        }
        const subjectBinding = Object.freeze({
            actionContextHash:
                canonicalBoardContext.expectedActionContextHash.slice(),
            ceremonyContextHash:
                canonicalBoardContext.expectedCeremonyContextHash.slice(),
            participantId: subjectParticipantIdentity.slice(),
            suiteId: canonicalBoardContext.expectedSuiteIdentifier.slice(),
        });
        const databaseName = createDatabaseName();

        const freshOpening = await openOperationOwner({
            binding: subjectBinding,
            databaseName,
            mode: { kind: 'fresh' },
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });
        const freshAuthority = await openAuthority({
            canonicalBoardContext,
            initializationMode: 'fresh',
            operationOwner: freshOpening.operationOwner,
            runtimeBuildAuthorityBinding:
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
        });
        await expect(freshAuthority.startup()).resolves.toBe('active');
        const freshDescriptions = await Promise.all(
            (await freshAuthority.witnessRoles()).map((role) =>
                freshAuthority.copyWitnessRoleDescription(role),
            ),
        );
        expect(freshDescriptions).toEqual(
            orderedRosterParticipantIdentities.slice(1).map((identity) => ({
                subjectParticipantIdentity: identity,
            })),
        );
        const freshCapability = freshAuthority.activeCapability();
        expect(() =>
            freshAuthority.actionRandomness(freshCapability),
        ).not.toThrow();

        await crashAuthority(freshOpening, freshAuthority);

        const recoveredOpening = await openOperationOwner({
            binding: subjectBinding,
            databaseName,
            mode: {
                expectedSnapshot: freshOpening.deviceWrappingSnapshot,
                kind: 'recovered',
            },
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });
        const recoveredAuthority = await openAuthority({
            canonicalBoardContext,
            initializationMode: 'recovered',
            operationOwner: recoveredOpening.operationOwner,
            runtimeBuildAuthorityBinding:
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
        });
        await expect(recoveredAuthority.startup()).resolves.toBe('active');
        const recoveredDescriptions = await Promise.all(
            (await recoveredAuthority.witnessRoles()).map((role) =>
                recoveredAuthority.copyWitnessRoleDescription(role),
            ),
        );
        expect(recoveredDescriptions).toEqual(freshDescriptions);
        const recoveredCapability = recoveredAuthority.activeCapability();
        expect(() =>
            recoveredAuthority.actionRandomness(recoveredCapability),
        ).not.toThrow();

        await closeAuthority(recoveredOpening, recoveredAuthority);
    }, 120_000);
});
