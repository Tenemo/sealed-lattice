import {
    openBrowserLocalExternalKeyProvider,
    signResetSafeSetupObject,
} from '@sealed-lattice/crypto';
import { foundationProfile } from '@sealed-lattice/types';

import { createBrowserLocalKeyOperations } from '#packages/crypto/tests/support/browser-local-key-operations';
import {
    createCanonicalCarrierMailboxKeyPairFixtures,
    createCanonicalCarrierSigningKeyPairFixtures,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import { installBrowserActionStorageCustodyWorkerHost } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { createCanonicalTestRosterBytes } from '#packages/wasm/tests/canonical-tuple-test-helpers';

const workerScope = globalThis as unknown as Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
    name: string;
    removeEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
}>;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }
    return difference === 0;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const workerNamePrefix = 'sealed-lattice-roster-position:';
const workerName = workerScope.name;
const localRosterPositionText = workerName.startsWith(workerNamePrefix)
    ? workerName.slice(workerNamePrefix.length)
    : '0';
const localRosterPosition = Number.parseInt(localRosterPositionText, 10);
if (
    !Number.isSafeInteger(localRosterPosition) ||
    String(localRosterPosition) !== localRosterPositionText ||
    localRosterPosition < 0 ||
    localRosterPosition >= foundationProfile.participantCount
) {
    throw new Error('The browser worker roster position is invalid.');
}
const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
    foundationProfile.participantCount,
);
const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
    foundationProfile.participantCount,
);
const expectedCanonicalRosterBytes = createCanonicalTestRosterBytes(
    signingKeyPairs.map(({ publicKey }, rosterPosition) => ({
        mailboxEncapsulationKey: mailboxKeyPairs[rosterPosition].publicKey,
        signingVerificationKey: publicKey,
    })),
);
const localKeyProvider = openBrowserLocalExternalKeyProvider(
    createBrowserLocalKeyOperations({
        mailbox: mailboxKeyPairs[localRosterPosition],
        signing: signingKeyPairs[localRosterPosition],
    }),
);
for (const keyPair of signingKeyPairs) {
    keyPair.secretKey.fill(0);
}
for (const keyPair of mailboxKeyPairs) {
    keyPair.secretKey.fill(0);
}

const transcriptCoreKernelPromise = loadFreshTranscriptCoreKernel();

installBrowserActionStorageCustodyWorkerHost({
    foundationWitnessRuntime: {
        durableStateLimits: {
            maximumExactOutputByteLength: 4_194_304,
            maximumRecordSealingCount: 256,
            maximumSignedVoteCarrierByteLength: 65_536,
            transactionLifetimeMilliseconds: 10_000,
        },
        openWitnessCryptography: ({ canonicalRosterBytes }) => {
            if (
                !bytesEqual(canonicalRosterBytes, expectedCanonicalRosterBytes)
            ) {
                throw new Error(
                    'The real-component browser worker received a roster outside its retained local key custody.',
                );
            }
            return Object.freeze({
                stateObjectSignatureOperation: Object.freeze({
                    signStateObjectMessage: (
                        signatureMessageHash: Uint8Array,
                    ) =>
                        signResetSafeSetupObject({
                            signatureMessageHash:
                                bytesToHex(signatureMessageHash),
                            signingCapability:
                                localKeyProvider.signingCapability,
                        }),
                }),
            });
        },
    },
    workerKernel: createWasmBrowserActionStorageWorkerKernel({
        kernel: transcriptCoreKernelPromise,
    }),
    workerScope,
});
