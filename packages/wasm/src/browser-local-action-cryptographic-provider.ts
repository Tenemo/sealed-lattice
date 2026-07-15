import {
    openBrowserLocalExternalKeyProvider,
    type BrowserLocalExternalKeyProvider,
    type BrowserLocalExternalKeyProviderInput,
} from '@sealed-lattice/crypto';
import type { BrowserActionStorageWorkerKernel } from '@sealed-lattice/types';

import {
    openClosedWorkerSetupMailboxRandomness,
    type ClosedWorkerSetupMailboxRandomnessOperations,
} from './local-storage-root-worker-kernel.js';

export type BrowserLocalActionCryptographicProvider = Readonly<{
    readonly actionRandomnessSessionIdentifier: string;
    readonly externalKeyProvider: BrowserLocalExternalKeyProvider;
    close(): Promise<void>;
}>;

export type BrowserLocalActionCryptographicProviderInput = Readonly<{
    readonly actionRandomnessSessionIdentifier: string;
    readonly mailbox: BrowserLocalExternalKeyProviderInput['mailbox'];
    readonly ordinaryOperationEntropy?: BrowserLocalExternalKeyProviderInput['entropy'];
    readonly signing: BrowserLocalExternalKeyProviderInput['signing'];
    readonly stateReservationIdentifier: string;
    readonly workerKernel: BrowserActionStorageWorkerKernel;
}>;

/**
 * Takes ownership of worker-held action randomness and its commitment-bound
 * reservation, binds both local key operations and each recipient key to the
 * frozen roster, then encloses setup-mailbox derivation and use inside the same
 * worker realm. No public operation returns the root, ML-KEM coins, or ML-DSA
 * hedge.
 */
export const openBrowserLocalActionCryptographicProvider = async (
    input: BrowserLocalActionCryptographicProviderInput,
): Promise<BrowserLocalActionCryptographicProvider> => {
    const closeOwnedWorkerState = async (): Promise<void> => {
        let firstFailure: unknown;
        try {
            await input.workerKernel.closeActionRandomness(
                input.actionRandomnessSessionIdentifier,
            );
        } catch (error) {
            firstFailure = error;
        }
        try {
            await input.workerKernel.releaseActionStateObject(
                input.stateReservationIdentifier,
            );
        } catch (error) {
            firstFailure ??= error;
        }
        if (firstFailure !== undefined) {
            throw firstFailure;
        }
    };
    let resetSafeSetupMailboxRandomness: ClosedWorkerSetupMailboxRandomnessOperations;
    let sourceMailboxEncapsulationKey = new Uint8Array(0);
    let sourceSigningVerificationKey = new Uint8Array(0);
    try {
        sourceMailboxEncapsulationKey = input.mailbox.encapsulationKey.slice();
        sourceSigningVerificationKey = input.signing.verificationKey.slice();
        resetSafeSetupMailboxRandomness =
            await openClosedWorkerSetupMailboxRandomness(input.workerKernel, {
                actionRandomnessSessionIdentifier:
                    input.actionRandomnessSessionIdentifier,
                sourceMailboxEncapsulationKey,
                sourceSigningVerificationKey,
                stateReservationIdentifier: input.stateReservationIdentifier,
            });
    } catch (error) {
        sourceMailboxEncapsulationKey.fill(0);
        sourceSigningVerificationKey.fill(0);
        try {
            await closeOwnedWorkerState();
        } catch (cleanupFailure) {
            throw new AggregateError(
                [error, cleanupFailure],
                'Opening the action cryptographic provider failed and its worker-owned state could not be fully released.',
            );
        }
        throw error;
    }
    let externalKeyProvider: BrowserLocalExternalKeyProvider;
    try {
        externalKeyProvider = openBrowserLocalExternalKeyProvider({
            ...(input.ordinaryOperationEntropy === undefined
                ? {}
                : { entropy: input.ordinaryOperationEntropy }),
            mailbox: {
                encapsulationKey: sourceMailboxEncapsulationKey,
                decapsulateClosedCiphertext: (ciphertext) =>
                    input.mailbox.decapsulateClosedCiphertext(ciphertext),
                revoke: () => input.mailbox.revoke(),
            },
            resetSafeSetupMailboxRandomness,
            signing: {
                verificationKey: sourceSigningVerificationKey,
                signClosedMessage: (signingInput) =>
                    input.signing.signClosedMessage(signingInput),
                revoke: () => input.signing.revoke(),
            },
        });
    } catch (error) {
        resetSafeSetupMailboxRandomness.revoke();
        try {
            await closeOwnedWorkerState();
        } catch (cleanupFailure) {
            throw new AggregateError(
                [error, cleanupFailure],
                'Opening the action cryptographic provider failed and its worker-owned state could not be fully released.',
            );
        }
        throw error;
    } finally {
        sourceMailboxEncapsulationKey.fill(0);
        sourceSigningVerificationKey.fill(0);
    }

    let closePromise: Promise<void> | undefined;
    return Object.freeze({
        actionRandomnessSessionIdentifier:
            input.actionRandomnessSessionIdentifier,
        externalKeyProvider,
        close: () =>
            (closePromise ??= (async () => {
                try {
                    externalKeyProvider.close();
                } finally {
                    resetSafeSetupMailboxRandomness.revoke();
                    await closeOwnedWorkerState();
                }
            })()),
    });
};
