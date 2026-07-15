import {
    openBrowserLocalExternalKeyProvider,
    type BrowserLocalExternalKeyProvider,
    type BrowserLocalExternalKeyProviderInput,
} from '@sealed-lattice/crypto';
import type { BrowserActionStorageWorkerKernel } from '@sealed-lattice/types';
import {
    openClosedWorkerSetupMailboxRandomness,
    type ClosedWorkerSetupMailboxRandomnessOperations,
} from '@sealed-lattice/wasm';

export type BrowserLocalActionCryptographicProvider = Readonly<{
    readonly actionRandomnessSessionIdentifier: string;
    readonly externalKeyProvider: BrowserLocalExternalKeyProvider;
    close(): Promise<void>;
}>;

export type BrowserLocalActionCryptographicProviderInput = Readonly<{
    readonly actionRandomnessSessionIdentifier: string;
    readonly mailbox: BrowserLocalExternalKeyProviderInput['mailbox'];
    readonly signing: BrowserLocalExternalKeyProviderInput['signing'];
    readonly stateReservationIdentifier: string;
    readonly workerKernel: BrowserActionStorageWorkerKernel;
}>;

class BrowserLocalActionCryptographicProviderCleanupError extends Error {
    public readonly cleanupFailure: unknown;
    public readonly operationFailure: unknown;

    public constructor(operationFailure: unknown, cleanupFailure: unknown) {
        super(
            'The action cryptographic provider operation failed and its worker-owned state could not be fully released.',
        );
        this.name = 'BrowserLocalActionCryptographicProviderCleanupError';
        this.operationFailure = operationFailure;
        this.cleanupFailure = cleanupFailure;
    }
}

class BrowserLocalActionCryptographicProviderOperationError extends Error {
    public readonly failureCause: unknown;

    public constructor(message: string, failureCause: unknown) {
        super(message);
        this.name = 'BrowserLocalActionCryptographicProviderOperationError';
        this.failureCause = failureCause;
    }
}

const errorFromUnknownFailure = (failure: unknown, message: string): Error =>
    failure instanceof Error
        ? failure
        : new BrowserLocalActionCryptographicProviderOperationError(
              message,
              failure,
          );

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
            throw errorFromUnknownFailure(
                firstFailure,
                'Closing worker-owned action cryptographic state failed.',
            );
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
            throw new BrowserLocalActionCryptographicProviderCleanupError(
                error,
                cleanupFailure,
            );
        }
        throw errorFromUnknownFailure(
            error,
            'Opening worker-owned action cryptographic state failed.',
        );
    }
    let externalKeyProvider: BrowserLocalExternalKeyProvider;
    try {
        externalKeyProvider = openBrowserLocalExternalKeyProvider({
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
        try {
            await closeOwnedWorkerState();
        } catch (cleanupFailure) {
            throw new BrowserLocalActionCryptographicProviderCleanupError(
                error,
                cleanupFailure,
            );
        }
        throw errorFromUnknownFailure(
            error,
            'Opening the browser-local external key provider failed.',
        );
    } finally {
        sourceMailboxEncapsulationKey.fill(0);
        sourceSigningVerificationKey.fill(0);
    }

    let closePromise: Promise<void> | undefined;
    const close = async (): Promise<void> => {
        let providerFailure: unknown;
        try {
            externalKeyProvider.close();
        } catch (error) {
            providerFailure = error;
        }
        let workerFailure: unknown;
        try {
            await closeOwnedWorkerState();
        } catch (error) {
            workerFailure = error;
        }
        if (providerFailure !== undefined && workerFailure !== undefined) {
            throw new BrowserLocalActionCryptographicProviderCleanupError(
                providerFailure,
                workerFailure,
            );
        }
        if (providerFailure !== undefined) {
            throw errorFromUnknownFailure(
                providerFailure,
                'Closing the browser-local external key provider failed.',
            );
        }
        if (workerFailure !== undefined) {
            throw errorFromUnknownFailure(
                workerFailure,
                'Closing worker-owned action cryptographic state failed.',
            );
        }
    };

    return Object.freeze({
        actionRandomnessSessionIdentifier:
            input.actionRandomnessSessionIdentifier,
        externalKeyProvider,
        close: () => (closePromise ??= close()),
    });
};
