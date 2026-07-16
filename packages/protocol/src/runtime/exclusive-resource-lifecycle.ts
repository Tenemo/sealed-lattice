export type ExclusiveResourceOwnerToken = Readonly<Record<never, never>>;

type ExclusiveResourceLifecycleState = 'closed' | 'closing' | 'open';

/**
 * Coordinates one synchronous ownership transfer and deterministic asynchronous
 * cleanup. The owner token is process-local and never crosses a storage or
 * transcript boundary.
 */
export class ExclusiveResourceLifecycle {
    readonly #cleanup: () => Promise<void>;
    readonly #createInvalidStateError: (message: string) => Error;
    readonly #inFlightOperations = new Set<Promise<void>>();
    #closePromise: Promise<void> | undefined;
    #currentOwner: ExclusiveResourceOwnerToken;
    #ownershipClaimed = false;
    #state: ExclusiveResourceLifecycleState = 'open';

    public constructor(input: {
        cleanup: () => Promise<void>;
        createInvalidStateError: (message: string) => Error;
    }) {
        this.#cleanup = input.cleanup;
        this.#createInvalidStateError = input.createInvalidStateError;
        this.#currentOwner = Object.freeze({});
    }

    public initialOwner(): ExclusiveResourceOwnerToken {
        return this.#currentOwner;
    }

    public assertOpen(owner: ExclusiveResourceOwnerToken): void {
        this.assertOwner(owner);
        if (this.#state !== 'open') {
            throw this.#createInvalidStateError(
                'The resource owner is closing or has already closed.',
            );
        }
    }

    public assertOwner(owner: ExclusiveResourceOwnerToken): void {
        this.#assertCurrentOwner(owner);
    }

    public claim(
        owner: ExclusiveResourceOwnerToken,
    ): ExclusiveResourceOwnerToken {
        this.assertOpen(owner);
        if (this.#ownershipClaimed) {
            throw this.#createInvalidStateError(
                'Exclusive ownership of this resource was already claimed.',
            );
        }
        const claimedOwner = Object.freeze({});
        this.#ownershipClaimed = true;
        this.#currentOwner = claimedOwner;
        return claimedOwner;
    }

    public close(owner: ExclusiveResourceOwnerToken): Promise<void> {
        this.#assertCurrentOwner(owner);
        if (this.#closePromise !== undefined) {
            return this.#closePromise;
        }
        if (this.#state === 'closed') {
            return Promise.resolve();
        }
        this.#state = 'closing';
        const operationsToDrain = [...this.#inFlightOperations];
        this.#closePromise = Promise.allSettled(operationsToDrain)
            .then(() => this.#cleanup())
            .then(() => {
                this.#state = 'closed';
            })
            .catch((error: unknown) => {
                this.#closePromise = undefined;
                throw error;
            });
        return this.#closePromise;
    }

    public run<Result>(
        owner: ExclusiveResourceOwnerToken,
        operation: () => Promise<Result>,
    ): Promise<Result> {
        this.assertOpen(owner);
        let result: Promise<Result>;
        try {
            result = operation();
        } catch (error) {
            result = Promise.reject(
                error instanceof Error
                    ? error
                    : new Error('The resource operation failed synchronously.'),
            );
        }
        const settled = result.then(
            () => {
                this.#inFlightOperations.delete(settled);
            },
            () => {
                this.#inFlightOperations.delete(settled);
            },
        );
        this.#inFlightOperations.add(settled);
        return result;
    }

    #assertCurrentOwner(owner: ExclusiveResourceOwnerToken): void {
        if (owner !== this.#currentOwner) {
            throw this.#createInvalidStateError(
                'This resource wrapper is stale because ownership was transferred.',
            );
        }
    }
}
