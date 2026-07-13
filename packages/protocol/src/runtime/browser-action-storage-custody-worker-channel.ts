import { browserActionStorageCustodyErrorCodes } from '@sealed-lattice/types';

import type { BrowserActionStorageWorkerKernel } from './browser-action-storage-custody-internal.js';
import {
    BrowserActionStorageCustodyError,
    type BrowserActionStorageCustody,
    type BrowserActionStorageCustodyErrorCode,
    type BrowserActionStorageRootBinding,
    type BrowserDeviceWrappingSnapshot,
    type ExternallyVerifiedStorageRootCommitment,
    type BrowserRecoveryExportChallenge,
    type BrowserRecoveryExportConfirmation,
} from './browser-action-storage-custody.js';
import type { UntrustedStorageTransactionLimits } from './untrusted-storage-transaction-store.js';
import {
    openWebLockOwnedBrowserActionStorageCustody,
    type WebLockOwnedBrowserActionStorageCustody,
} from './web-lock-owned-untrusted-storage-transaction-store.js';

const mutationIdentifierByteLength = 32;
const recoveryChecksumByteLength = 16;
const recoveryTextLength = 708;
const recoveryTextPattern = /^[A-Z2-7]{708}$/u;
const preparationIdentifierPattern = /^[0-9a-f]{64}$/u;
const storageRootCommitmentByteLength = 64;
const maximumDatabaseNameLength = 256;
const maximumNamespaceLength = 64;
const namespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;

type BrowserActionStorageCustodyWorkerConfiguration = Readonly<{
    acquisitionDeadlineEpochMilliseconds?: number;
    binding: BrowserActionStorageRootBinding;
    databaseName: string;
    knownStorageRootCommitment?: Uint8Array;
    limits: UntrustedStorageTransactionLimits;
    namespace: string;
}>;

type CustodyWorkerCommand =
    | 'begin-recovery-export'
    | 'cancel-recovery-export'
    | 'close'
    | 'confirm-recovery-export'
    | 'current-snapshot'
    | 'delete'
    | 'initialize'
    | 'open-custody'
    | 'open-root'
    | 'recover';

type CustodyWorkerRequest = Readonly<{
    command: CustodyWorkerCommand;
    input: unknown;
    messageKind: 'browser-action-storage-custody-request';
    requestIdentifier: number;
}>;

type CustodyWorkerResponse =
    | Readonly<{
          messageKind: 'browser-action-storage-custody-completed';
          requestIdentifier: number;
          result: unknown;
      }>
    | Readonly<{
          errorCode: BrowserActionStorageCustodyErrorCode;
          messageKind: 'browser-action-storage-custody-failed';
          requestIdentifier: number;
      }>
    | Readonly<{
          errorCode: 'OwnedWorkerFailure';
          messageKind: 'browser-action-storage-custody-channel-failed';
      }>;

type CustodyWorkerLike = Pick<
    Worker,
    'addEventListener' | 'postMessage' | 'removeEventListener' | 'terminate'
>;

type CustodyWorkerScope = Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: CustodyWorkerResponse): void;
    removeEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
}>;

type ActiveClientRequest = Readonly<{
    command: CustodyWorkerCommand;
    reject(error: Error): void;
    requestIdentifier: number;
    resolve(value: unknown): void;
    validateResult(value: unknown): unknown;
}>;

const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return false;
    }
    const prototype = Reflect.getPrototypeOf(value);

    return prototype === Object.prototype || prototype === null;
};

const hasRequiredKeys = (
    value: Record<string, unknown>,
    requiredKeys: readonly string[],
): boolean =>
    requiredKeys.every((requiredKey) =>
        Object.prototype.hasOwnProperty.call(value, requiredKey),
    );

const isSafePositiveInteger = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

const isCustodyErrorCode = (
    value: unknown,
): value is BrowserActionStorageCustodyErrorCode =>
    typeof value === 'string' &&
    browserActionStorageCustodyErrorCodes.includes(
        value as BrowserActionStorageCustodyErrorCode,
    );

const copyBytes = (
    value: unknown,
    byteLength: number,
    label: string,
): Uint8Array => {
    if (!(value instanceof Uint8Array) || value.byteLength !== byteLength) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must contain exactly ${byteLength} bytes.`,
        );
    }

    return value.slice();
};

const copyRootBinding = (value: unknown): BrowserActionStorageRootBinding => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, [
            'actionContextHash',
            'ceremonyContextHash',
            'participantId',
            'suiteId',
        ])
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The browser action-storage root binding is malformed.',
        );
    }

    return Object.freeze({
        actionContextHash: copyBytes(
            value.actionContextHash,
            storageRootCommitmentByteLength,
            'Action-context hash',
        ),
        ceremonyContextHash: copyBytes(
            value.ceremonyContextHash,
            storageRootCommitmentByteLength,
            'Ceremony-context hash',
        ),
        participantId: copyBytes(
            value.participantId,
            storageRootCommitmentByteLength,
            'Participant identity',
        ),
        suiteId: copyBytes(
            value.suiteId,
            storageRootCommitmentByteLength,
            'Suite identifier',
        ),
    });
};

const copyVerifiedCommitment = (
    value: unknown,
): ExternallyVerifiedStorageRootCommitment => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, ['storageRootCommitment'])
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The externally verified storage-root commitment is malformed.',
        );
    }

    return Object.freeze({
        storageRootCommitment: copyBytes(
            value.storageRootCommitment,
            storageRootCommitmentByteLength,
            'Externally verified storage-root commitment',
        ),
    });
};

const copySnapshot = (value: unknown): BrowserDeviceWrappingSnapshot => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, [
            'mutationIdentifier',
            'recoveryValueExported',
            'storageRootCommitment',
        ]) ||
        typeof value.recoveryValueExported !== 'boolean'
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The browser action-storage custody snapshot is malformed.',
        );
    }

    return Object.freeze({
        mutationIdentifier: copyBytes(
            value.mutationIdentifier,
            mutationIdentifierByteLength,
            'Custody mutation identifier',
        ),
        recoveryValueExported: value.recoveryValueExported,
        storageRootCommitment: copyBytes(
            value.storageRootCommitment,
            storageRootCommitmentByteLength,
            'Snapshot storage-root commitment',
        ),
    });
};

const copyBoundSnapshotInput = (
    value: unknown,
): Readonly<{
    expectedSnapshot: BrowserDeviceWrappingSnapshot;
    externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
}> => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, [
            'expectedSnapshot',
            'externallyVerifiedCommitment',
        ])
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The commitment-bound custody input is malformed.',
        );
    }

    return Object.freeze({
        expectedSnapshot: copySnapshot(value.expectedSnapshot),
        externallyVerifiedCommitment: copyVerifiedCommitment(
            value.externallyVerifiedCommitment,
        ),
    });
};

const copyOptionalSnapshot = (
    value: unknown,
): BrowserDeviceWrappingSnapshot | undefined =>
    value === undefined ? undefined : copySnapshot(value);

const copyRecoveryText = (
    value: unknown,
    requireCanonicalCase: boolean,
): string => {
    if (typeof value !== 'string') {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Recovery material must be text.',
        );
    }
    const canonicalRecoveryText = value.toUpperCase();
    if (
        value.length !== recoveryTextLength ||
        !recoveryTextPattern.test(canonicalRecoveryText) ||
        (requireCanonicalCase && value !== canonicalRecoveryText)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `Recovery material must contain exactly ${recoveryTextLength} base32 characters in the required case.`,
        );
    }

    return requireCanonicalCase ? canonicalRecoveryText : value;
};

const copyPreparationIdentifier = (value: unknown): string => {
    if (
        typeof value !== 'string' ||
        !preparationIdentifierPattern.test(value)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Recovery preparation identifier is malformed.',
        );
    }

    return value;
};

const copyChallenge = (value: unknown): BrowserRecoveryExportChallenge => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, ['preparationIdentifier', 'recoveryChecksum'])
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed recovery challenge.',
        );
    }

    return Object.freeze({
        preparationIdentifier: copyPreparationIdentifier(
            value.preparationIdentifier,
        ),
        recoveryChecksum: copyBytes(
            value.recoveryChecksum,
            recoveryChecksumByteLength,
            'Recovery checksum',
        ),
    });
};

const copyConfirmation = (
    value: unknown,
): BrowserRecoveryExportConfirmation => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, ['canonicalRecoveryText', 'snapshot'])
    ) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned a malformed recovery confirmation.',
        );
    }

    return Object.freeze({
        canonicalRecoveryText: copyRecoveryText(
            value.canonicalRecoveryText,
            true,
        ),
        snapshot: copySnapshot(value.snapshot),
    });
};

const validateVoidResult = (value: unknown): undefined => {
    if (value !== undefined) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The owned worker returned unexpected command output.',
        );
    }

    return undefined;
};

const copyLimits = (value: unknown): UntrustedStorageTransactionLimits => {
    const keys = [
        'maximumActiveTransactionCount',
        'maximumLeaseByteLength',
        'maximumLeaseCountPerTransaction',
        'maximumStoredValueByteLength',
        'maximumTransactionByteLength',
        'maximumTransactionLifetimeMilliseconds',
    ] as const;
    if (!isPlainRecord(value) || !hasRequiredKeys(value, keys)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser storage transaction limits are malformed.',
        );
    }
    for (const key of keys) {
        if (!isSafePositiveInteger(value[key])) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                `Browser storage transaction limit ${key} must be a positive safe integer.`,
            );
        }
    }

    return Object.freeze({
        maximumActiveTransactionCount: value.maximumActiveTransactionCount,
        maximumLeaseByteLength: value.maximumLeaseByteLength,
        maximumLeaseCountPerTransaction: value.maximumLeaseCountPerTransaction,
        maximumStoredValueByteLength: value.maximumStoredValueByteLength,
        maximumTransactionByteLength: value.maximumTransactionByteLength,
        maximumTransactionLifetimeMilliseconds:
            value.maximumTransactionLifetimeMilliseconds,
    }) as UntrustedStorageTransactionLimits;
};

const copyWorkerConfiguration = (
    value: unknown,
): BrowserActionStorageCustodyWorkerConfiguration => {
    if (
        !isPlainRecord(value) ||
        !hasRequiredKeys(value, [
            'acquisitionDeadlineEpochMilliseconds',
            'binding',
            'databaseName',
            'knownStorageRootCommitment',
            'limits',
            'namespace',
        ]) ||
        typeof value.databaseName !== 'string' ||
        value.databaseName.length === 0 ||
        value.databaseName.length > maximumDatabaseNameLength ||
        typeof value.namespace !== 'string' ||
        value.namespace.length > maximumNamespaceLength ||
        !namespacePattern.test(value.namespace) ||
        (value.acquisitionDeadlineEpochMilliseconds !== undefined &&
            (!Number.isSafeInteger(
                value.acquisitionDeadlineEpochMilliseconds,
            ) ||
                (value.acquisitionDeadlineEpochMilliseconds as number) < 0))
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Browser action-storage worker configuration is malformed.',
        );
    }

    return Object.freeze({
        acquisitionDeadlineEpochMilliseconds:
            value.acquisitionDeadlineEpochMilliseconds as number | undefined,
        binding: copyRootBinding(value.binding),
        databaseName: value.databaseName,
        knownStorageRootCommitment:
            value.knownStorageRootCommitment === undefined
                ? undefined
                : copyBytes(
                      value.knownStorageRootCommitment,
                      storageRootCommitmentByteLength,
                      'Known storage-root commitment',
                  ),
        limits: copyLimits(value.limits),
        namespace: value.namespace,
    });
};

const isCustodyWorkerResponse = (
    value: unknown,
): value is CustodyWorkerResponse => {
    if (!isPlainRecord(value)) {
        return false;
    }
    if (value.messageKind === 'browser-action-storage-custody-channel-failed') {
        return (
            hasRequiredKeys(value, ['errorCode', 'messageKind']) &&
            value.errorCode === 'OwnedWorkerFailure'
        );
    }
    if (!isSafePositiveInteger(value.requestIdentifier)) {
        return false;
    }
    if (value.messageKind === 'browser-action-storage-custody-completed') {
        return hasRequiredKeys(value, [
            'messageKind',
            'requestIdentifier',
            'result',
        ]);
    }

    return (
        value.messageKind === 'browser-action-storage-custody-failed' &&
        hasRequiredKeys(value, [
            'errorCode',
            'messageKind',
            'requestIdentifier',
        ]) &&
        isCustodyErrorCode(value.errorCode)
    );
};

const custodyWorkerCommands: readonly CustodyWorkerCommand[] = [
    'begin-recovery-export',
    'cancel-recovery-export',
    'close',
    'confirm-recovery-export',
    'current-snapshot',
    'delete',
    'initialize',
    'open-custody',
    'open-root',
    'recover',
];

const isCustodyWorkerRequest = (
    value: unknown,
): value is CustodyWorkerRequest =>
    isPlainRecord(value) &&
    hasRequiredKeys(value, [
        'command',
        'input',
        'messageKind',
        'requestIdentifier',
    ]) &&
    value.messageKind === 'browser-action-storage-custody-request' &&
    isSafePositiveInteger(value.requestIdentifier) &&
    typeof value.command === 'string' &&
    custodyWorkerCommands.includes(value.command as CustodyWorkerCommand);

class BrowserActionStorageCustodyWorkerClient implements BrowserActionStorageCustody {
    #activeRequest: ActiveClientRequest | undefined;
    #closed = false;
    #closing = false;
    #closePromise: Promise<void> | undefined;
    #nextRequestIdentifier = 1;
    #operationTail: Promise<void> = Promise.resolve();
    #terminalFailure: BrowserActionStorageCustodyError | undefined;
    readonly #worker: CustodyWorkerLike;
    readonly #errorListener: EventListener;
    readonly #messageErrorListener: EventListener;
    readonly #messageListener: EventListener;

    public constructor(worker: CustodyWorkerLike) {
        this.#worker = worker;
        this.#messageListener = (event): void => {
            this.#handleMessage((event as MessageEvent<unknown>).data);
        };
        this.#errorListener = (): void => {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker failed.',
                ),
            );
        };
        this.#messageErrorListener = (): void => {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker returned an uncloneable message.',
                ),
            );
        };
        worker.addEventListener('message', this.#messageListener);
        worker.addEventListener('error', this.#errorListener);
        worker.addEventListener('messageerror', this.#messageErrorListener);
    }

    public open(
        configuration: BrowserActionStorageCustodyWorkerConfiguration,
    ): Promise<void> {
        let copiedConfiguration: BrowserActionStorageCustodyWorkerConfiguration;
        try {
            copiedConfiguration = copyWorkerConfiguration({
                acquisitionDeadlineEpochMilliseconds:
                    configuration.acquisitionDeadlineEpochMilliseconds,
                binding: configuration.binding,
                databaseName: configuration.databaseName,
                knownStorageRootCommitment:
                    configuration.knownStorageRootCommitment,
                limits: configuration.limits,
                namespace: configuration.namespace,
            });
        } catch (error) {
            return Promise.reject(
                error instanceof Error
                    ? error
                    : new BrowserActionStorageCustodyError(
                          'InvalidInput',
                          'Browser action-storage worker configuration could not be copied.',
                          error,
                      ),
            );
        }

        return this.#queueOperation(() =>
            this.#sendRequest(
                'open-custody',
                copiedConfiguration,
                validateVoidResult,
            ),
        );
    }

    public initialize(): Promise<BrowserDeviceWrappingSnapshot> {
        return this.#queueOperation(() =>
            this.#sendRequest('initialize', undefined, copySnapshot),
        );
    }

    public currentSnapshot(): Promise<
        BrowserDeviceWrappingSnapshot | undefined
    > {
        return this.#queueOperation(() =>
            this.#sendRequest(
                'current-snapshot',
                undefined,
                copyOptionalSnapshot,
            ),
        );
    }

    public openIntoOwnedWorker(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
    }): Promise<void> {
        return this.#queueValidatedOperation(
            () => copyBoundSnapshotInput(input),
            (copiedInput) =>
                this.#sendRequest('open-root', copiedInput, validateVoidResult),
        );
    }

    public beginRecoveryExport(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
    }): Promise<BrowserRecoveryExportChallenge> {
        return this.#queueValidatedOperation(
            () => copyBoundSnapshotInput(input),
            (copiedInput) =>
                this.#sendRequest(
                    'begin-recovery-export',
                    copiedInput,
                    copyChallenge,
                ),
        );
    }

    public confirmRecoveryExport(input: {
        preparationIdentifier: string;
        confirmedChecksum: Uint8Array;
    }): Promise<BrowserRecoveryExportConfirmation> {
        return this.#queueValidatedOperation(
            () => ({
                confirmedChecksum: copyBytes(
                    input.confirmedChecksum,
                    recoveryChecksumByteLength,
                    'Confirmed recovery checksum',
                ),
                preparationIdentifier: copyPreparationIdentifier(
                    input.preparationIdentifier,
                ),
            }),
            (copiedInput) =>
                this.#sendRequest(
                    'confirm-recovery-export',
                    copiedInput,
                    copyConfirmation,
                ),
        );
    }

    public cancelRecoveryExport(preparationIdentifier: string): Promise<void> {
        return this.#queueValidatedOperation(
            () => copyPreparationIdentifier(preparationIdentifier),
            (copiedIdentifier) =>
                this.#sendRequest(
                    'cancel-recovery-export',
                    copiedIdentifier,
                    validateVoidResult,
                ),
        );
    }

    public recover(input: {
        caseInsensitiveRecoveryText: string;
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
        expectedSnapshot?: BrowserDeviceWrappingSnapshot;
    }): Promise<BrowserDeviceWrappingSnapshot> {
        return this.#queueValidatedOperation(
            () => ({
                caseInsensitiveRecoveryText: copyRecoveryText(
                    input.caseInsensitiveRecoveryText,
                    false,
                ),
                externallyVerifiedCommitment: copyVerifiedCommitment(
                    input.externallyVerifiedCommitment,
                ),
                expectedSnapshot: copyOptionalSnapshot(input.expectedSnapshot),
            }),
            (copiedInput) =>
                this.#sendRequest('recover', copiedInput, copySnapshot),
        );
    }

    public delete(
        expectedSnapshot: BrowserDeviceWrappingSnapshot,
    ): Promise<void> {
        return this.#queueValidatedOperation(
            () => copySnapshot(expectedSnapshot),
            (snapshot) =>
                this.#sendRequest('delete', snapshot, validateVoidResult),
        );
    }

    public close(): Promise<void> {
        if (this.#closePromise !== undefined) {
            return this.#closePromise;
        }
        if (this.#closed) {
            return this.#terminalFailure === undefined
                ? Promise.resolve()
                : Promise.reject(this.#terminalFailure);
        }
        this.#closing = true;
        this.#closePromise = this.#enqueue(async () => {
            try {
                await this.#sendRequest('close', undefined, validateVoidResult);
            } finally {
                this.#disposeWorker();
                this.#closed = true;
            }
        });

        return this.#closePromise;
    }

    public abortAfterOpenFailure(): void {
        this.#disposeWorker();
        this.#closed = true;
    }

    #queueValidatedOperation<Input, Result>(
        validateInput: () => Input,
        operation: (input: Input) => Promise<Result>,
    ): Promise<Result> {
        let copiedInput: Input;
        try {
            copiedInput = validateInput();
        } catch (error) {
            return Promise.reject(
                error instanceof Error
                    ? error
                    : new BrowserActionStorageCustodyError(
                          'InvalidInput',
                          'Browser action-storage command input could not be copied.',
                          error,
                      ),
            );
        }

        return this.#queueOperation(() => operation(copiedInput));
    }

    #queueOperation<Result>(operation: () => Promise<Result>): Promise<Result> {
        if (this.#closing || this.#closed) {
            return Promise.reject(
                this.#terminalFailure ??
                    new BrowserActionStorageCustodyError(
                        'Closed',
                        'The browser action-storage worker channel is closed.',
                    ),
            );
        }

        return this.#enqueue(operation);
    }

    #enqueue<Result>(operation: () => Promise<Result>): Promise<Result> {
        const result = this.#operationTail.then(operation, operation);
        this.#operationTail = result.then(
            () => undefined,
            () => undefined,
        );

        return result;
    }

    #sendRequest<Result>(
        command: CustodyWorkerCommand,
        input: unknown,
        validateResult: (value: unknown) => Result,
    ): Promise<Result> {
        if (this.#closed || this.#activeRequest !== undefined) {
            return Promise.reject(
                this.#terminalFailure ??
                    new BrowserActionStorageCustodyError(
                        this.#closed ? 'Closed' : 'OwnedWorkerFailure',
                        this.#closed
                            ? 'The browser action-storage worker channel is closed.'
                            : 'The browser action-storage worker channel attempted overlapping requests.',
                    ),
            );
        }
        const requestIdentifier = this.#nextRequestIdentifier;
        this.#nextRequestIdentifier += 1;
        if (!Number.isSafeInteger(this.#nextRequestIdentifier)) {
            this.#nextRequestIdentifier = 1;
        }

        return new Promise<Result>((resolve, reject) => {
            this.#activeRequest = {
                command,
                reject,
                requestIdentifier,
                resolve: (value) => resolve(value as Result),
                validateResult,
            };
            const message: CustodyWorkerRequest = {
                command,
                input,
                messageKind: 'browser-action-storage-custody-request',
                requestIdentifier,
            };
            try {
                this.#worker.postMessage(message);
            } catch (error) {
                this.#failChannel(
                    new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'Posting a browser action-storage worker command failed.',
                        error,
                    ),
                );
            }
        });
    }

    #handleMessage(message: unknown): void {
        if (!isCustodyWorkerResponse(message)) {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker returned a malformed response.',
                ),
            );
            return;
        }
        if (
            message.messageKind ===
            'browser-action-storage-custody-channel-failed'
        ) {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker channel failed closed.',
                ),
            );
            return;
        }
        const activeRequest = this.#activeRequest;
        if (message.requestIdentifier !== activeRequest?.requestIdentifier) {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker returned a malformed, unsolicited, or mismatched response.',
                ),
            );
            return;
        }
        this.#activeRequest = undefined;
        if (message.messageKind === 'browser-action-storage-custody-failed') {
            activeRequest.reject(
                new BrowserActionStorageCustodyError(
                    message.errorCode,
                    `The browser action-storage worker refused ${activeRequest.command}.`,
                ),
            );
            return;
        }
        try {
            activeRequest.resolve(activeRequest.validateResult(message.result));
        } catch (error) {
            this.#failChannel(
                new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The browser action-storage worker result failed validation.',
                    error,
                ),
                activeRequest,
            );
        }
    }

    #failChannel(
        error: BrowserActionStorageCustodyError,
        detachedRequest?: ActiveClientRequest,
    ): void {
        const activeRequest = detachedRequest ?? this.#activeRequest;
        this.#activeRequest = undefined;
        this.#closing = true;
        this.#closed = true;
        this.#terminalFailure ??= error;
        this.#disposeWorker();
        activeRequest?.reject(this.#terminalFailure);
    }

    #disposeWorker(): void {
        this.#worker.removeEventListener('message', this.#messageListener);
        this.#worker.removeEventListener('error', this.#errorListener);
        this.#worker.removeEventListener(
            'messageerror',
            this.#messageErrorListener,
        );
        this.#worker.terminate();
    }
}

export const openBrowserActionStorageCustodyWorker = async (input: {
    configuration: BrowserActionStorageCustodyWorkerConfiguration;
    worker: CustodyWorkerLike;
}): Promise<BrowserActionStorageCustody> => {
    const client = new BrowserActionStorageCustodyWorkerClient(input.worker);
    try {
        await client.open(input.configuration);

        return Object.freeze({
            beginRecoveryExport: (recoveryExportInput) =>
                client.beginRecoveryExport(recoveryExportInput),
            cancelRecoveryExport: (preparationIdentifier) =>
                client.cancelRecoveryExport(preparationIdentifier),
            close: () => client.close(),
            confirmRecoveryExport: (confirmationInput) =>
                client.confirmRecoveryExport(confirmationInput),
            currentSnapshot: () => client.currentSnapshot(),
            delete: (expectedSnapshot) => client.delete(expectedSnapshot),
            initialize: () => client.initialize(),
            openIntoOwnedWorker: (openInput) =>
                client.openIntoOwnedWorker(openInput),
            recover: (recoveryInput) => client.recover(recoveryInput),
        } satisfies BrowserActionStorageCustody);
    } catch (error) {
        client.abortAfterOpenFailure();
        throw error;
    }
};

const copyHostCommandInput = (
    command: CustodyWorkerCommand,
    input: unknown,
): unknown => {
    switch (command) {
        case 'open-custody':
            return copyWorkerConfiguration(input);
        case 'initialize':
        case 'current-snapshot':
        case 'close':
            return validateVoidResult(input);
        case 'open-root':
        case 'begin-recovery-export':
            return copyBoundSnapshotInput(input);
        case 'delete':
            return copySnapshot(input);
        case 'cancel-recovery-export':
            return copyPreparationIdentifier(input);
        case 'confirm-recovery-export': {
            if (
                !isPlainRecord(input) ||
                !hasRequiredKeys(input, [
                    'confirmedChecksum',
                    'preparationIdentifier',
                ])
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Recovery confirmation worker input is malformed.',
                );
            }

            return {
                confirmedChecksum: copyBytes(
                    input.confirmedChecksum,
                    recoveryChecksumByteLength,
                    'Confirmed recovery checksum',
                ),
                preparationIdentifier: copyPreparationIdentifier(
                    input.preparationIdentifier,
                ),
            };
        }
        case 'recover': {
            if (
                !isPlainRecord(input) ||
                !hasRequiredKeys(input, [
                    'caseInsensitiveRecoveryText',
                    'externallyVerifiedCommitment',
                    'expectedSnapshot',
                ])
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Recovery worker input is malformed.',
                );
            }

            return {
                caseInsensitiveRecoveryText: copyRecoveryText(
                    input.caseInsensitiveRecoveryText,
                    false,
                ),
                externallyVerifiedCommitment: copyVerifiedCommitment(
                    input.externallyVerifiedCommitment,
                ),
                expectedSnapshot: copyOptionalSnapshot(input.expectedSnapshot),
            };
        }
    }
};

const copyHostCommandResult = (
    command: CustodyWorkerCommand,
    result: unknown,
): unknown => {
    switch (command) {
        case 'open-custody':
        case 'open-root':
        case 'cancel-recovery-export':
        case 'delete':
        case 'close':
            return validateVoidResult(result);
        case 'initialize':
            return copySnapshot(result);
        case 'recover':
            return copySnapshot(result);
        case 'current-snapshot':
            return copyOptionalSnapshot(result);
        case 'begin-recovery-export':
            return copyChallenge(result);
        case 'confirm-recovery-export':
            return copyConfirmation(result);
    }
};

const normalizeHostErrorCode = (
    error: unknown,
): BrowserActionStorageCustodyErrorCode => {
    if (
        error instanceof BrowserActionStorageCustodyError &&
        isCustodyErrorCode(error.code)
    ) {
        return error.code;
    }
    if (
        typeof error === 'object' &&
        error !== null &&
        'name' in error &&
        error.name === 'BrowserActionStorageCustodyError' &&
        'code' in error &&
        isCustodyErrorCode(error.code)
    ) {
        return error.code;
    }
    if (
        isPlainRecord(error) &&
        (error.code === 'Unavailable' || error.code === 'InvalidConfiguration')
    ) {
        return error.code === 'Unavailable' ? 'Unavailable' : 'InvalidInput';
    }

    return 'OwnedWorkerFailure';
};

/**
 * Installs the worker half of the bounded custody channel. The cryptographic
 * kernel, Web Lock handle, IndexedDB adapter, device key, wrapped envelope, and
 * plaintext root all remain in this worker realm.
 */
type BrowserActionStorageCustodyWorkerHostConfiguration = Readonly<{
    cryptoProvider?: Crypto;
    indexedDbFactory?: IDBFactory;
    keyRangeFactory?: typeof IDBKeyRange;
    lockManager?: LockManager | null;
    workerScope: CustodyWorkerScope;
}> &
    (
        | Readonly<{
              openOwnedCustody?: never;
              workerKernel: BrowserActionStorageWorkerKernel;
          }>
        | Readonly<{
              openOwnedCustody(
                  configuration: BrowserActionStorageCustodyWorkerConfiguration,
                  acquisitionSignal: AbortSignal,
              ): Promise<WebLockOwnedBrowserActionStorageCustody>;
              workerKernel?: never;
          }>
    );

export const installBrowserActionStorageCustodyWorkerHost = (
    input: BrowserActionStorageCustodyWorkerHostConfiguration,
): (() => Promise<void>) => {
    if (typeof globalThis.document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Browser action-storage custody host must run inside a dedicated worker.',
        );
    }
    let lastRequestIdentifier = 0;
    let ownedCustody: WebLockOwnedBrowserActionStorageCustody | undefined;
    let openingCustody:
        | Promise<WebLockOwnedBrowserActionStorageCustody>
        | undefined;
    let openingCustodyAbortController: AbortController | undefined;
    let operationTail: Promise<void> = Promise.resolve();
    let terminalCleanup: Promise<void> | undefined;
    let terminalFailure: BrowserActionStorageCustodyError | undefined;
    let uninstalled = false;
    const listenerHolder: {
        value?: (event: MessageEvent<unknown>) => void;
    } = {};

    const closeForTerminalFailure = async (
        originalFailure: BrowserActionStorageCustodyError,
    ): Promise<void> => {
        const cleanupFailures: unknown[] = [];
        const handles = new Set<WebLockOwnedBrowserActionStorageCustody>();
        const opening = openingCustody;
        if (opening !== undefined) {
            try {
                handles.add(await opening);
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (ownedCustody !== undefined) {
            handles.add(ownedCustody);
        }
        ownedCustody = undefined;
        const closeOutcomes = await Promise.allSettled(
            [...handles].map((handle) => handle.close()),
        );
        for (const outcome of closeOutcomes) {
            if (outcome.status === 'rejected') {
                cleanupFailures.push(outcome.reason as unknown);
            }
        }
        if (cleanupFailures.length > 0) {
            terminalFailure = new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The browser action-storage worker channel failed and custody cleanup also failed.',
                [originalFailure, ...cleanupFailures],
            );
        }
        let notificationFailure: unknown;
        try {
            input.workerScope.postMessage({
                errorCode: 'OwnedWorkerFailure',
                messageKind: 'browser-action-storage-custody-channel-failed',
            });
        } catch (error) {
            notificationFailure = error;
        }
        if (notificationFailure !== undefined) {
            terminalFailure = new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The browser action-storage worker channel failed, then its terminal notification failed.',
                [terminalFailure ?? originalFailure, notificationFailure],
            );
        }
        if (cleanupFailures.length > 0 || notificationFailure !== undefined) {
            throw terminalFailure ?? originalFailure;
        }
    };

    const failHost = (failureCause: unknown): void => {
        if (terminalFailure !== undefined) {
            return;
        }
        terminalFailure = new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The browser action-storage worker channel received invalid traffic or output.',
            failureCause,
        );
        uninstalled = true;
        openingCustodyAbortController?.abort(terminalFailure);
        if (listenerHolder.value !== undefined) {
            input.workerScope.removeEventListener(
                'message',
                listenerHolder.value,
            );
        }
        terminalCleanup = closeForTerminalFailure(terminalFailure);
        void terminalCleanup.catch(() => undefined);
    };

    const custody = (): BrowserActionStorageCustody => {
        if (ownedCustody === undefined) {
            throw new BrowserActionStorageCustodyError(
                'Closed',
                'Browser action-storage custody is not open in this worker.',
            );
        }

        return ownedCustody.custody;
    };

    const execute = async (
        request: CustodyWorkerRequest,
        copiedInput: unknown,
    ): Promise<unknown> => {
        switch (request.command) {
            case 'open-custody': {
                if (ownedCustody !== undefined) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'Browser action-storage custody is already open in this worker.',
                    );
                }
                const configuration =
                    copiedInput as BrowserActionStorageCustodyWorkerConfiguration;
                const acquisitionAbortController = new AbortController();
                openingCustodyAbortController = acquisitionAbortController;
                const opening =
                    input.openOwnedCustody === undefined
                        ? openWebLockOwnedBrowserActionStorageCustody({
                              acquisitionDeadlineEpochMilliseconds:
                                  configuration.acquisitionDeadlineEpochMilliseconds,
                              acquisitionSignal:
                                  acquisitionAbortController.signal,
                              binding: configuration.binding,
                              cryptoProvider: input.cryptoProvider,
                              databaseName: configuration.databaseName,
                              indexedDbFactory: input.indexedDbFactory,
                              keyRangeFactory: input.keyRangeFactory,
                              limits: configuration.limits,
                              lockManager: input.lockManager,
                              knownStorageRootCommitment:
                                  configuration.knownStorageRootCommitment,
                              namespace: configuration.namespace,
                              workerKernel: input.workerKernel,
                          })
                        : input.openOwnedCustody(
                              configuration,
                              acquisitionAbortController.signal,
                          );
                openingCustody = opening;
                let openedCustody: WebLockOwnedBrowserActionStorageCustody;
                try {
                    openedCustody = await opening;
                } finally {
                    if (openingCustody === opening) {
                        openingCustody = undefined;
                    }
                    if (
                        openingCustodyAbortController ===
                        acquisitionAbortController
                    ) {
                        openingCustodyAbortController = undefined;
                    }
                }
                if (terminalFailure !== undefined) {
                    await openedCustody.close();
                    throw terminalFailure;
                }
                ownedCustody = openedCustody;
                return undefined;
            }
            case 'initialize':
                return custody().initialize();
            case 'current-snapshot':
                return custody().currentSnapshot();
            case 'open-root':
                return custody().openIntoOwnedWorker(
                    copiedInput as {
                        expectedSnapshot: BrowserDeviceWrappingSnapshot;
                        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
                    },
                );
            case 'begin-recovery-export':
                return custody().beginRecoveryExport(
                    copiedInput as {
                        expectedSnapshot: BrowserDeviceWrappingSnapshot;
                        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
                    },
                );
            case 'confirm-recovery-export':
                return custody().confirmRecoveryExport(
                    copiedInput as {
                        confirmedChecksum: Uint8Array;
                        preparationIdentifier: string;
                    },
                );
            case 'cancel-recovery-export':
                return custody().cancelRecoveryExport(copiedInput as string);
            case 'recover':
                return custody().recover(
                    copiedInput as {
                        caseInsensitiveRecoveryText: string;
                        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
                        expectedSnapshot?: BrowserDeviceWrappingSnapshot;
                    },
                );
            case 'delete':
                return custody().delete(
                    copiedInput as BrowserDeviceWrappingSnapshot,
                );
            case 'close': {
                const handle = ownedCustody;
                ownedCustody = undefined;
                await handle?.close();
                return undefined;
            }
        }
    };

    const handleRequest = async (
        request: CustodyWorkerRequest,
    ): Promise<void> => {
        if (terminalFailure !== undefined) {
            return;
        }
        let copiedInput: unknown;
        try {
            copiedInput = copyHostCommandInput(request.command, request.input);
        } catch (error) {
            failHost(error);
            return;
        }
        let result: unknown;
        try {
            result = await execute(request, copiedInput);
        } catch (error) {
            if (terminalFailure !== undefined) {
                return;
            }
            try {
                input.workerScope.postMessage({
                    errorCode: normalizeHostErrorCode(error),
                    messageKind: 'browser-action-storage-custody-failed',
                    requestIdentifier: request.requestIdentifier,
                });
            } catch (postError) {
                failHost([error, postError]);
            }
            return;
        }
        if (terminalFailure !== undefined) {
            return;
        }
        let copiedResult: unknown;
        try {
            copiedResult = copyHostCommandResult(request.command, result);
        } catch (error) {
            failHost(error);
            return;
        }
        try {
            input.workerScope.postMessage({
                messageKind: 'browser-action-storage-custody-completed',
                requestIdentifier: request.requestIdentifier,
                result: copiedResult,
            });
        } catch (error) {
            failHost(error);
        }
    };

    const listener = (event: MessageEvent<unknown>): void => {
        if (uninstalled) {
            return;
        }
        const request = event.data;
        if (
            !isCustodyWorkerRequest(request) ||
            request.requestIdentifier <= lastRequestIdentifier
        ) {
            failHost(
                new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The browser action-storage worker received a malformed, duplicate, or nonmonotonic request.',
                ),
            );
            return;
        }
        lastRequestIdentifier = request.requestIdentifier;
        operationTail = operationTail.then(
            () => handleRequest(request),
            () => handleRequest(request),
        );
    };

    listenerHolder.value = listener;
    input.workerScope.addEventListener('message', listener);

    return async (): Promise<void> => {
        if (uninstalled) {
            await terminalCleanup;
            return;
        }
        uninstalled = true;
        input.workerScope.removeEventListener('message', listener);
        await operationTail;
        const handle = ownedCustody;
        ownedCustody = undefined;
        await handle?.close();
    };
};
