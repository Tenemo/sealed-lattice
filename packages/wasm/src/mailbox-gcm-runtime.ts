import { foundationProfile } from '@sealed-lattice/types';

import {
    CanonicalStreamCleanupError,
    canonicalStreamKernelContext,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    type CanonicalStreamKernelContext,
} from './canonical-stream-runtime.js';
import type { TranscriptCoreKernelContextOwner } from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const mailboxGcmKeyByteLength = 32;
const mailboxGcmNonceByteLength = 12;
const mailboxGcmTagByteLength = 16;
const maximumMailboxAssociatedDataByteLength = 65_536;
const wasm32WordByteLength = 4;

export type MailboxGcmLeaseState =
    | 'active'
    | 'authenticating'
    | 'cancelled'
    | 'completed'
    | 'decrypting'
    | 'failed';

export type MailboxGcmEncryptorLease = Readonly<{
    readonly totalByteLength: number;
    cancel(): void;
    encryptChunk(bytes: ArrayBuffer): void;
    finish(): Uint8Array;
    state(): MailboxGcmLeaseState;
}>;

export type MailboxGcmVerifierLease = Readonly<{
    readonly totalByteLength: number;
    authenticateChunk(bytes: ArrayBuffer): void;
    cancel(): void;
    decryptChunk(bytes: ArrayBuffer): void;
    finishAuthentication(tag: Uint8Array): void;
    finishDecryption(): void;
    state(): MailboxGcmLeaseState;
}>;

export type MailboxGcmRuntime = Readonly<{
    openEncryptor(input: {
        readonly associatedData: Uint8Array;
        readonly key: Uint8Array;
        readonly nonce: Uint8Array;
        readonly totalByteLength: number;
    }): MailboxGcmEncryptorLease;
    openVerifier(input: {
        readonly associatedData: Uint8Array;
        readonly key: Uint8Array;
        readonly nonce: Uint8Array;
        readonly totalByteLength: number;
    }): MailboxGcmVerifierLease;
}>;

type RequiredMailboxGcmKernelContext = CanonicalStreamKernelContext &
    Required<
        Pick<
            CanonicalStreamKernelContext,
            | 'mailboxGcmAuthenticateChunk'
            | 'mailboxGcmBeginEncryptor'
            | 'mailboxGcmBeginVerifier'
            | 'mailboxGcmCancel'
            | 'mailboxGcmDecryptChunk'
            | 'mailboxGcmEncryptChunk'
            | 'mailboxGcmFinishAuthentication'
            | 'mailboxGcmFinishDecryptor'
            | 'mailboxGcmFinishEncryptor'
        >
    >;

type ActiveMailboxGcmLease = {
    handle: number;
    kind: 'encryptor' | 'verifier';
    state: MailboxGcmLeaseState;
    totalByteLength: number;
};

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const isArrayBuffer = (value: unknown): value is ArrayBuffer =>
    Object.prototype.toString.call(value) === '[object ArrayBuffer]';

const requireExactBytes = (
    value: Uint8Array,
    expectedByteLength: number,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== expectedByteLength) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value;
};

const requireAssociatedData = (value: Uint8Array): Uint8Array => {
    if (
        !isUint8Array(value) ||
        value.byteLength === 0 ||
        value.byteLength > maximumMailboxAssociatedDataByteLength
    ) {
        throw new CanonicalStreamRefusalError(
            value.byteLength > maximumMailboxAssociatedDataByteLength
                ? 'outsideSupportedProfile'
                : 'wrongTypeOrLength',
        );
    }
    return value;
};

const requireTotalByteLength = (value: number): number => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    if (value > foundationProfile.maximumCanonicalStreamByteLength) {
        throw new CanonicalStreamResourceError(
            'The mailbox ciphertext exceeds the canonical stream profile.',
        );
    }
    return value;
};

const requireMailboxContext = (
    context: CanonicalStreamKernelContext,
): RequiredMailboxGcmKernelContext => {
    const requiredFunctions = [
        context.mailboxGcmAuthenticateChunk,
        context.mailboxGcmBeginEncryptor,
        context.mailboxGcmBeginVerifier,
        context.mailboxGcmCancel,
        context.mailboxGcmDecryptChunk,
        context.mailboxGcmEncryptChunk,
        context.mailboxGcmFinishAuthentication,
        context.mailboxGcmFinishDecryptor,
        context.mailboxGcmFinishEncryptor,
    ];
    if (requiredFunctions.some((value) => value === undefined)) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the mailbox GCM boundary.',
        );
    }
    return context as RequiredMailboxGcmKernelContext;
};

class MailboxGcmRuntimeImplementation implements MailboxGcmRuntime {
    readonly #context: RequiredMailboxGcmKernelContext;
    readonly #memoryBoundary: WasmMemoryBoundary;
    readonly #statusBoundary: WasmStatusBoundary;
    #activeLease: ActiveMailboxGcmLease | undefined;

    public constructor(context: RequiredMailboxGcmKernelContext) {
        this.#context = context;
        this.#memoryBoundary = new WasmMemoryBoundary({
            context,
            createInternalError: (message) =>
                new CanonicalStreamInternalError(message),
            createResourceError: (message) =>
                new CanonicalStreamResourceError(message),
            label: 'mailbox GCM',
        });
        this.#statusBoundary = new WasmStatusBoundary({
            createInternalError: (message) =>
                new CanonicalStreamInternalError(message),
            createRefusalError: (refusalReason) =>
                new CanonicalStreamRefusalError(refusalReason),
            createResourceError: () => new CanonicalStreamResourceError(),
            internalFailureMessage:
                'The mailbox GCM kernel session failed internally.',
            unknownStatusMessage:
                'The mailbox GCM kernel returned an unknown status code.',
        });
    }

    public openEncryptor(input: {
        readonly associatedData: Uint8Array;
        readonly key: Uint8Array;
        readonly nonce: Uint8Array;
        readonly totalByteLength: number;
    }): MailboxGcmEncryptorLease {
        const lease = this.#begin('encryptor', input);
        return Object.freeze({
            cancel: (): void => this.#cancelLease(lease),
            encryptChunk: (bytes: ArrayBuffer): void =>
                this.#transformChunk(lease, bytes, 'encrypt'),
            finish: (): Uint8Array => this.#finishEncryption(lease),
            state: (): MailboxGcmLeaseState => lease.state,
            totalByteLength: lease.totalByteLength,
        });
    }

    public openVerifier(input: {
        readonly associatedData: Uint8Array;
        readonly key: Uint8Array;
        readonly nonce: Uint8Array;
        readonly totalByteLength: number;
    }): MailboxGcmVerifierLease {
        const lease = this.#begin('verifier', input);
        lease.state = 'authenticating';
        return Object.freeze({
            authenticateChunk: (bytes: ArrayBuffer): void =>
                this.#authenticateChunk(lease, bytes),
            cancel: (): void => this.#cancelLease(lease),
            decryptChunk: (bytes: ArrayBuffer): void =>
                this.#transformChunk(lease, bytes, 'decrypt'),
            finishAuthentication: (tag: Uint8Array): void =>
                this.#finishAuthentication(lease, tag),
            finishDecryption: (): void => this.#finishDecryption(lease),
            state: (): MailboxGcmLeaseState => lease.state,
            totalByteLength: lease.totalByteLength,
        });
    }

    #begin(
        kind: 'encryptor' | 'verifier',
        input: {
            readonly associatedData: Uint8Array;
            readonly key: Uint8Array;
            readonly nonce: Uint8Array;
            readonly totalByteLength: number;
        },
    ): ActiveMailboxGcmLease {
        if (this.#activeLease !== undefined) {
            throw new CanonicalStreamResourceError(
                'Only one mailbox GCM operation may be active in a WASM instance.',
            );
        }
        const key = requireExactBytes(input.key, mailboxGcmKeyByteLength);
        const nonce = requireExactBytes(input.nonce, mailboxGcmNonceByteLength);
        const associatedData = requireAssociatedData(input.associatedData);
        const totalByteLength = requireTotalByteLength(input.totalByteLength);
        let keyPointer = 0;
        let noncePointer = 0;
        let associatedDataPointer = 0;
        let statusPointer = 0;
        let handle = 0;
        try {
            keyPointer = this.#copyIntoWasm(key);
            noncePointer = this.#copyIntoWasm(nonce);
            associatedDataPointer = this.#copyIntoWasm(associatedData);
            statusPointer = this.#memoryBoundary.allocateZeroedWords(1);
            handle = this.#context.runExclusive(
                `mailbox GCM ${kind} begin`,
                () =>
                    (kind === 'encryptor'
                        ? this.#context.mailboxGcmBeginEncryptor
                        : this.#context.mailboxGcmBeginVerifier)(
                        keyPointer,
                        key.byteLength,
                        noncePointer,
                        nonce.byteLength,
                        associatedDataPointer,
                        associatedData.byteLength,
                        totalByteLength,
                        statusPointer,
                    ),
            );
            const [status] = this.#memoryBoundary.readWords(statusPointer, 1);
            this.#statusBoundary.throwIfError(status);
            if (handle === 0) {
                throw new CanonicalStreamInternalError(
                    'The mailbox GCM kernel returned an invalid session handle.',
                );
            }
            const lease: ActiveMailboxGcmLease = {
                handle,
                kind,
                state: 'active',
                totalByteLength,
            };
            this.#activeLease = lease;
            return lease;
        } catch (error) {
            if (handle !== 0) {
                return this.#cancelUnactivated(handle, error);
            }
            throw error;
        } finally {
            this.#zeroAndDeallocate(keyPointer, key.byteLength);
            this.#zeroAndDeallocate(noncePointer, nonce.byteLength);
            this.#zeroAndDeallocate(
                associatedDataPointer,
                associatedData.byteLength,
            );
            this.#zeroAndDeallocate(statusPointer, wasm32WordByteLength);
        }
    }

    #authenticateChunk(lease: ActiveMailboxGcmLease, bytes: ArrayBuffer): void {
        this.#requireState(lease, 'verifier', 'authenticating');
        const byteLength = this.#requireChunk(bytes);
        let pointer = 0;
        try {
            pointer = this.#copyIntoWasm(new Uint8Array(bytes));
            const status = this.#context.runExclusive(
                'mailbox GCM authenticate chunk',
                () =>
                    this.#context.mailboxGcmAuthenticateChunk(
                        lease.handle,
                        pointer,
                        byteLength,
                    ),
            );
            this.#statusBoundary.throwIfError(status);
        } catch (error) {
            return this.#failLease(lease, error);
        } finally {
            this.#zeroAndDeallocate(pointer, byteLength);
        }
    }

    #transformChunk(
        lease: ActiveMailboxGcmLease,
        bytes: ArrayBuffer,
        operation: 'decrypt' | 'encrypt',
    ): void {
        this.#requireState(
            lease,
            operation === 'encrypt' ? 'encryptor' : 'verifier',
            operation === 'encrypt' ? 'active' : 'decrypting',
        );
        const byteLength = this.#requireChunk(bytes);
        let pointer = 0;
        try {
            pointer = this.#copyIntoWasm(new Uint8Array(bytes));
            const status = this.#context.runExclusive(
                `mailbox GCM ${operation} chunk`,
                () =>
                    (operation === 'encrypt'
                        ? this.#context.mailboxGcmEncryptChunk
                        : this.#context.mailboxGcmDecryptChunk)(
                        lease.handle,
                        pointer,
                        byteLength,
                    ),
            );
            this.#statusBoundary.throwIfError(status);
            new Uint8Array(bytes).set(
                new Uint8Array(
                    this.#context.memory.buffer,
                    pointer,
                    byteLength,
                ),
            );
        } catch (error) {
            new Uint8Array(bytes).fill(0);
            return this.#failLease(lease, error);
        } finally {
            this.#zeroAndDeallocate(pointer, byteLength);
        }
    }

    #finishEncryption(lease: ActiveMailboxGcmLease): Uint8Array {
        this.#requireState(lease, 'encryptor', 'active');
        let tagPointer = 0;
        try {
            tagPointer = this.#allocate(mailboxGcmTagByteLength);
            const status = this.#context.runExclusive(
                'mailbox GCM encryption finish',
                () =>
                    this.#context.mailboxGcmFinishEncryptor(
                        lease.handle,
                        tagPointer,
                        mailboxGcmTagByteLength,
                    ),
            );
            this.#statusBoundary.throwIfError(status);
            const tag = new Uint8Array(mailboxGcmTagByteLength);
            tag.set(
                new Uint8Array(
                    this.#context.memory.buffer,
                    tagPointer,
                    mailboxGcmTagByteLength,
                ),
            );
            this.#completeLease(lease);
            return tag;
        } catch (error) {
            return this.#failLease(lease, error);
        } finally {
            this.#zeroAndDeallocate(tagPointer, mailboxGcmTagByteLength);
        }
    }

    #finishAuthentication(lease: ActiveMailboxGcmLease, tag: Uint8Array): void {
        this.#requireState(lease, 'verifier', 'authenticating');
        const canonicalTag = requireExactBytes(tag, mailboxGcmTagByteLength);
        let tagPointer = 0;
        try {
            tagPointer = this.#copyIntoWasm(canonicalTag);
            const status = this.#context.runExclusive(
                'mailbox GCM authentication finish',
                () =>
                    this.#context.mailboxGcmFinishAuthentication(
                        lease.handle,
                        tagPointer,
                        canonicalTag.byteLength,
                    ),
            );
            this.#statusBoundary.throwIfError(status);
            lease.state = 'decrypting';
        } catch (error) {
            return this.#failLease(lease, error);
        } finally {
            this.#zeroAndDeallocate(tagPointer, canonicalTag.byteLength);
        }
    }

    #finishDecryption(lease: ActiveMailboxGcmLease): void {
        this.#requireState(lease, 'verifier', 'decrypting');
        try {
            const status = this.#context.runExclusive(
                'mailbox GCM decryption finish',
                () => this.#context.mailboxGcmFinishDecryptor(lease.handle),
            );
            this.#statusBoundary.throwIfError(status);
            this.#completeLease(lease);
        } catch (error) {
            return this.#failLease(lease, error);
        }
    }

    #cancelLease(lease: ActiveMailboxGcmLease): void {
        if (
            lease.state === 'cancelled' ||
            lease.state === 'completed' ||
            lease.state === 'failed'
        ) {
            return;
        }
        this.#requireActiveLease(lease);
        try {
            const status = this.#context.runExclusive(
                'mailbox GCM cancellation',
                () => this.#context.mailboxGcmCancel(lease.handle),
            );
            this.#statusBoundary.throwIfError(status);
            lease.state = 'cancelled';
            this.#activeLease = undefined;
        } catch (error) {
            return this.#failLease(lease, error);
        }
    }

    #completeLease(lease: ActiveMailboxGcmLease): void {
        this.#requireActiveLease(lease);
        lease.state = 'completed';
        this.#activeLease = undefined;
    }

    #failLease(lease: ActiveMailboxGcmLease, operationFailure: unknown): never {
        let cleanupFailure: unknown;
        if (this.#activeLease === lease) {
            try {
                const status = this.#context.runExclusive(
                    'mailbox GCM failure cleanup',
                    () => this.#context.mailboxGcmCancel(lease.handle),
                );
                if (!this.#statusBoundary.isInvalidSession(status)) {
                    this.#statusBoundary.throwIfError(status);
                }
            } catch (error) {
                cleanupFailure = error;
            }
            this.#activeLease = undefined;
        }
        lease.state = 'failed';
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }

    #cancelUnactivated(handle: number, operationFailure: unknown): never {
        try {
            const status = this.#context.runExclusive(
                'mailbox GCM begin failure cleanup',
                () => this.#context.mailboxGcmCancel(handle),
            );
            this.#statusBoundary.throwIfError(status);
        } catch (cleanupFailure) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }

    #requireState(
        lease: ActiveMailboxGcmLease,
        kind: ActiveMailboxGcmLease['kind'],
        state: MailboxGcmLeaseState,
    ): void {
        this.#requireActiveLease(lease);
        if (lease.kind !== kind || lease.state !== state) {
            throw new CanonicalStreamInternalError(
                'The mailbox GCM lease is in the wrong lifecycle state.',
            );
        }
    }

    #requireActiveLease(lease: ActiveMailboxGcmLease): void {
        if (this.#activeLease !== lease) {
            throw new CanonicalStreamInternalError(
                'The mailbox GCM lease is no longer active.',
            );
        }
    }

    #requireChunk(bytes: ArrayBuffer): number {
        if (!isArrayBuffer(bytes) || bytes.byteLength === 0) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        if (
            bytes.byteLength > foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw new CanonicalStreamResourceError(
                'A mailbox GCM fragment exceeds the copied-buffer profile.',
            );
        }
        return bytes.byteLength;
    }

    #copyIntoWasm(bytes: Uint8Array): number {
        return this.#memoryBoundary.copy(bytes);
    }

    #allocate(byteLength: number): number {
        return this.#memoryBoundary.allocate(byteLength);
    }

    #zeroAndDeallocate(pointer: number, byteLength: number): void {
        this.#memoryBoundary.zeroAndDeallocate(pointer, byteLength);
    }
}

export const openMailboxGcmRuntime = (input: {
    readonly kernel: TranscriptCoreKernelContextOwner;
}): MailboxGcmRuntime => {
    const context = canonicalStreamKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel has no registered runtime boundary.',
        );
    }
    return Object.freeze(
        new MailboxGcmRuntimeImplementation(requireMailboxContext(context)),
    );
};
