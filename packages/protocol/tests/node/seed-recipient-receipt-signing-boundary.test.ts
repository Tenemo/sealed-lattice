import type {
    BrowserLocalMailboxCapability,
    BrowserLocalSigningCapability,
} from '@sealed-lattice/crypto';
import type {
    OpenProductionSeedRecipientReceiptKernelInput,
    ProductionSeedRecipientReceiptKernel,
} from '@sealed-lattice/wasm';
import { beforeEach, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
    assertRecipientKeys: vi.fn(),
    decapsulate: vi.fn(),
    openKernel: vi.fn(),
    signReceipt: vi.fn(),
}));

vi.mock('@sealed-lattice/crypto', () => ({
    assertSeedRecipientReceiptCapabilitiesMatchRosterKeys:
        mocks.assertRecipientKeys,
    decapsulateSeedRecipientMailboxCiphertext: mocks.decapsulate,
    signSeedRecipientReceiptBody: mocks.signReceipt,
}));

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionSeedRecipientReceiptKernel: () => true,
    openProductionSeedRecipientReceiptKernel: mocks.openKernel,
}));

import type { RuntimeRecordProtection } from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { AuthenticatedStorageRecencyCoordinator } from '#packages/protocol/src/runtime/authenticated-storage-recency';
import {
    openBrowserLocalSeedRecipientReceiptKernel,
    SeedRecipientAuthenticationCustody,
} from '#packages/protocol/src/runtime/seed-recipient-authentication-custody';
import type { UntrustedStorageTransactionStore } from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';

beforeEach(() => {
    mocks.assertRecipientKeys.mockReset();
    mocks.decapsulate.mockReset();
    mocks.openKernel.mockReset();
    mocks.signReceipt.mockReset();
});

it('binds recipient decapsulation and receipt signing to one browser-local participant', async () => {
    const productionKernel = Object.freeze({
        authenticatedInventoryAuthorization: () => Object.freeze({}),
        close: (): void => undefined,
        prepare: (): never => {
            throw new Error('The binding test does not prepare a receipt.');
        },
        produce: (): never => {
            throw new Error('The binding test does not produce a receipt.');
        },
        validate: (): void => undefined,
    }) as unknown as ProductionSeedRecipientReceiptKernel;
    let openedInput: OpenProductionSeedRecipientReceiptKernelInput | undefined;
    mocks.openKernel.mockImplementation(
        (
            _kernelUrl: URL,
            input: OpenProductionSeedRecipientReceiptKernelInput,
        ) => {
            openedInput = input;
            return Promise.resolve(productionKernel);
        },
    );
    const mailboxCapability = Object.freeze(
        {},
    ) as BrowserLocalMailboxCapability;
    const signingCapability = Object.freeze(
        {},
    ) as BrowserLocalSigningCapability;
    const carrier = Object.freeze({
        encryptedChunks: Object.freeze([Uint8Array.of(0x11)]),
        headerBytes: Uint8Array.of(0x12),
        manifestBytes: Uint8Array.of(0x13),
        senderPosition: 0,
        signatureEnvelopeBytes: Uint8Array.of(0x14),
    });
    const parameterIdentity = new Uint8Array(64).fill(0x21);
    const preparationContextBytes = Uint8Array.of(0x22);
    const rootPackage = Object.freeze({
        contributorSignatureEnvelopeBytes: Uint8Array.of(0x23),
        exactOutputCertificateBytes: Uint8Array.of(0x24),
        reservationCertificateBytes: Uint8Array.of(0x25),
        rootBodyBytes: Uint8Array.of(0x26),
    });
    const rootTerminalCertificateBytes = Uint8Array.of(0x27);
    const rosterBytes = Uint8Array.of(0x28);
    const authenticationCustody = new SeedRecipientAuthenticationCustody({
        context: Object.freeze({
            parameterIdentity: parameterIdentity.slice(),
            participantCount: 4,
            preparationAttemptOrdinal: 0,
            preparationContextIdentity: new Uint8Array(64).fill(0x29),
            recipientPosition: 1,
            rootTerminalIdentity: new Uint8Array(64).fill(0x2a),
        }),
        limits: Object.freeze({
            maximumCanonicalOpenRequestByteLength: 1_024,
            transactionLifetimeMilliseconds: 1_000,
        }),
        protection: Object.freeze({}) as RuntimeRecordProtection,
        recencyCoordinator: new AuthenticatedStorageRecencyCoordinator({
            anchor: Object.freeze({
                compareAndSet: () => Promise.resolve(false),
                read: () => Promise.resolve(undefined),
            }),
            store: Object.freeze({}) as UntrustedStorageTransactionStore,
        }),
    });

    await expect(
        openBrowserLocalSeedRecipientReceiptKernel(
            new URL('https://example.invalid/kernel.wasm'),
            {
                authenticationCustody,
                carriers: [carrier],
                mailboxCapability,
                parameterIdentity,
                preparationContextBytes,
                recipientPosition: 1,
                rootAuthorizationPackages: [rootPackage],
                rootTerminalCertificateBytes,
                rosterBytes,
                signingCapability,
            },
        ),
    ).resolves.toBe(productionKernel);
    expect(mocks.openKernel).toHaveBeenCalledTimes(1);
    expect(openedInput).toMatchObject({
        carriers: [carrier],
        parameterIdentity,
        preparationContextBytes,
        recipientPosition: 1,
        rootAuthorizationPackages: [rootPackage],
        rootTerminalCertificateBytes,
        rosterBytes,
    });
    expect(
        typeof openedInput?.stateOperations.retainAuthenticatedInconsistency,
    ).toBe('function');
    expect(
        typeof openedInput?.stateOperations.retainVerifiedPublicSelection,
    ).toBe('function');

    const mailboxEncapsulationKey = new Uint8Array(1_184).fill(0x31);
    const recipientSigningVerificationKey = new Uint8Array(1_952).fill(0x32);
    openedInput?.keyOperations.assertMatchesRecipientKeys({
        mailboxEncapsulationKey,
        recipientSigningVerificationKey,
    });
    expect(mocks.assertRecipientKeys).toHaveBeenCalledWith({
        mailboxCapability,
        mailboxEncapsulationKey,
        recipientSigningVerificationKey,
        signingCapability,
    });

    const ciphertext = new Uint8Array(1_088).fill(0x41);
    const sharedSecret = new Uint8Array(32).fill(0x42);
    mocks.decapsulate.mockReturnValue(sharedSecret);
    expect(
        openedInput?.keyOperations.decapsulateMailboxCiphertext({
            ciphertext,
            mailboxEncapsulationKey,
        }),
    ).toBe(sharedSecret);
    expect(mocks.decapsulate).toHaveBeenCalledWith({
        ciphertext,
        mailboxCapability,
        mailboxEncapsulationKey,
    });

    const receiptBodyBytes = new Uint8Array(374).fill(0x51);
    const signatureRandomness = new Uint8Array(32).fill(0x52);
    const signature = new Uint8Array(3_309).fill(0x53);
    mocks.signReceipt.mockReturnValue(signature);
    expect(
        openedInput?.keyOperations.signReceiptBody({
            receiptBodyBytes,
            recipientSigningVerificationKey,
            signatureRandomness,
        }),
    ).toBe(signature);
    expect(mocks.signReceipt).toHaveBeenCalledWith({
        receiptBodyBytes,
        recipientSigningVerificationKey,
        signatureRandomness,
        signingCapability,
    });
});
