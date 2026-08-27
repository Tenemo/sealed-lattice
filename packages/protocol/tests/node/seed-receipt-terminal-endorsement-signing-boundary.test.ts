import type { BrowserLocalSigningCapability } from '@sealed-lattice/crypto';
import type {
    OpenProductionSeedReceiptTerminalEndorsementKernelInput,
    ProductionSeedReceiptTerminalEndorsementKernel,
} from '@sealed-lattice/wasm';
import { beforeEach, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
    assertSigningKey: vi.fn(),
    consumeReceiptAuthorization: vi.fn(),
    openKernel: vi.fn(),
    signEndorsement: vi.fn(),
}));

vi.mock('@sealed-lattice/crypto', () => ({
    assertSeedReceiptTerminalEndorsementSigningCapabilityMatchesRosterKey:
        mocks.assertSigningKey,
    signSeedReceiptTerminalEndorsementBody: mocks.signEndorsement,
}));

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionSeedReceiptTerminalEndorsementKernel: () => true,
    openProductionSeedReceiptTerminalEndorsementKernel: mocks.openKernel,
}));

vi.mock('../../src/runtime/seed-recipient-receipt-custody.js', () => ({
    consumeSeedRecipientReceiptTerminalEndorsementAuthorization:
        mocks.consumeReceiptAuthorization,
}));

import { openBrowserLocalSeedReceiptTerminalEndorsementKernel } from '#packages/protocol/src/runtime/seed-receipt-terminal-endorsement-custody';

beforeEach(() => {
    mocks.assertSigningKey.mockReset();
    mocks.consumeReceiptAuthorization.mockReset();
    mocks.openKernel.mockReset();
    mocks.signEndorsement.mockReset();
});

it('binds the fixed terminal-endorsement operation to completed receipt custody and one browser-local capability', async () => {
    const productionKernel = Object.freeze({
        close: (): void => undefined,
        prepare: (): never => {
            throw new Error(
                'The binding test does not prepare an endorsement.',
            );
        },
        produce: (): never => {
            throw new Error(
                'The binding test does not produce an endorsement.',
            );
        },
        validate: (): void => undefined,
    }) as unknown as ProductionSeedReceiptTerminalEndorsementKernel;
    const receiptContext = Object.freeze({
        parameterIdentity: new Uint8Array(64).fill(0x21),
        participantCount: 10,
        preparationAttemptOrdinal: 0,
        preparationContextIdentity: new Uint8Array(64).fill(0xa2),
        recipientPosition: 3,
        rootTerminalIdentity: new Uint8Array(64).fill(0xa3),
    });
    const receiptRecordBytes = new Uint8Array(73).fill(0xb1);
    const receiptCustodyAuthorization = Object.freeze({});
    mocks.consumeReceiptAuthorization.mockResolvedValue({
        context: receiptContext,
        recordBytes: receiptRecordBytes,
    });
    let openedInput:
        | OpenProductionSeedReceiptTerminalEndorsementKernelInput
        | undefined;
    mocks.openKernel.mockImplementation(
        (
            _kernelUrl: URL,
            input: OpenProductionSeedReceiptTerminalEndorsementKernelInput,
        ) => {
            expect(input.endorserPosition).toBe(3);
            expect(input.parameterIdentity).toEqual(parameterIdentity);
            expect(input.preparationContextBytes).toEqual(
                preparationContextBytes,
            );
            expect(input.receiptCustodyContext).toEqual(receiptContext);
            expect(input.receiptCustodyRecordBytes).toEqual(receiptRecordBytes);
            expect(input.receiptEnvelopeBytes).toEqual([receiptEnvelopeBytes]);
            expect(input.rootAuthorizationPackages).toEqual([
                {
                    contributorSignatureEnvelopeBytes,
                    exactOutputCertificateBytes,
                    reservationCertificateBytes,
                    rootBodyBytes,
                },
            ]);
            expect(input.rootTerminalCertificateBytes).toEqual(
                rootTerminalCertificateBytes,
            );
            expect(input.rosterBytes).toEqual(rosterBytes);
            openedInput = input;
            return Promise.resolve(productionKernel);
        },
    );
    const signingCapability = Object.freeze(
        {},
    ) as BrowserLocalSigningCapability;
    const kernelUrl = new URL('https://example.invalid/kernel.wasm');
    const parameterIdentity = new Uint8Array(64).fill(0x21);
    const preparationContextBytes = Uint8Array.of(0x31);
    const rootBodyBytes = Uint8Array.of(0x41);
    const reservationCertificateBytes = Uint8Array.of(0x51);
    const exactOutputCertificateBytes = Uint8Array.of(0x61);
    const contributorSignatureEnvelopeBytes = Uint8Array.of(0x71);
    const rootTerminalCertificateBytes = Uint8Array.of(0x81);
    const receiptEnvelopeBytes = Uint8Array.of(0x91);
    const rosterBytes = Uint8Array.of(0xa1);

    await expect(
        openBrowserLocalSeedReceiptTerminalEndorsementKernel(kernelUrl, {
            endorserPosition: 3,
            parameterIdentity,
            preparationContextBytes,
            receiptCustodyAuthorization: receiptCustodyAuthorization as never,
            receiptEnvelopeBytes: [receiptEnvelopeBytes],
            rootAuthorizationPackages: [
                {
                    contributorSignatureEnvelopeBytes,
                    exactOutputCertificateBytes,
                    reservationCertificateBytes,
                    rootBodyBytes,
                },
            ],
            rootTerminalCertificateBytes,
            rosterBytes,
            signingCapability,
        }),
    ).resolves.toBe(productionKernel);
    expect(mocks.consumeReceiptAuthorization).toHaveBeenCalledExactlyOnceWith(
        receiptCustodyAuthorization,
    );
    expect(mocks.openKernel).toHaveBeenCalledTimes(1);

    const endorserSigningVerificationKey = new Uint8Array(1_952).fill(0xb1);
    openedInput?.signingOperations.assertMatchesEndorserVerificationKey({
        endorserSigningVerificationKey,
    });
    expect(mocks.assertSigningKey).toHaveBeenCalledWith({
        endorserSigningVerificationKey,
        signingCapability,
    });

    const endorsementAuthorizationBodyBytes = new Uint8Array(174).fill(0xc1);
    const signatureRandomness = new Uint8Array(32).fill(0xd1);
    const signature = new Uint8Array(3_309).fill(0xe1);
    mocks.signEndorsement.mockReturnValue(signature);
    expect(
        openedInput?.signingOperations.signEndorsementBody({
            endorsementAuthorizationBodyBytes,
            endorserSigningVerificationKey,
            signatureRandomness,
        }),
    ).toBe(signature);
    expect(mocks.signEndorsement).toHaveBeenCalledWith({
        endorsementAuthorizationBodyBytes,
        endorserSigningVerificationKey,
        signatureRandomness,
        signingCapability,
    });
});
