import type { BrowserLocalSigningCapability } from '@sealed-lattice/crypto';
import type {
    OpenProductionSeedMailboxSenderStreamKernelInput,
    ProductionSeedMailboxSenderStreamKernel,
} from '@sealed-lattice/wasm';
import { beforeEach, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
    assertSigningKey: vi.fn(),
    openKernel: vi.fn(),
    signManifest: vi.fn(),
}));

vi.mock('@sealed-lattice/crypto', () => ({
    assertSeedMailboxSenderSigningCapabilityMatchesRosterKey:
        mocks.assertSigningKey,
    signSeedMailboxManifestBody: mocks.signManifest,
}));

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionSeedMailboxSenderStreamKernel: () => true,
    openProductionSeedMailboxSenderStreamKernel: mocks.openKernel,
}));

import { openBrowserLocalSeedMailboxSenderStreamKernel } from '#packages/protocol/src/runtime/seed-mailbox-sender-stream-custody';

beforeEach(() => {
    mocks.assertSigningKey.mockReset();
    mocks.openKernel.mockReset();
    mocks.signManifest.mockReset();
});

it('binds the fixed sender-manifest operations to one opaque browser-local capability', async () => {
    const productionKernel = Object.freeze({
        close: (): void => undefined,
        produce: (): never => {
            throw new Error('The binding test does not produce a carrier.');
        },
        validate: (): void => undefined,
    }) as unknown as ProductionSeedMailboxSenderStreamKernel;
    let openedInput:
        | OpenProductionSeedMailboxSenderStreamKernelInput
        | undefined;
    mocks.openKernel.mockImplementation(
        (
            _kernelUrl: URL,
            input: OpenProductionSeedMailboxSenderStreamKernelInput,
        ) => {
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
    const rosterBytes = Uint8Array.of(0x91);

    await expect(
        openBrowserLocalSeedMailboxSenderStreamKernel(kernelUrl, {
            parameterIdentity,
            preparationContextBytes,
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
            senderPosition: 3,
            signingCapability,
        }),
    ).resolves.toBe(productionKernel);
    expect(mocks.openKernel).toHaveBeenCalledExactlyOnceWith(
        kernelUrl,
        expect.objectContaining({
            parameterIdentity,
            preparationContextBytes,
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
            senderPosition: 3,
        }),
    );

    const senderSigningVerificationKey = new Uint8Array(1_952).fill(0xa1);
    openedInput?.signingOperations.assertMatchesSenderVerificationKey({
        senderSigningVerificationKey,
    });
    expect(mocks.assertSigningKey).toHaveBeenCalledWith({
        senderSigningVerificationKey,
        signingCapability,
    });

    const signatureBodyBytes = new Uint8Array(309).fill(0xb1);
    const signatureRandomness = new Uint8Array(32).fill(0xc1);
    const signature = new Uint8Array(3_309).fill(0xd1);
    mocks.signManifest.mockReturnValue(signature);
    expect(
        openedInput?.signingOperations.signManifestBody({
            senderSigningVerificationKey,
            signatureBodyBytes,
            signatureRandomness,
        }),
    ).toBe(signature);
    expect(mocks.signManifest).toHaveBeenCalledWith({
        senderSigningVerificationKey,
        signatureBodyBytes,
        signatureRandomness,
        signingCapability,
    });
});
