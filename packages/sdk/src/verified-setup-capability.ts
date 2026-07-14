import type { ProtocolHash } from '@sealed-lattice/types';
import type { PublishedSdkKernel } from '@sealed-lattice/wasm/published-sdk';

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const verifiedSetupCapabilityBrand: unique symbol = Symbol(
    'sealed-lattice/verified-setup-capability',
);

/** A process-local setup capability issued only by successful setup verification. */
export type VerifiedSetup = Readonly<{
    readonly setupPackageHash: ProtocolHash;
    readonly [verifiedSetupCapabilityBrand]: true;
}>;

type VerifiedSetupKernelBinding = Readonly<{
    readonly acceptedSetupHandle: number;
    readonly kernel: PublishedSdkKernel;
}>;

const verifiedSetupKernelBindings = new WeakMap<
    VerifiedSetup,
    VerifiedSetupKernelBinding
>();

export const issueVerifiedSetup = (input: {
    readonly acceptedSetupHandle: number;
    readonly kernel: PublishedSdkKernel;
    readonly setupPackageHash: ProtocolHash;
}): VerifiedSetup => {
    if (
        !Number.isInteger(input.acceptedSetupHandle) ||
        input.acceptedSetupHandle <= 0 ||
        input.acceptedSetupHandle > 0xffff_ffff
    ) {
        throw new TypeError(
            'accepted setup verification returned an invalid internal handle.',
        );
    }
    if (!protocolHashPattern.test(input.setupPackageHash)) {
        throw new TypeError(
            'accepted setup verification returned an invalid setup package hash.',
        );
    }

    const verifiedSetupRecord = {
        setupPackageHash: input.setupPackageHash,
    } as {
        setupPackageHash: ProtocolHash;
        [verifiedSetupCapabilityBrand]?: true;
    };
    Object.defineProperty(verifiedSetupRecord, verifiedSetupCapabilityBrand, {
        configurable: false,
        enumerable: false,
        value: true,
        writable: false,
    });
    const verifiedSetup = Object.freeze(verifiedSetupRecord) as VerifiedSetup;
    verifiedSetupKernelBindings.set(
        verifiedSetup,
        Object.freeze({
            acceptedSetupHandle: input.acceptedSetupHandle,
            kernel: input.kernel,
        }),
    );

    return verifiedSetup;
};

export const resolveVerifiedSetup = (
    value: unknown,
): VerifiedSetupKernelBinding => {
    if (typeof value !== 'object' || value === null) {
        throw new TypeError(
            'verifiedSetup must be an active capability issued by successful setup verification in this SDK instance.',
        );
    }

    const binding = verifiedSetupKernelBindings.get(value as VerifiedSetup);
    if (binding === undefined) {
        throw new TypeError(
            'verifiedSetup must be an active capability issued by successful setup verification in this SDK instance.',
        );
    }

    return binding;
};
