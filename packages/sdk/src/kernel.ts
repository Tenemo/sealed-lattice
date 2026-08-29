import {
    createPublishedSdkKernelLoader,
    type PublishedSdkKernel,
} from '@sealed-lattice/wasm/published-sdk';

const foundationKernelUrl = new URL(
    './sealed-lattice-kernel.wasm',
    import.meta.url,
);
// The package build replaces this identifier with the SHA-256 hash of the exact
// WASM bytes copied into the published package. An unreplaced source build has
// no hash and the published loader therefore refuses to load it.
declare const __SEALED_LATTICE_KERNEL_SHA256_HEX__: string | undefined;
const packagedFoundationKernelSha256Hex =
    typeof __SEALED_LATTICE_KERNEL_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_SHA256_HEX__;

const foundationKernelLoaderOptions = {
    expectedKernelSha256Hex: packagedFoundationKernelSha256Hex,
} as const;

export const loadFreshFoundationKernel = (): Promise<PublishedSdkKernel> =>
    createPublishedSdkKernelLoader(
        foundationKernelUrl,
        foundationKernelLoaderOptions,
    )();
