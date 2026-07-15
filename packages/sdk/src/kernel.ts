import {
    createPublishedSdkKernelLoader,
    type PublishedSdkKernel,
} from '@sealed-lattice/wasm/published-sdk';

const transcriptCoreKernelUrl = new URL(
    './sealed-lattice-kernel.wasm',
    import.meta.url,
);
// The package build replaces this identifier with the normalized hash of the
// exact WASM bytes copied into the published package. Source-level execution
// remains deliberately unpinned and is useful only to the build and test tools.
declare const __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__:
    | string
    | undefined;
const packagedTranscriptCoreKernelNormalizedSha256Hex =
    typeof __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;

const transcriptCoreKernelLoaderOptions = {
    expectedKernelSha256Hex: packagedTranscriptCoreKernelNormalizedSha256Hex,
} as const;

// Portable one-shot operations can own a disposable WASM instance. If source
// staging or generated-material export fails, discarding that instance also
// discards authenticated or generated one-shot roots and its linear-memory
// high-water mark.
export const loadFreshTranscriptCoreKernel = (): Promise<PublishedSdkKernel> =>
    createPublishedSdkKernelLoader(
        transcriptCoreKernelUrl,
        transcriptCoreKernelLoaderOptions,
    )();
