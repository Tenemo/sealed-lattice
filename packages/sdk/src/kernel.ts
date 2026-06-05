import {
    createTranscriptCoreKernelLoader,
    type TranscriptCoreKernel,
} from '@sealed-lattice/wasm';

const transcriptCoreKernelUrl = new URL(
    './sealed-lattice-kernel.wasm',
    import.meta.url,
);
// Shipped undefined on purpose: the build step rewrites this literal to pin the real
// normalized hash into dist/kernel.js. Loading an unpinned source build throws (the
// loader requires expectedKernelSha256Hex), and verify-packed-package.ts enforces
// that the published value is non-undefined.
const packagedTranscriptCoreKernelNormalizedSha256Hex: string | undefined =
    undefined;

export const loadTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, {
        expectedKernelSha256Hex:
            packagedTranscriptCoreKernelNormalizedSha256Hex,
    });
