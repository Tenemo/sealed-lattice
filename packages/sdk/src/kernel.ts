import {
    createTranscriptCoreKernelLoader,
    type TranscriptCoreKernel,
} from '@sealed-lattice/wasm';

const transcriptCoreKernelUrl = new URL(
    './sealed-lattice-kernel.wasm',
    import.meta.url,
);
const packagedTranscriptCoreKernelNormalizedSha256Hex: string | undefined =
    undefined;

export const loadTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, {
        expectedKernelSha256Hex:
            packagedTranscriptCoreKernelNormalizedSha256Hex,
    });
