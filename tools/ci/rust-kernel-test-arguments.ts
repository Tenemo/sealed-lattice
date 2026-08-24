export const heavyRustKernelTestNamePrefix = 'heavy_rust_kernel_';
// The rejected row-code backend remains source history until final removal.
// Routine lanes must not execute its tests.
export const rejectedRowCodeBackendRustTestNamePrefix =
    'bgv::proof_suite::row_code_whir::';

export const normalizeRustTestFilter = (filter: string): string => {
    const normalizedSeparators = filter.replace(/\\/gu, '/');
    const pathParts = normalizedSeparators.split('/');
    const fileName = pathParts[pathParts.length - 1] ?? filter;
    if (fileName.endsWith('.rs')) {
        return fileName.slice(0, -'.rs'.length);
    }

    return fileName;
};

export const cargoTestArgumentsForRustKernelFast = (
    testFilter?: string,
): readonly string[] => [
    'test',
    '--locked',
    '-p',
    'sealed-lattice-kernel',
    ...(testFilter === undefined ? [] : [testFilter]),
    '--',
    // Proof and evaluator tests use Rayon internally. Serial libtest scheduling
    // prevents nested CPU and memory oversubscription.
    '--test-threads',
    '1',
    '--show-output',
    '--skip',
    rejectedRowCodeBackendRustTestNamePrefix,
];

export const cargoTestArgumentsForRustKernelHeavy = (
    testFilter = heavyRustKernelTestNamePrefix,
): readonly string[] => [
    'test',
    '--locked',
    '-p',
    'sealed-lattice-kernel',
    testFilter,
    '--',
    '--ignored',
    // These proof and evaluator tests use Rayon internally. Serial libtest
    // scheduling prevents nested CPU and memory oversubscription while keeping
    // the implementation's own polynomial parallelism enabled.
    '--nocapture',
    '--test-threads',
    '1',
];
