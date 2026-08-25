export const heavyRustKernelTestNamePrefix = 'heavy_rust_kernel_';

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
    // Serial scheduling keeps completion-profile cryptographic tests from
    // inflating one another's memory and CPU measurements.
    '--test-threads',
    '1',
    '--show-output',
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
    // Heavy evidence remains serialized under the runner-owned resource guard.
    '--nocapture',
    '--test-threads',
    '1',
];
