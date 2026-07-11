export const acceptedSetupTestModulePattern =
    'bgv::setup::tests::accepted_setup';

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
    '-p',
    'sealed-lattice-kernel',
    ...(testFilter === undefined ? [] : [testFilter]),
    '--',
    '--skip',
    acceptedSetupTestModulePattern,
    // Kernel proof and evaluator tests already parallelize their polynomial
    // work through Rayon. Letting libtest start one such test per logical
    // processor creates nested CPU and memory oversubscription: individually
    // short setup tests remain active for more than a minute and the fast lane
    // stretches past sixteen minutes. Serial libtest scheduling keeps every
    // fast test deterministic while Rayon still uses the machine inside each
    // test. These protections also apply to focused runs so an accepted-setup
    // test-name filter cannot bypass the guarded accepted-setup runner.
    '--test-threads',
    '1',
    '--show-output',
];

export const cargoTestArgumentsForRustKernelHeavy = (
    testFilter = heavyRustKernelTestNamePrefix,
): readonly string[] => [
    'test',
    '-p',
    'sealed-lattice-kernel',
    testFilter,
    '--',
    '--ignored',
    // These proof and evaluator tests use Rayon internally. Serial libtest
    // scheduling prevents nested CPU and memory oversubscription while keeping
    // the implementation's own polynomial parallelism enabled.
    '--test-threads',
    '1',
    '--show-output',
];
