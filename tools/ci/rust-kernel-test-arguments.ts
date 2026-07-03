import os from 'node:os';

export const heavyAcceptedSetupTestPattern = 'heavy_accepted_setup';
export const heavyAcceptedSetupFinalPackageTestPattern =
    'heavy_accepted_setup_final_package';

export const normalizeRustTestFilter = (filter: string): string => {
    const normalizedSeparators = filter.replace(/\\/gu, '/');
    const pathParts = normalizedSeparators.split('/');
    const fileName = pathParts[pathParts.length - 1] ?? filter;
    if (fileName.endsWith('.rs')) {
        return fileName.slice(0, -'.rs'.length);
    }

    return fileName;
};

// The non-ignored accepted-setup tests in this lane share a large transient
// proof-generation working set (the memoized compact setup fixture is tens of
// gibibytes resident while it is built and verified). libtest concurrency here
// must therefore be memory-bounded the same way the dedicated accepted-setup
// lane bounds it, or an oversubscribed default-parallelism run exhausts RAM on a
// high-core machine and corrupts large proof buffers rather than failing
// cleanly. Size the thread count from currently available memory using the same
// per-test budget the accepted-setup runner uses, capped by the core count, so a
// constrained runner stays serial and a workstation runs a few tests at once.
const approximateGigabytesPerAcceptedSetupFixtureTest = 15;
const fastLaneMemoryBudgetFraction = 0.7;

export const memoryBoundedFastTestThreadCount = (): number => {
    const gigabyte = 1024 ** 3;
    const availableGigabytes = os.freemem() / gigabyte;
    const logicalProcessorCount = os.cpus().length;

    return Math.max(
        1,
        Math.min(
            logicalProcessorCount,
            Math.floor(
                (availableGigabytes * fastLaneMemoryBudgetFraction) /
                    approximateGigabytesPerAcceptedSetupFixtureTest,
            ),
        ),
    );
};

// The optional `testThreadCount` keeps this builder a pure, deterministic
// function of its inputs: callers that need the memory bound pass
// `memoryBoundedFastTestThreadCount()`, and tests pass a fixed count.
export const cargoTestArgumentsForRustKernelFast = (
    testFilter?: string,
    testThreadCount?: number,
): readonly string[] => [
    'test',
    '-p',
    'sealed-lattice-kernel',
    ...(testFilter === undefined ? [] : [testFilter]),
    '--',
    '--skip',
    heavyAcceptedSetupTestPattern,
    ...(testThreadCount === undefined
        ? []
        : ['--test-threads', String(testThreadCount)]),
    '--show-output',
];
