export const heavyRustKernelTestNamePrefix = 'heavy_rust_kernel_';

const heavyRustKernelTestFilterPattern =
    /^heavy_rust_kernel_[a-z0-9]+(?:_[a-z0-9]+)*$/u;

/**
 * @param {readonly unknown[]} testFilters
 * @returns {readonly string[]}
 */
export const validateHeavyRustKernelTestRegistry = (testFilters) => {
    if (!Array.isArray(testFilters)) {
        throw new Error(
            'The active heavy Rust test registry must be an array.',
        );
    }

    /** @type {string[]} */
    const validatedTestFilters = [];
    const seenTestFilters = new Set();
    for (const testFilter of testFilters) {
        if (
            typeof testFilter !== 'string' ||
            !heavyRustKernelTestFilterPattern.test(testFilter)
        ) {
            throw new Error(
                `Invalid active heavy Rust test filter: ${String(testFilter)}.`,
            );
        }
        if (seenTestFilters.has(testFilter)) {
            throw new Error(
                `Duplicate active heavy Rust test filter: ${testFilter}.`,
            );
        }
        seenTestFilters.add(testFilter);
        validatedTestFilters.push(testFilter);
    }

    const sortedTestFilters = [...validatedTestFilters].sort((left, right) =>
        left.localeCompare(right),
    );
    for (const [testIndex, testFilter] of validatedTestFilters.entries()) {
        if (testFilter !== sortedTestFilters[testIndex]) {
            throw new Error(
                'The active heavy Rust test registry must use canonical lexical order.',
            );
        }
    }

    return Object.freeze(validatedTestFilters);
};

export const activeHeavyRustKernelTests = validateHeavyRustKernelTestRegistry(
    [],
);

/**
 * @param {readonly unknown[]} testFilters
 * @returns {{ readonly include: readonly { readonly testFilter: string }[] }}
 */
export const buildHeavyRustKernelTestMatrix = (testFilters) => ({
    include: validateHeavyRustKernelTestRegistry(testFilters).map(
        (testFilter) => ({ testFilter }),
    ),
});
