export const acceptedSetupTestModulePattern =
    'bgv::setup::tests::accepted_setup';

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
    ...(testFilter === undefined
        ? ['--skip', acceptedSetupTestModulePattern]
        : []),
    '--show-output',
];
