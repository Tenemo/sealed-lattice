import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { collectFiles, toPosixPath } from '#tools/internal/files.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const heavyKernelNodeTestPath =
    'packages/wasm/tests/node/transcript-core-kernel/bgv-collective-setup.kernel.test.ts';

type TestLaneGroup =
    | 'browser'
    | 'node-fast'
    | 'node-kernel'
    | 'node-kernel-heavy'
    | 'node-protocol';

const normalizeRelativeTestPath = (filePath: string): string =>
    toPosixPath(path.relative(repoRoot, path.resolve(repoRoot, filePath)));

export const testLaneGroupsForRelativePath = (
    filePath: string,
): readonly TestLaneGroup[] => {
    const relativePath = normalizeRelativeTestPath(filePath);
    const laneGroups: TestLaneGroup[] = [];

    if (!relativePath.endsWith('.test.ts')) {
        return laneGroups;
    }

    if (
        relativePath.startsWith('packages/') &&
        relativePath.includes('/tests/browser/') &&
        relativePath.endsWith('.browser.test.ts')
    ) {
        laneGroups.push('browser');
    }

    if (relativePath.startsWith('packages/protocol/tests/node/')) {
        laneGroups.push('node-protocol');
    } else if (relativePath === heavyKernelNodeTestPath) {
        laneGroups.push('node-kernel-heavy');
    } else if (
        relativePath.startsWith('packages/wasm/tests/node/') &&
        relativePath.endsWith('.kernel.test.ts')
    ) {
        laneGroups.push('node-kernel');
    } else if (
        relativePath.startsWith('tests/node/') &&
        relativePath.endsWith('.kernel.test.ts')
    ) {
        laneGroups.push('node-kernel');
    } else if (
        relativePath.startsWith('tests/node/') ||
        (relativePath.startsWith('packages/') &&
            relativePath.includes('/tests/node/'))
    ) {
        laneGroups.push('node-fast');
    }

    return laneGroups;
};

export const validateTestLaneCoverage = (
    filePaths: readonly string[],
): readonly string[] => {
    const failures: string[] = [];

    for (const filePath of filePaths) {
        const relativePath = normalizeRelativeTestPath(filePath);
        const laneGroups = testLaneGroupsForRelativePath(relativePath);

        if (laneGroups.length === 0) {
            failures.push(
                `${relativePath} is not covered by any test lane. Browser tests must use the .browser.test.ts suffix, and kernel tests must use the .kernel.test.ts suffix in a kernel test directory.`,
            );
            continue;
        }
        if (laneGroups.length > 1) {
            failures.push(
                `${relativePath} is covered by multiple test lanes: ${laneGroups.join(', ')}.`,
            );
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

const collectWorkspaceTestFiles = async (): Promise<readonly string[]> => [
    ...(await collectFiles(path.resolve(repoRoot, 'packages'), {
        fileNamePattern: /\.test\.ts$/u,
    })),
    ...(await collectFiles(path.resolve(repoRoot, 'tests'), {
        fileNamePattern: /\.test\.ts$/u,
    })),
];

const main = async (): Promise<void> => {
    const failures = validateTestLaneCoverage(
        await collectWorkspaceTestFiles(),
    );
    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Test lane coverage verification passed.');
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
