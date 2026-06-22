import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    heavyAcceptedSetupTestPattern,
    requiredRustHeavyEvidenceTests,
    type RequiredRustHeavyEvidenceTest,
} from './heavy-evidence-tests.js';
import type { PackageManagerRunner } from './package-manager-runner.js';
import type { CommandInvocation } from './run-command.js';
import {
    createDirectBallotSetupHandoffEvidenceCommands,
    directBallotSetupHandoffPublicPackageEvidenceTestPaths,
} from './run-direct-ballot-setup-handoff-evidence.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { collectFiles, toPosixPath } from '#tools/internal/files.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const heavyKernelNodeTestPath =
    'packages/wasm/tests/node/transcript-core-kernel/bgv-collective-setup.kernel.test.ts';
const directBallotSetupHandoffPublicPackageEvidenceCommandDescription =
    'Run direct ballot setup handoff public package evidence tests';
const verificationPackageManagerRunner = {
    command: process.execPath,
    commandArgumentsPrefix: ['pnpm.cjs'],
    kind: 'pnpm',
} as const satisfies PackageManagerRunner;

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

const escapeRegExp = (value: string): string =>
    value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');

export const validateRustHeavyEvidenceTestSource = (
    requiredTest: RequiredRustHeavyEvidenceTest,
    sourceText: string,
): readonly string[] => {
    const failures: string[] = [];
    if (!requiredTest.testName.startsWith(heavyAcceptedSetupTestPattern)) {
        failures.push(
            `${requiredTest.testName} must use the ${heavyAcceptedSetupTestPattern} prefix so pnpm run test:rust:kernel:heavy includes it.`,
        );
    }

    const ignoredHeavyTestPattern = new RegExp(
        `#\\[test\\]\\s*#\\[ignore\\s*=\\s*"heavy accepted setup test"\\]\\s*fn\\s+${escapeRegExp(
            requiredTest.testName,
        )}\\s*\\(`,
        'u',
    );
    if (!ignoredHeavyTestPattern.test(sourceText)) {
        failures.push(
            `${requiredTest.relativePath} must define ${requiredTest.testName} as an ignored heavy accepted setup test for ${requiredTest.claimEvidence}.`,
        );
    }

    return failures;
};

export const validateRequiredRustHeavyEvidenceTests = async (): Promise<
    readonly string[]
> => {
    const failures: string[] = [];
    for (const requiredTest of requiredRustHeavyEvidenceTests) {
        const absolutePath = path.resolve(repoRoot, requiredTest.relativePath);
        try {
            const sourceText = await readFile(absolutePath, 'utf8');
            failures.push(
                ...validateRustHeavyEvidenceTestSource(
                    requiredTest,
                    sourceText,
                ),
            );
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            failures.push(
                `${requiredTest.relativePath} could not be read while checking required Rust heavy evidence test ${requiredTest.testName}: ${message}`,
            );
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

export const validateDirectBallotSetupHandoffPublicPackageEvidenceCommand = (
    commands: readonly CommandInvocation[],
): readonly string[] => {
    const failures: string[] = [];
    const publicPackageEvidenceCommands = commands.filter(
        (command) =>
            command.description ===
            directBallotSetupHandoffPublicPackageEvidenceCommandDescription,
    );

    if (publicPackageEvidenceCommands.length !== 1) {
        failures.push(
            `direct ballot setup handoff evidence lane must include exactly one public package evidence command; found ${String(publicPackageEvidenceCommands.length)}.`,
        );

        return failures;
    }

    const [publicPackageEvidenceCommand] = publicPackageEvidenceCommands;
    if (publicPackageEvidenceCommand === undefined) {
        throw new Error(
            'direct ballot setup handoff public package evidence command was unexpectedly missing after length validation.',
        );
    }
    const commandArguments = publicPackageEvidenceCommand.args;
    if (
        !commandArguments.includes('exec') ||
        !commandArguments.includes('vitest') ||
        !commandArguments.includes('run')
    ) {
        failures.push(
            'direct ballot setup handoff public package evidence command must run vitest through the package manager.',
        );
    }

    for (const testPath of directBallotSetupHandoffPublicPackageEvidenceTestPaths) {
        if (!commandArguments.includes(testPath)) {
            failures.push(
                `direct ballot setup handoff public package evidence command must include ${testPath}.`,
            );
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

export const validateDirectBallotSetupHandoffEvidenceLane =
    (): readonly string[] =>
        validateDirectBallotSetupHandoffPublicPackageEvidenceCommand(
            createDirectBallotSetupHandoffEvidenceCommands({
                packageManagerRunner: verificationPackageManagerRunner,
            }),
        );

const collectWorkspaceTestFiles = async (): Promise<readonly string[]> => [
    ...(await collectFiles(path.resolve(repoRoot, 'packages'), {
        fileNamePattern: /\.test\.ts$/u,
    })),
    ...(await collectFiles(path.resolve(repoRoot, 'tests'), {
        fileNamePattern: /\.test\.ts$/u,
    })),
];

const main = async (): Promise<void> => {
    const failures = [
        ...validateTestLaneCoverage(await collectWorkspaceTestFiles()),
        ...(await validateRequiredRustHeavyEvidenceTests()),
        ...validateDirectBallotSetupHandoffEvidenceLane(),
    ].sort((left, right) => left.localeCompare(right));
    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Test lane coverage verification passed.');
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
