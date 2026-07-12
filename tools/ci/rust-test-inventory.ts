import { fileURLToPath } from 'node:url';

import type { ActiveLocalRunLog } from './local-run-log.js';
import { runCommandAndCaptureOutput } from './run-command.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

type CargoMetadata = {
    readonly packages: readonly CargoPackage[];
    readonly workspace_members: readonly string[];
};

type CargoPackage = {
    readonly id: string;
    readonly name: string;
    readonly targets: readonly CargoTarget[];
};

type CargoTarget = {
    readonly doctest: boolean;
    readonly kind: readonly string[];
    readonly name: string;
    readonly test: boolean;
};

export type RustTestInventoryEntry = {
    readonly ignored: boolean;
    readonly packageName: string;
    readonly targetName: string;
    readonly testName: string;
};

type RustTestInventory = readonly RustTestInventoryEntry[];

export const parseLibtestListOutput = (output: string): readonly string[] => {
    const names: string[] = [];
    for (const rawLine of output.split(/\r?\n/u)) {
        const line = rawLine.trim();
        if (line.endsWith(': test')) {
            names.push(line.slice(0, -': test'.length));
            continue;
        }
        if (line.endsWith(' - compile')) {
            names.push(line);
        }
    }
    return [...new Set(names)].sort((left, right) => left.localeCompare(right));
};

const runCargoAndCaptureAsynchronously = async (
    arguments_: readonly string[],
    input: {
        readonly environment?: NodeJS.ProcessEnv;
        readonly runLog?: ActiveLocalRunLog;
    } = {},
): Promise<string> => {
    const result = await runCommandAndCaptureOutput(
        {
            args: arguments_,
            command: 'cargo',
            description: `inventory Cargo tests: cargo ${arguments_.join(' ')}`,
            env: input.environment,
            logFileSlug: 'cargo-test-inventory',
            workingDirectoryPath: repoRoot,
        },
        { runLog: input.runLog },
    );
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `cargo ${arguments_.join(' ')} failed with exit code ${result.exitCode}, signal ${result.terminationSignal ?? 'none'}:\n${result.stderr}${result.stdout}`,
        );
    }

    return result.stdout;
};

export const inventoryEntriesFromListedTests = (input: {
    readonly allTests: readonly string[];
    readonly ignoredTests: ReadonlySet<string>;
    readonly packageName: string;
    readonly targetName: string;
}): readonly RustTestInventoryEntry[] =>
    input.allTests.map((testName) => ({
        ignored: input.ignoredTests.has(testName),
        packageName: input.packageName,
        targetName: input.targetName,
        testName,
    }));

const listCargoTargetTestsAsynchronously = async (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly packageName: string;
    readonly runLog?: ActiveLocalRunLog;
    readonly selector: readonly string[];
    readonly targetName: string;
}): Promise<readonly RustTestInventoryEntry[]> => {
    const cargoPrefix = [
        'test',
        '--locked',
        '-p',
        input.packageName,
        ...input.selector,
    ];
    const allTests = parseLibtestListOutput(
        await runCargoAndCaptureAsynchronously(
            [...cargoPrefix, '--', '--list', '--format', 'terse'],
            input,
        ),
    );
    const ignoredTests = new Set(
        parseLibtestListOutput(
            await runCargoAndCaptureAsynchronously(
                [
                    ...cargoPrefix,
                    '--',
                    '--ignored',
                    '--list',
                    '--format',
                    'terse',
                ],
                input,
            ),
        ),
    );

    return inventoryEntriesFromListedTests({
        allTests,
        ignoredTests,
        packageName: input.packageName,
        targetName: input.targetName,
    });
};

const selectorForCargoTarget = (
    target: CargoTarget,
): readonly string[] | undefined => {
    if (
        target.kind.some((kind) =>
            ['cdylib', 'dylib', 'lib', 'rlib', 'staticlib'].includes(kind),
        )
    ) {
        return ['--lib'];
    }
    if (target.kind.includes('bin')) {
        return ['--bin', target.name];
    }
    if (target.kind.includes('test')) {
        return ['--test', target.name];
    }
    if (target.kind.includes('example')) {
        return ['--example', target.name];
    }
    if (target.kind.includes('bench')) {
        return ['--bench', target.name];
    }

    return undefined;
};

export const collectRustTestInventory = async (
    runLog?: ActiveLocalRunLog,
): Promise<RustTestInventory> => {
    const metadata = JSON.parse(
        await runCargoAndCaptureAsynchronously(
            ['metadata', '--locked', '--no-deps', '--format-version', '1'],
            { runLog },
        ),
    ) as CargoMetadata;
    const workspaceMembers = new Set(metadata.workspace_members);
    const inventory: RustTestInventoryEntry[] = [];

    for (const cargoPackage of metadata.packages) {
        if (!workspaceMembers.has(cargoPackage.id)) {
            continue;
        }
        for (const target of cargoPackage.targets) {
            if (target.test) {
                const selector = selectorForCargoTarget(target);
                if (selector === undefined) {
                    throw new Error(
                        `Unsupported testable Cargo target ${cargoPackage.name}/${target.name} (${target.kind.join(', ')}).`,
                    );
                }
                inventory.push(
                    ...(await listCargoTargetTestsAsynchronously({
                        packageName: cargoPackage.name,
                        runLog,
                        selector,
                        targetName: target.name,
                    })),
                );
            }
            if (target.doctest) {
                inventory.push(
                    ...(await listCargoTargetTestsAsynchronously({
                        packageName: cargoPackage.name,
                        runLog,
                        selector: ['--doc'],
                        targetName: `${target.name}:doctest`,
                    })),
                );
            }
        }
    }

    return inventory;
};

export const collectFocusedRustKernelTestInventory = async (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
}): Promise<readonly RustTestInventoryEntry[]> => {
    const packageName = 'sealed-lattice-kernel';
    const cargoPrefix = [
        'test',
        '--locked',
        '-p',
        packageName,
        input.testFilter,
    ];
    const allTests = parseLibtestListOutput(
        await runCargoAndCaptureAsynchronously(
            [
                ...cargoPrefix,
                '--',
                '--include-ignored',
                '--list',
                '--format',
                'terse',
            ],
            input,
        ),
    );
    const ignoredTests = new Set(
        parseLibtestListOutput(
            await runCargoAndCaptureAsynchronously(
                [
                    ...cargoPrefix,
                    '--',
                    '--ignored',
                    '--list',
                    '--format',
                    'terse',
                ],
                input,
            ),
        ),
    );

    return inventoryEntriesFromListedTests({
        allTests,
        ignoredTests,
        packageName,
        targetName: 'focused',
    });
};
