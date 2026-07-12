import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

const runCargoAndCapture = (
    arguments_: readonly string[],
    environment: NodeJS.ProcessEnv = process.env,
): string => {
    const result = spawnSync('cargo', arguments_, {
        cwd: repoRoot,
        encoding: 'utf8',
        env: environment,
        maxBuffer: 100 * 1024 * 1024,
    });
    if (result.error !== undefined) {
        throw new Error(`Failed to start cargo: ${result.error.message}`);
    }
    if (result.status !== 0) {
        throw new Error(
            `cargo ${arguments_.join(' ')} failed:\n${result.stderr}${result.stdout}`,
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

const listCargoTargetTests = (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly packageName: string;
    readonly selector: readonly string[];
    readonly targetName: string;
}): readonly RustTestInventoryEntry[] => {
    const cargoPrefix = [
        'test',
        '--locked',
        '-p',
        input.packageName,
        ...input.selector,
    ];
    const allTests = parseLibtestListOutput(
        runCargoAndCapture(
            [...cargoPrefix, '--', '--list', '--format', 'terse'],
            input.environment,
        ),
    );
    const ignoredTests = new Set(
        parseLibtestListOutput(
            runCargoAndCapture(
                [
                    ...cargoPrefix,
                    '--',
                    '--ignored',
                    '--list',
                    '--format',
                    'terse',
                ],
                input.environment,
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

export const collectRustTestInventory = (): RustTestInventory => {
    const metadata = JSON.parse(
        runCargoAndCapture([
            'metadata',
            '--locked',
            '--no-deps',
            '--format-version',
            '1',
        ]),
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
                    ...listCargoTargetTests({
                        packageName: cargoPackage.name,
                        selector,
                        targetName: target.name,
                    }),
                );
            }
            if (target.doctest) {
                inventory.push(
                    ...listCargoTargetTests({
                        packageName: cargoPackage.name,
                        selector: ['--doc'],
                        targetName: `${target.name}:doctest`,
                    }),
                );
            }
        }
    }

    return inventory;
};

export const collectFocusedRustKernelTestInventory = (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly testFilter: string;
}): readonly RustTestInventoryEntry[] => {
    const packageName = 'sealed-lattice-kernel';
    const cargoPrefix = [
        'test',
        '--locked',
        '-p',
        packageName,
        input.testFilter,
    ];
    const allTests = parseLibtestListOutput(
        runCargoAndCapture(
            [
                ...cargoPrefix,
                '--',
                '--include-ignored',
                '--list',
                '--format',
                'terse',
            ],
            input.environment,
        ),
    );
    const ignoredTests = new Set(
        parseLibtestListOutput(
            runCargoAndCapture(
                [
                    ...cargoPrefix,
                    '--',
                    '--ignored',
                    '--list',
                    '--format',
                    'terse',
                ],
                input.environment,
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
