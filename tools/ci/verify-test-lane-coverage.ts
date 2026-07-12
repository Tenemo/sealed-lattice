import { spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    createSourceFile,
    forEachChild,
    isCallExpression,
    isIdentifier,
    isImportDeclaration,
    isNamespaceImport,
    isPropertyAccessExpression,
    isStringLiteral,
    ScriptKind,
    ScriptTarget,
    type Expression,
    type Node,
    type SourceFile,
} from 'typescript';

import {
    aggregateTestScripts,
    canonicalTestLaneDefinitions,
    canonicalTestLaneValues,
    expectedOwnedTestCounts,
    externalOracleDefinitions,
    fullProfileEvidenceRustTests,
    fuzzTargetDefinitions,
    measurementRustTests,
    rustTestLanesForInventoryEntry,
    testLaneGroupsForRelativePath,
    testUtilityScripts,
    type CanonicalTestLane,
} from '#tools/ci/test-lanes.js';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { toPosixPath } from '#tools/internal/files.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const testFileNamePattern = /\.(?:test|spec)\.[cm]?[jt]sx?$/u;
const sourceFileNamePattern = /\.[cm]?[jt]sx?$/u;
const ownedTypeScriptSourceDirectoryNames = [
    'packages',
    'tests',
    'tools',
] as const;
const excludedSourceDirectoryNames = new Set([
    '.git',
    '.next',
    '.svelte-kit',
    '.turbo',
    '.venv',
    '.vitest-attachments',
    '__pycache__',
    'build',
    'coverage',
    'dist',
    'node_modules',
    'target',
]);

type TypeScriptTestAnalysis = {
    readonly definitionCount: number;
    readonly failures: readonly string[];
};

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
    readonly crate_types: readonly string[];
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

type RootPackage = {
    readonly scripts?: Readonly<Record<string, string>>;
};

type VitestCall = {
    readonly modifiers: readonly string[];
    readonly rootName: string;
};

const normalizeRelativePath = (filePath: string): string =>
    toPosixPath(path.relative(repoRoot, path.resolve(repoRoot, filePath)));

export const validateTestLaneCoverage = (
    filePaths: readonly string[],
): readonly string[] => {
    const failures: string[] = [];

    for (const filePath of filePaths) {
        const relativePath = normalizeRelativePath(filePath);
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

const vitestCallFromExpression = (
    expression: Expression,
): VitestCall | undefined => {
    if (isCallExpression(expression)) {
        return vitestCallFromExpression(expression.expression);
    }
    if (isPropertyAccessExpression(expression)) {
        const parent = vitestCallFromExpression(expression.expression);
        if (parent === undefined) {
            return undefined;
        }
        return {
            modifiers: [...parent.modifiers, expression.name.text],
            rootName: parent.rootName,
        };
    }
    if (isIdentifier(expression)) {
        return { modifiers: [], rootName: expression.text };
    }

    return undefined;
};

const collectVitestBindings = (
    sourceFile: SourceFile,
): {
    readonly definitionBindings: ReadonlySet<string>;
    readonly namespaceBindings: ReadonlySet<string>;
} => {
    const definitionBindings = new Set<string>();
    const namespaceBindings = new Set<string>();

    for (const statement of sourceFile.statements) {
        if (
            !isImportDeclaration(statement) ||
            !isStringLiteral(statement.moduleSpecifier) ||
            statement.moduleSpecifier.text !== 'vitest'
        ) {
            continue;
        }
        const importClause = statement.importClause;
        const namedBindings = importClause?.namedBindings;
        if (namedBindings === undefined) {
            continue;
        }
        if (isNamespaceImport(namedBindings)) {
            namespaceBindings.add(namedBindings.name.text);
            continue;
        }
        for (const element of namedBindings.elements) {
            const importedName =
                element.propertyName?.text ?? element.name.text;
            if (['describe', 'it', 'test'].includes(importedName)) {
                definitionBindings.add(element.name.text);
            }
        }
    }

    return { definitionBindings, namespaceBindings };
};

const resolvedVitestCall = (input: {
    readonly call: VitestCall;
    readonly definitionBindings: ReadonlySet<string>;
    readonly namespaceBindings: ReadonlySet<string>;
    readonly testNamedFile: boolean;
}): VitestCall | undefined => {
    if (
        input.definitionBindings.has(input.call.rootName) ||
        (input.testNamedFile &&
            ['describe', 'it', 'test'].includes(input.call.rootName))
    ) {
        return input.call;
    }
    if (
        input.namespaceBindings.has(input.call.rootName) &&
        input.call.modifiers.length > 0 &&
        ['describe', 'it', 'test'].includes(input.call.modifiers[0] ?? '')
    ) {
        return {
            modifiers: input.call.modifiers.slice(1),
            rootName: input.call.modifiers[0] ?? '',
        };
    }

    return undefined;
};

export const analyzeTypeScriptTestSource = (input: {
    readonly relativePath: string;
    readonly sourceText: string;
}): TypeScriptTestAnalysis => {
    const relativePath = toPosixPath(input.relativePath);
    const testNamedFile = testFileNamePattern.test(relativePath);
    const sourceFile = createSourceFile(
        relativePath,
        input.sourceText,
        ScriptTarget.Latest,
        true,
        relativePath.endsWith('.tsx') ? ScriptKind.TSX : ScriptKind.TS,
    );
    const bindings = collectVitestBindings(sourceFile);
    const failures: string[] = [];
    let definitionCount = 0;

    const visit = (node: Node): void => {
        if (isCallExpression(node)) {
            const nestedInsideDefinitionCall =
                isCallExpression(node.parent) &&
                node.parent.expression === node;
            if (!nestedInsideDefinitionCall) {
                const call = vitestCallFromExpression(node.expression);
                const resolvedCall =
                    call === undefined
                        ? undefined
                        : resolvedVitestCall({
                              ...bindings,
                              call,
                              testNamedFile,
                          });
                if (resolvedCall !== undefined) {
                    definitionCount += 1;
                    const line =
                        sourceFile.getLineAndCharacterOfPosition(
                            node.getStart(sourceFile),
                        ).line + 1;
                    const disabledModifier = resolvedCall.modifiers.find(
                        (modifier) =>
                            ['only', 'skip', 'todo'].includes(modifier),
                    );
                    if (disabledModifier !== undefined) {
                        failures.push(
                            `${relativePath}:${line} uses unconditional .${disabledModifier}; focused and disabled tests are not allowed.`,
                        );
                    }
                    if (resolvedCall.modifiers.includes('skipIf')) {
                        const lanes =
                            testLaneGroupsForRelativePath(relativePath);
                        if (lanes.length !== 1 || lanes[0] !== 'browser') {
                            failures.push(
                                `${relativePath}:${line} uses .skipIf outside the classified browser lane.`,
                            );
                        }
                    }
                }
            }
        }
        forEachChild(node, visit);
    };
    visit(sourceFile);

    if (testNamedFile && definitionCount === 0) {
        failures.push(
            `${relativePath} is test-named but defines no Vitest tests.`,
        );
    }
    if (!testNamedFile && definitionCount > 0) {
        failures.push(
            `${relativePath} defines Vitest tests outside a recognized test-named file.`,
        );
    }

    return { definitionCount, failures };
};

export const validateRootTestScripts = (
    scripts: Readonly<Record<string, string>>,
): readonly string[] => {
    const failures: string[] = [];
    const canonicalScripts = new Map<string, CanonicalTestLane>();
    for (const lane of canonicalTestLaneValues) {
        const script = canonicalTestLaneDefinitions[lane].rootScript;
        const previousOwner = canonicalScripts.get(script);
        if (previousOwner !== undefined) {
            failures.push(
                `${script} is assigned to both ${previousOwner} and ${lane}.`,
            );
        }
        canonicalScripts.set(script, lane);
        if (scripts[script] === undefined) {
            failures.push(`${lane} is missing root script ${script}.`);
        }
    }

    const permittedScripts = new Set([
        ...canonicalScripts.keys(),
        ...aggregateTestScripts,
        ...testUtilityScripts,
    ]);
    for (const scriptName of Object.keys(scripts)) {
        if (
            scriptName.startsWith('test:') &&
            !permittedScripts.has(scriptName)
        ) {
            failures.push(
                `${scriptName} is an undeclared root test script; register it as a canonical lane or aggregate alias.`,
            );
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

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

export const validateRustTestInventory = (
    entries: readonly RustTestInventoryEntry[],
): readonly string[] => {
    const failures: string[] = [];
    const counts = new Map<CanonicalTestLane, number>();

    for (const entry of entries) {
        const lanes = rustTestLanesForInventoryEntry(entry);
        const identity = `${entry.packageName}/${entry.targetName}/${entry.testName}`;
        if (lanes.length === 0) {
            failures.push(`${identity} is not owned by a Rust test lane.`);
            continue;
        }
        if (lanes.length > 1) {
            failures.push(
                `${identity} is owned by multiple Rust test lanes: ${lanes.join(', ')}.`,
            );
            continue;
        }
        const lane = lanes[0];
        if (
            [
                'rust-accepted-setup',
                'rust-full-profile-evidence',
                'rust-kernel-heavy',
                'rust-measurements',
            ].includes(lane) &&
            !entry.ignored &&
            lane !== 'rust-accepted-setup'
        ) {
            failures.push(
                `${identity} belongs to ${lane} but is not marked ignored.`,
            );
        }
        counts.set(lane, (counts.get(lane) ?? 0) + 1);
    }

    const kernelNames = new Set(
        entries
            .filter((entry) => entry.packageName === 'sealed-lattice-kernel')
            .map((entry) => entry.testName),
    );
    for (const explicitTestName of [
        ...fullProfileEvidenceRustTests,
        ...measurementRustTests,
    ]) {
        if (!kernelNames.has(explicitTestName)) {
            failures.push(
                `Explicitly owned Rust test ${explicitTestName} is stale or missing.`,
            );
        }
    }

    for (const lane of [
        'rust-kernel-fast',
        'rust-kernel-heavy',
        'rust-accepted-setup',
        'rust-full-profile-evidence',
        'rust-measurements',
        'rust-process-memory-guard',
    ] as const) {
        const actualCount = counts.get(lane) ?? 0;
        const expectedCount = expectedOwnedTestCounts[lane];
        if (actualCount !== expectedCount) {
            failures.push(
                `${lane} owns ${actualCount} Rust tests; registry baseline is ${expectedCount}.`,
            );
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

const collectOwnedTypeScriptSources = async (): Promise<readonly string[]> => {
    const files: string[] = [];
    const pendingDirectories = ownedTypeScriptSourceDirectoryNames.map(
        (directoryName) => path.join(repoRoot, directoryName),
    );

    while (pendingDirectories.length > 0) {
        const directoryPath = pendingDirectories.pop()!;
        const entries = await fs.readdir(directoryPath, {
            withFileTypes: true,
        });
        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (!excludedSourceDirectoryNames.has(entry.name)) {
                    pendingDirectories.push(
                        path.join(directoryPath, entry.name),
                    );
                }
                continue;
            }
            if (
                entry.isFile() &&
                sourceFileNamePattern.test(entry.name) &&
                !entry.name.endsWith('.d.ts')
            ) {
                files.push(path.join(directoryPath, entry.name));
            }
        }
    }

    return files.sort((left, right) => left.localeCompare(right));
};

export const parseCargoFuzzBins = (
    cargoManifest: string,
): readonly { readonly name: string; readonly sourcePath: string }[] => {
    const bins: { name: string; sourcePath: string }[] = [];
    const binBlocks = cargoManifest.matchAll(
        /\[\[bin\]\]([\s\S]*?)(?=\r?\n\[\[|$)/gu,
    );
    for (const match of binBlocks) {
        const block = match[1] ?? '';
        const name = /^name\s*=\s*"([^"]+)"\s*$/mu.exec(block)?.[1];
        const sourcePath = /^path\s*=\s*"([^"]+)"\s*$/mu.exec(block)?.[1];
        if (name !== undefined && sourcePath !== undefined) {
            bins.push({ name, sourcePath });
        }
    }
    return bins;
};

export const validateFuzzTargetInventory = (
    bins: readonly { readonly name: string; readonly sourcePath: string }[],
): readonly string[] => {
    const failures: string[] = [];
    for (const [targetName, definition] of Object.entries(
        fuzzTargetDefinitions,
    )) {
        const matchingBins = bins.filter((bin) => bin.name === targetName);
        if (matchingBins.length !== 1) {
            failures.push(
                `${definition.cargoManifestPath} must declare fuzz target ${targetName} exactly once.`,
            );
        }
        const expectedSourcePath = toPosixPath(
            path.relative(
                path.dirname(path.join(repoRoot, definition.cargoManifestPath)),
                path.join(repoRoot, definition.sourcePath),
            ),
        );
        if (
            matchingBins[0] !== undefined &&
            toPosixPath(matchingBins[0].sourcePath) !== expectedSourcePath
        ) {
            failures.push(
                `${targetName} points to ${matchingBins[0].sourcePath}; expected ${expectedSourcePath}.`,
            );
        }
    }
    for (const unexpectedBin of bins.filter(
        (bin) => !(bin.name in fuzzTargetDefinitions),
    )) {
        failures.push(
            `fuzz/Cargo.toml declares unowned fuzz target ${unexpectedBin.name}.`,
        );
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

export const validateExternalOracleInventory = (
    runnerPaths: readonly string[],
): readonly string[] => {
    const expectedPaths = new Set<string>(
        Object.values(externalOracleDefinitions).map(
            (definition) => definition.runnerPath,
        ),
    );
    const actualPaths = new Set(runnerPaths.map(toPosixPath));
    const failures: string[] = [];
    for (const expectedPath of expectedPaths) {
        if (!actualPaths.has(expectedPath)) {
            failures.push(
                `${expectedPath} is missing from external oracle ownership.`,
            );
        }
    }
    for (const actualPath of actualPaths) {
        if (!expectedPaths.has(actualPath)) {
            failures.push(
                `${actualPath} is an unowned external oracle runner.`,
            );
        }
    }
    return failures.sort((left, right) => left.localeCompare(right));
};

const verifyStaticOwnership = async (): Promise<readonly string[]> => {
    const failures: string[] = [];
    const files = await collectOwnedTypeScriptSources();
    const testFiles: string[] = [];
    const testFileCounts = new Map<CanonicalTestLane, number>();

    for (const filePath of files) {
        const relativePath = normalizeRelativePath(filePath);
        const analysis = analyzeTypeScriptTestSource({
            relativePath,
            sourceText: await fs.readFile(filePath, 'utf8'),
        });
        failures.push(...analysis.failures);
        if (testFileNamePattern.test(relativePath)) {
            testFiles.push(relativePath);
            const lanes = testLaneGroupsForRelativePath(relativePath);
            if (lanes.length === 1) {
                const lane = lanes[0];
                testFileCounts.set(lane, (testFileCounts.get(lane) ?? 0) + 1);
            }
        }
    }
    failures.push(...validateTestLaneCoverage(testFiles));

    for (const lane of [
        'node-fast',
        'node-protocol',
        'node-kernel-fast',
        'node-kernel-heavy',
        'browser',
    ] as const) {
        const actualCount = testFileCounts.get(lane) ?? 0;
        const expectedCount = expectedOwnedTestCounts[lane];
        if (actualCount !== expectedCount) {
            failures.push(
                `${lane} owns ${actualCount} TypeScript test files; registry baseline is ${expectedCount}.`,
            );
        }
    }

    const rootPackage = JSON.parse(
        await fs.readFile(path.join(repoRoot, 'package.json'), 'utf8'),
    ) as RootPackage;
    failures.push(...validateRootTestScripts(rootPackage.scripts ?? {}));

    const checkedFuzzManifests = new Set<string>();
    for (const definition of Object.values(fuzzTargetDefinitions)) {
        const manifestPath = path.join(repoRoot, definition.cargoManifestPath);
        if (!checkedFuzzManifests.has(manifestPath)) {
            failures.push(
                ...validateFuzzTargetInventory(
                    parseCargoFuzzBins(await fs.readFile(manifestPath, 'utf8')),
                ),
            );
            checkedFuzzManifests.add(manifestPath);
        }
        try {
            await fs.access(path.join(repoRoot, definition.sourcePath));
        } catch {
            failures.push(`${definition.sourcePath} is missing.`);
        }
    }

    failures.push(
        ...validateExternalOracleInventory(
            files
                .map(normalizeRelativePath)
                .filter((filePath) => /\/run-[^/]*oracle\.ts$/u.test(filePath)),
        ),
    );

    return failures.sort((left, right) => left.localeCompare(right));
};

const runCargoAndCapture = (arguments_: readonly string[]): string => {
    const result = spawnSync('cargo', arguments_, {
        cwd: repoRoot,
        encoding: 'utf8',
        env: process.env,
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

const listCargoTargetTests = (input: {
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
        runCargoAndCapture([
            ...cargoPrefix,
            '--',
            '--list',
            '--format',
            'terse',
        ]),
    );
    const ignoredTests = new Set(
        parseLibtestListOutput(
            runCargoAndCapture([
                ...cargoPrefix,
                '--',
                '--ignored',
                '--list',
                '--format',
                'terse',
            ]),
        ),
    );

    return allTests.map((testName) => ({
        ignored: ignoredTests.has(testName),
        packageName: input.packageName,
        targetName: input.targetName,
        testName,
    }));
};

const collectRustTestInventory = (): readonly RustTestInventoryEntry[] => {
    const metadata = JSON.parse(
        runCargoAndCapture(['metadata', '--no-deps', '--format-version', '1']),
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

const parsePhases = (
    commandArguments: readonly string[],
): { readonly rust: boolean; readonly static: boolean } => {
    if (commandArguments.length === 0) {
        return { rust: true, static: true };
    }
    let rust = false;
    let staticPhase = false;
    for (const argument of commandArguments) {
        if (argument === '--' || argument === undefined) {
            continue;
        }
        if (argument === '--rust') {
            rust = true;
            continue;
        }
        if (argument === '--static') {
            staticPhase = true;
            continue;
        }
        throw new Error(
            `Unknown argument ${argument}. Use --static, --rust, or no arguments for both phases.`,
        );
    }
    if (!rust && !staticPhase) {
        throw new Error(
            'At least one test-lane verification phase is required.',
        );
    }
    return { rust, static: staticPhase };
};

export const verifyTestLaneCoverage = async (
    commandArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const phases = parsePhases(commandArguments);
    const failures: string[] = [];
    if (phases.static) {
        failures.push(...(await verifyStaticOwnership()));
    }
    if (phases.rust) {
        failures.push(...validateRustTestInventory(collectRustTestInventory()));
    }
    if (failures.length > 0) {
        throw new Error([...new Set(failures)].sort().join('\n'));
    }

    const completedPhases = [
        ...(phases.static ? ['static'] : []),
        ...(phases.rust ? ['Rust inventory'] : []),
    ];
    console.log(
        `Test lane coverage verification passed (${completedPhases.join(' and ')}).`,
    );
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void verifyTestLaneCoverage();
}
