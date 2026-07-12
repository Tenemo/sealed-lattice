import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    createSourceFile,
    flattenDiagnosticMessageText,
    forEachChild,
    isCallExpression,
    isIdentifier,
    isImportDeclaration,
    isNamespaceImport,
    isParenthesizedExpression,
    isPrefixUnaryExpression,
    isPropertyAccessExpression,
    isStringLiteral,
    ScriptKind,
    ScriptTarget,
    SyntaxKind,
    type Expression,
    type Diagnostic,
    type Node,
    type SourceFile,
} from 'typescript';

import {
    collectRustTestInventory,
    type RustTestInventoryEntry,
} from '#tools/ci/rust-test-inventory.js';
import {
    aggregateTestScriptCommands,
    aggregateTestScripts,
    browserTestLaneDefinitions,
    canonicalTestLaneDefinitions,
    canonicalTestLaneValues,
    externalOracleDefinitions,
    fullProfileEvidenceRustTests,
    fuzzTargetDefinitions,
    measurementRustTests,
    rustTestLanesForInventoryEntry,
    testLaneGroupsForRelativePath,
    testUtilityScriptCommands,
    testUtilityScripts,
    type CanonicalTestLane,
} from '#tools/ci/test-lanes.js';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { toPosixPath } from '#tools/internal/files.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const testFileNamePattern = /\.(?:test|spec)\.[cm]?[jt]sx?$/u;
const sourceFileNamePattern = /\.[cm]?[jt]sx?$/u;
const sharedBrowserCapabilitiesModuleSpecifier =
    '#tests/support/browser-capabilities';
const excludedSourceDirectoryNames = new Set([
    '.cache',
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
    'implementation-documentation',
    'logs',
    'node_modules',
    'reference-documents',
    'reference-projects',
    'target',
    'temp',
]);

type TypeScriptTestAnalysis = {
    readonly definitionCount: number;
    readonly failures: readonly string[];
};

type SourceFileWithParseDiagnostics = SourceFile & {
    readonly parseDiagnostics?: readonly Diagnostic[];
};

type RootPackage = {
    readonly scripts?: Readonly<Record<string, string>>;
};

type VitestRootName = 'describe' | 'it' | 'test';

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
    readonly definitionBindings: ReadonlyMap<string, VitestRootName>;
    readonly namespaceBindings: ReadonlySet<string>;
} => {
    const definitionBindings = new Map<string, VitestRootName>();
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
                definitionBindings.set(
                    element.name.text,
                    importedName as VitestRootName,
                );
            }
        }
    }

    return { definitionBindings, namespaceBindings };
};

const resolvedVitestCall = (input: {
    readonly call: VitestCall;
    readonly definitionBindings: ReadonlyMap<string, VitestRootName>;
    readonly namespaceBindings: ReadonlySet<string>;
    readonly testNamedFile: boolean;
}): VitestCall | undefined => {
    const importedRootName = input.definitionBindings.get(input.call.rootName);
    if (importedRootName !== undefined) {
        return { ...input.call, rootName: importedRootName };
    }
    if (
        input.testNamedFile &&
        ['describe', 'it', 'test'].includes(input.call.rootName)
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

const conditionalModifierArgument = (
    call: Node,
    modifier: string,
): Expression | undefined => {
    let expression = isCallExpression(call) ? call.expression : undefined;
    while (expression !== undefined) {
        if (isCallExpression(expression)) {
            if (
                isPropertyAccessExpression(expression.expression) &&
                expression.expression.name.text === modifier
            ) {
                return expression.arguments[0];
            }
            expression = expression.expression;
            continue;
        }
        if (isPropertyAccessExpression(expression)) {
            expression = expression.expression;
            continue;
        }
        break;
    }

    return undefined;
};

const staticBooleanValue = (expression: Expression): boolean | undefined => {
    if (expression.kind === SyntaxKind.TrueKeyword) {
        return true;
    }
    if (expression.kind === SyntaxKind.FalseKeyword) {
        return false;
    }
    if (isParenthesizedExpression(expression)) {
        return staticBooleanValue(expression.expression);
    }
    if (
        isPrefixUnaryExpression(expression) &&
        expression.operator === SyntaxKind.ExclamationToken
    ) {
        const operand = staticBooleanValue(expression.operand);
        return operand === undefined ? undefined : !operand;
    }

    return undefined;
};

const isSharedBrowserCapabilityCondition = (
    expression: Expression,
): boolean => {
    if (isParenthesizedExpression(expression)) {
        return isSharedBrowserCapabilityCondition(expression.expression);
    }
    if (isIdentifier(expression)) {
        return expression.text === 'webLocksAvailable';
    }

    return (
        isPrefixUnaryExpression(expression) &&
        expression.operator === SyntaxKind.ExclamationToken &&
        isIdentifier(expression.operand) &&
        expression.operand.text === 'webLocksAvailable'
    );
};

const importsSharedBrowserCapability = (sourceFile: SourceFile): boolean =>
    sourceFile.statements.some((statement) => {
        if (
            !isImportDeclaration(statement) ||
            !isStringLiteral(statement.moduleSpecifier) ||
            statement.moduleSpecifier.text !==
                sharedBrowserCapabilitiesModuleSpecifier
        ) {
            return false;
        }
        const namedBindings = statement.importClause?.namedBindings;
        if (namedBindings === undefined || isNamespaceImport(namedBindings)) {
            return false;
        }

        return namedBindings.elements.some(
            (element) =>
                element.name.text === 'webLocksAvailable' &&
                (element.propertyName?.text ?? element.name.text) ===
                    'webLocksAvailable',
        );
    });

const scriptKindForPath = (filePath: string): ScriptKind => {
    if (filePath.endsWith('.tsx')) {
        return ScriptKind.TSX;
    }
    if (filePath.endsWith('.jsx')) {
        return ScriptKind.JSX;
    }
    if (/\.(?:c|m)?js$/u.test(filePath)) {
        return ScriptKind.JS;
    }

    return ScriptKind.TS;
};

const typeScriptParseFailures = (
    relativePath: string,
    sourceFile: SourceFile,
): readonly string[] =>
    ((sourceFile as SourceFileWithParseDiagnostics).parseDiagnostics ?? []).map(
        (diagnostic) => {
            const location =
                diagnostic.start === undefined
                    ? relativePath
                    : (() => {
                          const position =
                              sourceFile.getLineAndCharacterOfPosition(
                                  diagnostic.start,
                              );
                          return `${relativePath}:${position.line + 1}:${position.character + 1}`;
                      })();
            const message = flattenDiagnosticMessageText(
                diagnostic.messageText,
                ' ',
            );
            return `${location} has TypeScript syntax error TS${diagnostic.code}: ${message}`;
        },
    );

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
        scriptKindForPath(relativePath),
    );
    const failures = [...typeScriptParseFailures(relativePath, sourceFile)];
    const hasSharedBrowserCapabilityImport =
        importsSharedBrowserCapability(sourceFile);
    const bindings = collectVitestBindings(sourceFile);
    let definitionCount = 0;
    let vitestCallCount = 0;

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
                    vitestCallCount += 1;
                    if (
                        resolvedCall.rootName === 'it' ||
                        resolvedCall.rootName === 'test'
                    ) {
                        definitionCount += 1;
                    }
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
                        const condition = conditionalModifierArgument(
                            node,
                            'skipIf',
                        );
                        if (condition === undefined) {
                            failures.push(
                                `${relativePath}:${line} uses .skipIf without a capability condition.`,
                            );
                        } else if (
                            staticBooleanValue(condition) !== undefined
                        ) {
                            failures.push(
                                `${relativePath}:${line} uses .skipIf with a static boolean; only runtime browser-capability conditions are allowed.`,
                            );
                        } else if (
                            !isSharedBrowserCapabilityCondition(condition) ||
                            !hasSharedBrowserCapabilityImport
                        ) {
                            failures.push(
                                `${relativePath}:${line} uses .skipIf without the shared webLocksAvailable capability import.`,
                            );
                        }
                    }
                    if (resolvedCall.modifiers.includes('runIf')) {
                        failures.push(
                            `${relativePath}:${line} uses .runIf; conditional browser tests must use capability-dependent .skipIf.`,
                        );
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
    if (!testNamedFile && vitestCallCount > 0) {
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
        const definition = canonicalTestLaneDefinitions[lane];
        const script = definition.rootScript;
        const previousOwner = canonicalScripts.get(script);
        if (previousOwner !== undefined) {
            failures.push(
                `${script} is assigned to both ${previousOwner} and ${lane}.`,
            );
        }
        canonicalScripts.set(script, lane);
        const actualCommand = scripts[script];
        if (actualCommand === undefined) {
            failures.push(`${lane} is missing root script ${script}.`);
        } else if (actualCommand !== definition.command) {
            failures.push(
                `${script} runs ${JSON.stringify(actualCommand)}; expected ${JSON.stringify(definition.command)} for ${lane}.`,
            );
        }
    }

    for (const script of aggregateTestScripts) {
        const actualCommand = scripts[script];
        const expectedCommand = aggregateTestScriptCommands[script];
        if (actualCommand === undefined) {
            failures.push(`Aggregate test script ${script} is missing.`);
        } else if (actualCommand !== expectedCommand) {
            failures.push(
                `${script} runs ${JSON.stringify(actualCommand)}; expected aggregate command ${JSON.stringify(expectedCommand)}.`,
            );
        }
    }
    for (const script of testUtilityScripts) {
        const actualCommand = scripts[script];
        const expectedCommand = testUtilityScriptCommands[script];
        if (actualCommand === undefined) {
            failures.push(`Test utility script ${script} is missing.`);
        } else if (actualCommand !== expectedCommand) {
            failures.push(
                `${script} runs ${JSON.stringify(actualCommand)}; expected utility command ${JSON.stringify(expectedCommand)}.`,
            );
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

export { parseLibtestListOutput } from './rust-test-inventory.js';

export const validateRustTestInventory = (
    entries: readonly RustTestInventoryEntry[],
): readonly string[] => {
    const failures: string[] = [];
    const ownedLanes = new Set<CanonicalTestLane>();

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
        ownedLanes.add(lane);
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
        if (!ownedLanes.has(lane)) {
            failures.push(`${lane} owns no discovered Rust tests.`);
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

export const collectOwnedTypeScriptSources = async (
    rootDirectoryPath = repoRoot,
): Promise<readonly string[]> => {
    const files: string[] = [];
    const pendingDirectories = [rootDirectoryPath];

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

export const validateMobileBrowserTestSelectors = (
    discoveredTestFiles: readonly string[],
): readonly string[] => {
    const failures: string[] = [];
    const discoveredPaths = new Set(discoveredTestFiles.map(toPosixPath));
    const mobileSelectors = browserTestLaneDefinitions.mobile.include;

    if (new Set(mobileSelectors).size !== mobileSelectors.length) {
        failures.push('The mobile browser smoke selectors contain duplicates.');
    }
    for (const mobileSelector of mobileSelectors) {
        if (
            [...mobileSelector].some((character) =>
                '*?[]{}'.includes(character),
            )
        ) {
            failures.push(
                `Mobile browser selector ${mobileSelector} must name one exact smoke test file.`,
            );
            continue;
        }
        if (!discoveredPaths.has(mobileSelector)) {
            failures.push(
                `Mobile browser smoke test ${mobileSelector} is stale or missing.`,
            );
        }
        if (
            !browserTestLaneDefinitions.desktop.include.some((desktopGlob) =>
                path.matchesGlob(mobileSelector, desktopGlob),
            )
        ) {
            failures.push(
                `Mobile browser smoke test ${mobileSelector} is not covered by the desktop browser selector.`,
            );
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
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
    const ownedTestFileLanes = new Set<CanonicalTestLane>();

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
                ownedTestFileLanes.add(lanes[0]);
            }
        }
    }
    failures.push(...validateTestLaneCoverage(testFiles));
    failures.push(...validateMobileBrowserTestSelectors(testFiles));

    for (const lane of [
        'node-fast',
        'node-protocol',
        'node-kernel-fast',
        'node-kernel-heavy',
        'browser',
    ] as const) {
        if (!ownedTestFileLanes.has(lane)) {
            failures.push(`${lane} owns no discovered TypeScript test files.`);
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
