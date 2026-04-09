import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

type ExportEntry = {
    import: string;
    types: string;
};

type PackageManifest = {
    exports: Record<string, ExportEntry>;
    imports: Record<string, string>;
    name: string;
};

type ModuleNamespace = Record<string, unknown>;

const repoRoot = process.cwd();
const packagePath = path.resolve(repoRoot, 'package.json');
const npmignorePath = path.resolve(repoRoot, '.npmignore');
const expectedExports = [
    '.',
    './core',
    './proofs',
    './protocol',
    './runtime',
    './serialize',
    './threshold',
    './transport',
] as const;
const expectedRootExports = ['UnsupportedRuntimeError', 'sha256Hex'] as const;
const placeholderImports = [
    '#proofs',
    '#protocol',
    '#runtime',
    '#serialize',
    '#threshold',
    '#transport',
] as const;

const aliasForExportKey = (
    exportKey: (typeof expectedExports)[number],
): string => (exportKey === '.' ? '#root' : `#${exportKey.slice(2)}`);

const assertFileExists = async (relativePath: string): Promise<void> => {
    await access(path.resolve(repoRoot, relativePath));
};

const loadManifest = async (): Promise<PackageManifest> =>
    JSON.parse(await readFile(packagePath, 'utf8')) as PackageManifest;

const moduleKeys = (moduleNamespace: ModuleNamespace): string[] =>
    Object.keys(moduleNamespace).sort();

const importModuleAt = async (relativePath: string): Promise<ModuleNamespace> =>
    (await import(
        pathToFileURL(path.resolve(repoRoot, relativePath)).href
    )) as ModuleNamespace;

const main = async (): Promise<void> => {
    const manifest = await loadManifest();
    const failures: string[] = [];

    if (manifest.name !== 'sealed-lattice') {
        failures.push(
            `Package name must be "sealed-lattice", received "${manifest.name}".`,
        );
    }

    const exportKeys = Object.keys(manifest.exports).sort();
    const importKeys = Object.keys(manifest.imports).sort();
    const expectedExportKeys = [...expectedExports].sort();
    const expectedImportKeys = expectedExports
        .map((exportKey) => aliasForExportKey(exportKey))
        .sort();

    if (JSON.stringify(exportKeys) !== JSON.stringify(expectedExportKeys)) {
        failures.push(
            `Unexpected public exports: ${exportKeys.join(', ') || '(none)'}.`,
        );
    }

    if (JSON.stringify(importKeys) !== JSON.stringify(expectedImportKeys)) {
        failures.push(
            `Unexpected internal imports: ${importKeys.join(', ') || '(none)'}.`,
        );
    }

    for (const exportKey of expectedExports) {
        const importAlias = aliasForExportKey(exportKey);
        const exportEntry = manifest.exports[exportKey];
        const importTarget = manifest.imports[importAlias];

        if (exportEntry === undefined) {
            failures.push(`Missing export entry for ${exportKey}.`);
            continue;
        }

        if (importTarget === undefined) {
            failures.push(`Missing import alias for ${importAlias}.`);
            continue;
        }

        const expectedDistStem =
            exportKey === '.' ? 'index' : `${exportKey.slice(2)}/index`;
        if (exportEntry.import !== `./dist/${expectedDistStem}.js`) {
            failures.push(
                `Export ${exportKey} must point to ./dist/${expectedDistStem}.js.`,
            );
        }
        if (exportEntry.types !== `./dist/${expectedDistStem}.d.ts`) {
            failures.push(
                `Export ${exportKey} must point to ./dist/${expectedDistStem}.d.ts.`,
            );
        }

        try {
            await assertFileExists(importTarget);
        } catch {
            failures.push(`Missing source entrypoint ${importTarget}.`);
        }

        const typedocEntryPoint = `typedoc/entrypoints/${
            exportKey === '.' ? manifest.name : exportKey.slice(2)
        }.ts`;
        try {
            await assertFileExists(typedocEntryPoint);
        } catch {
            failures.push(`Missing Typedoc entrypoint ${typedocEntryPoint}.`);
        }
    }

    const npmignore = (await readFile(npmignorePath, 'utf8'))
        .replace(/\r\n/g, '\n')
        .trim();
    if (npmignore !== '*\n!dist/**') {
        failures.push(
            '.npmignore must preserve the dist-only tarball policy via "*" and "!dist/**".',
        );
    }

    const rootModule = await importModuleAt(manifest.imports['#root']);
    const coreModule = await importModuleAt(manifest.imports['#core']);

    if (
        JSON.stringify(moduleKeys(rootModule)) !==
        JSON.stringify([...expectedRootExports])
    ) {
        failures.push(
            `Root package exports must be ${expectedRootExports.join(', ')}.`,
        );
    }

    if (
        JSON.stringify(moduleKeys(coreModule)) !==
        JSON.stringify([...expectedRootExports])
    ) {
        failures.push(
            `Core package exports must be ${expectedRootExports.join(', ')}.`,
        );
    }

    for (const importAlias of placeholderImports) {
        const moduleNamespace = await importModuleAt(
            manifest.imports[importAlias],
        );
        if (moduleKeys(moduleNamespace).length > 0) {
            failures.push(`${importAlias} must stay empty in phase one.`);
        }
    }

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Scaffold verification passed.');
};

void main();
