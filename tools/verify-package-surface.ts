import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

type ExportEntry = {
    import: string;
    types: string;
};

type PackageManifest = {
    exports: Record<string, ExportEntry>;
    name: string;
};

type ModuleNamespace = Record<string, unknown>;

const repoRoot = process.cwd();
const packagePath = path.resolve(repoRoot, 'package.json');
const npmignorePath = path.resolve(repoRoot, '.npmignore');
const expectedRootExports = ['UnsupportedRuntimeError', 'sha256Hex'] as const;

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
    const expectedExportKeys = ['.'];

    if (JSON.stringify(exportKeys) !== JSON.stringify(expectedExportKeys)) {
        failures.push(
            `Unexpected public exports: ${exportKeys.join(', ') || '(none)'}.`,
        );
    }

    const rootExport = manifest.exports['.'];
    if (rootExport === undefined) {
        failures.push('Missing export entry for .');
    } else {
        if (rootExport.import !== './dist/index.js') {
            failures.push('Export . must point to ./dist/index.js.');
        }
        if (rootExport.types !== './dist/index.d.ts') {
            failures.push('Export . must point to ./dist/index.d.ts.');
        }

        try {
            await assertFileExists('src/index.ts');
        } catch {
            failures.push('Missing source entrypoint src/index.ts.');
        }

        const typedocEntryPoint = `typedoc/entrypoints/${manifest.name}.ts`;
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

    const rootModule = await importModuleAt('src/index.ts');

    if (
        JSON.stringify(moduleKeys(rootModule)) !==
        JSON.stringify([...expectedRootExports])
    ) {
        failures.push(
            `Root package exports must be ${expectedRootExports.join(', ')}.`,
        );
    }

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Package surface verification passed.');
};

void main();
