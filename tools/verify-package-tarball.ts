import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import packageManifest from '../package.json';

type NpmPackFile = {
    mode: number;
    path: string;
    size: number;
};

type NpmPackMetadata = {
    files: NpmPackFile[];
    version: string;
};

const execFileAsync = promisify(execFile);
const allowedTopLevelFiles = new Set(['LICENSE', 'README.md', 'package.json']);

const normalizePackPath = (filePath: string): string =>
    filePath.replace(/\\/g, '/').replace(/^\.\//, '');

const collectExportPaths = (value: unknown): string[] => {
    if (typeof value === 'string') {
        return [normalizePackPath(value)];
    }

    if (Array.isArray(value)) {
        return value.flatMap((entry) => collectExportPaths(entry));
    }

    if (value !== null && typeof value === 'object') {
        return Object.values(value).flatMap((entry) =>
            collectExportPaths(entry),
        );
    }

    return [];
};

const runNpmPackDryRun = async (): Promise<string> => {
    if (process.platform === 'win32') {
        const { stdout } = await execFileAsync(
            process.env.comspec ?? 'cmd.exe',
            ['/d', '/s', '/c', 'npm pack --json --dry-run --ignore-scripts'],
            { cwd: process.cwd() },
        );
        return stdout;
    }

    const { stdout } = await execFileAsync(
        'npm',
        ['pack', '--json', '--dry-run', '--ignore-scripts'],
        {
            cwd: process.cwd(),
        },
    );
    return stdout;
};

const main = async (): Promise<void> => {
    const stdout = await runNpmPackDryRun();
    const metadata = JSON.parse(stdout) as NpmPackMetadata[];

    if (metadata.length !== 1) {
        throw new Error(
            `Expected npm pack --json to return exactly one package, received ${metadata.length}.`,
        );
    }

    const [packResult] = metadata;
    const packagedFiles = packResult.files.map((entry) =>
        normalizePackPath(entry.path),
    );
    const packagedFileSet = new Set(packagedFiles);
    const exportedFiles = new Set([
        normalizePackPath(packageManifest.main),
        normalizePackPath(packageManifest.types),
        ...collectExportPaths(packageManifest.exports),
    ]);

    const failures: string[] = [];

    if (packResult.version !== packageManifest.version) {
        failures.push(
            `npm pack version ${packResult.version} does not match package.json version ${packageManifest.version}.`,
        );
    }

    for (const requiredFile of [...allowedTopLevelFiles, ...exportedFiles]) {
        if (!packagedFileSet.has(requiredFile)) {
            failures.push(`npm pack is missing required file: ${requiredFile}`);
        }
    }

    for (const filePath of packagedFiles) {
        if (
            !allowedTopLevelFiles.has(filePath) &&
            !filePath.startsWith('dist/')
        ) {
            failures.push(
                `npm pack includes an unexpected file outside dist/: ${filePath}`,
            );
        }
    }

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Package tarball verification passed.');
};

void main();
