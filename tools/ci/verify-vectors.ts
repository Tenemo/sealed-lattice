import { spawnSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const repoRootUrl = new URL('../../', import.meta.url);
const repoRoot = fileURLToPath(repoRootUrl);

const packageManagerEntryPointPath = process.env.npm_execpath;
if (packageManagerEntryPointPath === undefined) {
    throw new Error('npm_execpath is required to run package manager commands');
}

const vectorFilePath = 'test-vectors/core.json';

const runPackageManager = (
    packageManagerArguments: readonly string[],
): void => {
    const commandArgs = [
        packageManagerEntryPointPath,
        ...packageManagerArguments,
    ];
    const commandDescription = [process.execPath, ...commandArgs].join(' ');
    const result = spawnSync(process.execPath, commandArgs, {
        cwd: repoRoot,
        stdio: 'inherit',
        env: process.env,
    });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start command: ${commandDescription}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `Command terminated by signal ${result.signal}: ${commandDescription}`,
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `Command exited with status ${result.status ?? 'null'}: ${commandDescription}`,
        );
    }
};

const main = async (): Promise<void> => {
    const originalContent = await readFile(
        new URL(vectorFilePath, repoRootUrl),
        'utf8',
    );

    try {
        runPackageManager(['run', 'vectors:core']);

        const currentContent = await readFile(
            new URL(vectorFilePath, repoRootUrl),
            'utf8',
        );
        if (currentContent !== originalContent) {
            throw new Error(
                `Generated vectors drifted from the committed fixture: ${vectorFilePath}`,
            );
        }
    } finally {
        await writeFile(
            new URL(vectorFilePath, repoRootUrl),
            originalContent,
            'utf8',
        );
    }

    console.log('Committed test vectors match the generator.');
};

void main();
