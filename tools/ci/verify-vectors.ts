import { spawnSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const repoRootUrl = new URL('../../', import.meta.url);
const packageManagerEntrypoint = process.env.npm_execpath;
const packageManagerCommand =
    packageManagerEntrypoint === undefined
        ? process.platform === 'win32'
            ? 'pnpm.cmd'
            : 'pnpm'
        : process.execPath;

const vectorFile = 'test-vectors/core.json';

const runPackageManager = (args: readonly string[]): void => {
    const commandArgs =
        packageManagerEntrypoint === undefined
            ? [...args]
            : [packageManagerEntrypoint, ...args];
    const commandDescription = [packageManagerCommand, ...commandArgs].join(
        ' ',
    );
    const result = spawnSync(packageManagerCommand, commandArgs, {
        cwd: fileURLToPath(repoRootUrl),
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

const normalizeJson = (content: string): string =>
    JSON.stringify(JSON.parse(content));

const main = async (): Promise<void> => {
    const originalContent = await readFile(
        new URL(vectorFile, repoRootUrl),
        'utf8',
    );

    try {
        runPackageManager(['exec', 'tsx', './tools/generate-core-vectors.ts']);

        const currentContent = await readFile(
            new URL(vectorFile, repoRootUrl),
            'utf8',
        );
        if (normalizeJson(currentContent) !== normalizeJson(originalContent)) {
            throw new Error(
                `Generated vectors drifted from the committed fixture: ${vectorFile}`,
            );
        }
    } finally {
        await writeFile(
            new URL(vectorFile, repoRootUrl),
            originalContent,
            'utf8',
        );
    }

    console.log('Committed test vectors match the generator.');
};

void main();
