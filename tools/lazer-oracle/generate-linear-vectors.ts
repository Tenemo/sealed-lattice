import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

type Command = {
    readonly args: readonly string[];
    readonly command: string;
    readonly cwd?: string;
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const oracleDirectory = path.join(repoRoot, 'tools', 'lazer-oracle');
const imageName =
    process.env.LAZER_ORACLE_IMAGE ?? 'sealed-lattice-lazer-oracle:local';

const runCommand = ({ args, command, cwd = repoRoot }: Command): void => {
    const result = spawnSync(command, args, {
        cwd,
        env: process.env,
        stdio: 'inherit',
    });
    if (result.error !== undefined) {
        throw new Error(
            `Failed to start ${command} ${args.join(' ')}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `Command terminated by signal ${result.signal}: ${command} ${args.join(' ')}`,
        );
    }
    if (result.status !== 0) {
        throw new Error(
            `Command exited with status ${String(result.status)}: ${command} ${args.join(' ')}`,
        );
    }
};

runCommand({
    command: 'docker',
    args: ['build', '-t', imageName, oracleDirectory],
});

runCommand({
    command: 'docker',
    args: [
        'run',
        '--rm',
        '-v',
        `${repoRoot}:/work`,
        '-w',
        '/work/temp/lazer',
        imageName,
        'python3',
        '/work/tools/lazer-oracle/run_oracle.py',
        '--repo-root',
        '/work',
        '--lazer-root',
        '/work/temp/lazer',
        '--out',
        '/work/test-vectors/ballot-privacy/proof-backend-linear-vectors.json',
    ],
});
