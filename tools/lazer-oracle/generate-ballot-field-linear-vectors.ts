import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The source file is .mts, but tsc emits and resolves the runtime import as .mjs.
// eslint-disable-next-line import-x/extensions
import { generateBallotFieldLinearProofOracleInput } from '../ballot-privacy-vectors/generate-ballot-field-linear-proof-input.mjs';

type Command = {
    readonly args: readonly string[];
    readonly command: string;
    readonly cwd?: string;
    readonly captureStdout?: boolean;
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const oracleDirectory = path.join(repoRoot, 'tools', 'lazer-oracle');
const lazerDemoDirectory = path.join(
    repoRoot,
    'temp',
    'lazer',
    'python',
    'demo',
);
const imageName =
    process.env.LAZER_ORACLE_IMAGE ?? 'sealed-lattice-lazer-oracle:local';
const sageImageName = process.env.SAGE_IMAGE ?? 'sagemath/sagemath:latest';
const oracleInputPath = path.join(
    lazerDemoDirectory,
    'ballot_field_input.json',
);
const generatedHeaderPath = path.join(
    lazerDemoDirectory,
    'ballot_field_params.h',
);

const runCommand = ({
    args,
    captureStdout = false,
    command,
    cwd = repoRoot,
}: Command): string => {
    const result = spawnSync(command, args, {
        cwd,
        env: process.env,
        encoding: 'utf8',
        stdio: captureStdout ? ['ignore', 'pipe', 'inherit'] : 'inherit',
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

    return typeof result.stdout === 'string' ? result.stdout : '';
};

const extractHeaderText = (sageStdout: string): string => {
    const headerStartIndex = sageStdout.indexOf('// auto-generated');
    if (headerStartIndex === -1) {
        throw new Error('Sage output did not contain a generated header.');
    }

    const headerLines = sageStdout.slice(headerStartIndex).split(/\r?\n/u);
    const finalHeaderLineIndex = headerLines.findIndex((line) =>
        line.startsWith('static const lin_params_t ballot_field_param = '),
    );
    if (finalHeaderLineIndex === -1) {
        throw new Error(
            'Sage output did not contain the final linear parameter line.',
        );
    }

    return `${headerLines.slice(0, finalHeaderLineIndex + 1).join('\n')}\n`;
};

mkdirSync(lazerDemoDirectory, { recursive: true });

await generateBallotFieldLinearProofOracleInput(oracleInputPath);

const sageOutput = runCommand({
    command: 'docker',
    captureStdout: true,
    args: [
        'run',
        '--rm',
        '-v',
        `${repoRoot}:/work`,
        '-w',
        '/work/temp/lazer/scripts',
        sageImageName,
        'sage',
        'lin-codegen.sage',
        '/work/tools/lazer-oracle/ballot-field-linear-params.py',
    ],
});
writeFileSync(generatedHeaderPath, extractHeaderText(sageOutput), 'utf8');

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
        '/work/tools/lazer-oracle/run_ballot_field_oracle.py',
        '--repo-root',
        '/work',
        '--lazer-root',
        '/work/temp/lazer',
        '--input',
        '/work/temp/lazer/python/demo/ballot_field_input.json',
        '--out',
        '/work/test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json',
    ],
});
