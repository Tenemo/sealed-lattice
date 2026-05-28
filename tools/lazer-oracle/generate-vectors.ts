import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The source file is .mts, but tsc emits and resolves the runtime import as .mjs.
// eslint-disable-next-line import-x/extensions
import { generateBallotFieldLinearProofOracleInput } from '../ballot-privacy-vectors/generate-ballot-field-linear-proof-input.mjs';

type Command = {
    readonly args: readonly string[];
    readonly captureStdout?: boolean;
    readonly command: string;
    readonly workingDirectory?: string;
};

type VectorProfileName =
    | 'ballot-field-linear'
    | 'demo-linear'
    | 'receiver-key-linear';

type HeaderGenerationConfig = {
    readonly finalHeaderLinePrefix: string;
    readonly generatedHeaderPath: string;
    readonly parameterSourcePathInContainer: string;
};

type VectorProfileConfig = {
    readonly dockerProfileName: VectorProfileName;
    readonly headerGeneration?: HeaderGenerationConfig;
    readonly oracleInputPath?: string;
    readonly oracleInputPathInContainer?: string;
    readonly outputPathInContainer: string;
};

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const oracleDirectory = path.join(repoRoot, 'tools', 'lazer-oracle');
const lazerDemoDirectory = path.join(
    repoRoot,
    'temp',
    'lazer',
    'python',
    'demo',
);
const imageName = 'sealed-lattice-lazer-oracle:local';
const sageImageName = 'sagemath/sagemath:latest';
const supportedProfileNames = [
    'demo-linear',
    'receiver-key-linear',
    'ballot-field-linear',
] as const satisfies readonly VectorProfileName[];

const profileConfigs: Record<VectorProfileName, VectorProfileConfig> = {
    'demo-linear': {
        dockerProfileName: 'demo-linear',
        outputPathInContainer:
            '/work/test-vectors/ballot-privacy/proof-backend-linear-vectors.json',
    },
    'receiver-key-linear': {
        dockerProfileName: 'receiver-key-linear',
        headerGeneration: {
            finalHeaderLinePrefix:
                'static const lin_params_t receiver_key_param = ',
            generatedHeaderPath: path.join(
                lazerDemoDirectory,
                'receiver_key_params.h',
            ),
            parameterSourcePathInContainer:
                '/work/tools/lazer-oracle/receiver-key-linear-params.py',
        },
        outputPathInContainer:
            '/work/test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json',
    },
    'ballot-field-linear': {
        dockerProfileName: 'ballot-field-linear',
        headerGeneration: {
            finalHeaderLinePrefix:
                'static const lin_params_t ballot_field_param = ',
            generatedHeaderPath: path.join(
                lazerDemoDirectory,
                'ballot_field_params.h',
            ),
            parameterSourcePathInContainer:
                '/work/tools/lazer-oracle/ballot-field-linear-params.py',
        },
        oracleInputPath: path.join(
            lazerDemoDirectory,
            'ballot_field_input.json',
        ),
        oracleInputPathInContainer:
            '/work/temp/lazer/python/demo/ballot_field_input.json',
        outputPathInContainer:
            '/work/test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json',
    },
};

const isVectorProfileName = (value: string): value is VectorProfileName =>
    supportedProfileNames.some(
        (supportedProfileName) => supportedProfileName === value,
    );

const usage = (): string =>
    `Usage: tsx tools/lazer-oracle/generate-vectors.ts --profile ${supportedProfileNames.join('|')}|all`;

const requestedProfileNames = (
    commandLineArguments: readonly string[],
): readonly VectorProfileName[] => {
    if (
        commandLineArguments.length !== 2 ||
        commandLineArguments[0] !== '--profile'
    ) {
        throw new Error(usage());
    }

    const requestedProfileText = commandLineArguments[1];
    if (
        requestedProfileText === undefined ||
        requestedProfileText.length === 0
    ) {
        throw new Error(usage());
    }
    if (requestedProfileText === 'all') {
        return supportedProfileNames;
    }

    const profiles: VectorProfileName[] = [];
    for (const profileName of requestedProfileText.split(',')) {
        const trimmedProfileName = profileName.trim();
        if (!isVectorProfileName(trimmedProfileName)) {
            throw new Error(`Unsupported LaZer vector profile: ${profileName}`);
        }
        if (!profiles.includes(trimmedProfileName)) {
            profiles.push(trimmedProfileName);
        }
    }
    if (profiles.length === 0) {
        throw new Error(usage());
    }

    return profiles;
};

const runCommand = ({
    args,
    captureStdout = false,
    command,
    workingDirectory = repoRoot,
}: Command): string => {
    const result = spawnSync(command, args, {
        cwd: workingDirectory,
        encoding: 'utf8',
        env: process.env,
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

const extractGeneratedHeaderText = (
    sageOutput: string,
    finalHeaderLinePrefix: string,
): string => {
    const headerStartIndex = sageOutput.indexOf('// auto-generated');
    if (headerStartIndex === -1) {
        throw new Error('Sage output did not contain a generated header.');
    }

    const headerLines = sageOutput.slice(headerStartIndex).split(/\r?\n/u);
    const finalHeaderLineIndex = headerLines.findIndex((line) =>
        line.startsWith(finalHeaderLinePrefix),
    );
    if (finalHeaderLineIndex === -1) {
        throw new Error(
            `Sage output did not contain the final parameter line ${finalHeaderLinePrefix}.`,
        );
    }

    return `${headerLines.slice(0, finalHeaderLineIndex + 1).join('\n')}\n`;
};

const generateHeader = (config: HeaderGenerationConfig): void => {
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
            config.parameterSourcePathInContainer,
        ],
    });
    writeFileSync(
        config.generatedHeaderPath,
        extractGeneratedHeaderText(sageOutput, config.finalHeaderLinePrefix),
        'utf8',
    );
};

const prepareProfile = async (
    profileName: VectorProfileName,
): Promise<void> => {
    const config = profileConfigs[profileName];
    mkdirSync(lazerDemoDirectory, { recursive: true });
    if (config.oracleInputPath !== undefined) {
        await generateBallotFieldLinearProofOracleInput(config.oracleInputPath);
    }
    if (config.headerGeneration !== undefined) {
        generateHeader(config.headerGeneration);
    }
};

const buildOracleImage = (): void => {
    runCommand({
        command: 'docker',
        args: ['build', '-t', imageName, oracleDirectory],
    });
};

const runOracleProfile = (profileName: VectorProfileName): void => {
    const config = profileConfigs[profileName];
    const oracleArguments = [
        'run',
        '--rm',
        '-v',
        `${repoRoot}:/work`,
        '-w',
        '/work/temp/lazer',
        imageName,
        'python3',
        '/work/tools/lazer-oracle/run_oracle.py',
        '--profile',
        config.dockerProfileName,
        '--repo-root',
        '/work',
        '--lazer-root',
        '/work/temp/lazer',
        '--out',
        config.outputPathInContainer,
        ...(config.oracleInputPathInContainer === undefined
            ? []
            : ['--input', config.oracleInputPathInContainer]),
    ];

    runCommand({
        command: 'docker',
        args: oracleArguments,
    });
};

const main = async (): Promise<void> => {
    const profileNames = requestedProfileNames(process.argv.slice(2));
    for (const profileName of profileNames) {
        await prepareProfile(profileName);
    }

    buildOracleImage();

    for (const profileName of profileNames) {
        runOracleProfile(profileName);
    }
};

await main();
